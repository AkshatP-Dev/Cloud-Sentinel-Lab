"""
Unit tests for the responder Lambda — the one place in this project that
takes a real (if reversible) action against live AWS state, so these
tests use moto's IAM mock to exercise REAL state transitions rather than
just asserting a mocked function was called: a real fake IAM user gets a
real fake access key, and the assertions check that key's actual Status
via list_access_keys after the responder runs — the same way
tests/live/test_live_detection_flow.py checks the real thing post-deploy.
"""
from __future__ import annotations

import json

import boto3
import pytest
from moto import mock_aws


LAB_USER_NAME = "cloudsentinel-lab-user"


@pytest.fixture
def moto_aws():
    """Activates moto for the lifetime of this fixture — as a context
    manager wrapped around `yield`, not a decorator, because a decorator
    applied to a test METHOD does not extend to fixtures that method
    depends on: pytest resolves fixture dependencies (like
    iam_and_user below) BEFORE entering the decorated test function's
    body, so a @mock_aws decorator on the test method alone would leave
    a fixture's own AWS calls unpatched, and they would attempt real
    network requests. Making mock_aws itself a fixture that everything
    else depends on avoids that ordering trap entirely."""
    with mock_aws():
        yield


@pytest.fixture
def iam_and_user(moto_aws):
    """Depends on moto_aws so IAM is already mocked before this runs —
    creates a real fake lab user and returns (iam_client, user_arn)."""
    iam = boto3.client("iam", region_name="us-east-1")
    user = iam.create_user(UserName=LAB_USER_NAME)["User"]
    return iam, user["Arn"]


class TestSafetyGate:
    def test_refuses_when_target_does_not_match_lab_user(self, responder, iam_and_user):
        iam, lab_user_arn = iam_and_user
        responder.LAB_USER_ARN = lab_user_arn
        responder._iam = iam

        result = responder.lambda_handler({"resource_affected": "some-other-user"}, None)

        assert result["action"] == "refused"
        # Confirm no state was touched: the (nonexistent) other user was
        # never queried or acted on — if the safety gate has a bug, this
        # would raise a moto NoSuchEntity error instead of just refusing.
        keys = iam.list_access_keys(UserName=LAB_USER_NAME)["AccessKeyMetadata"]
        assert keys == []

    def test_refuses_when_lab_user_arn_is_unset(self, responder, iam_and_user):
        iam, _ = iam_and_user
        responder.LAB_USER_ARN = ""
        responder._iam = iam

        result = responder.lambda_handler({"resource_affected": LAB_USER_NAME}, None)
        assert result["action"] == "refused"

    def test_refuses_empty_target(self, responder, iam_and_user):
        iam, lab_user_arn = iam_and_user
        responder.LAB_USER_ARN = lab_user_arn
        responder._iam = iam

        result = responder.lambda_handler({"resource_affected": ""}, None)
        assert result["action"] == "refused"


class TestContainment:
    def test_deactivates_the_specific_requested_key(self, responder, iam_and_user):
        iam, lab_user_arn = iam_and_user
        key = iam.create_access_key(UserName=LAB_USER_NAME)["AccessKey"]
        responder.LAB_USER_ARN = lab_user_arn
        responder.SNS_TOPIC_ARN = ""
        responder._iam = iam

        result = responder.lambda_handler(
            {"resource_affected": LAB_USER_NAME, "access_key_id": key["AccessKeyId"], "summary": "test"},
            None,
        )

        assert result["action"] == "contained"
        assert result["deactivated_key_ids"] == [key["AccessKeyId"]]
        live = iam.list_access_keys(UserName=LAB_USER_NAME)["AccessKeyMetadata"]
        assert live[0]["Status"] == "Inactive"

    def test_falls_back_to_all_active_keys_when_requested_key_id_is_stale(self, responder, iam_and_user):
        """The payload named a key that's no longer active (or never
        existed) — rather than silently no-op, deactivate whatever IS
        currently active, so a stale/delayed invocation still contains
        the real live threat."""
        iam, lab_user_arn = iam_and_user
        real_key = iam.create_access_key(UserName=LAB_USER_NAME)["AccessKey"]
        responder.LAB_USER_ARN = lab_user_arn
        responder.SNS_TOPIC_ARN = ""
        responder._iam = iam

        result = responder.lambda_handler(
            {"resource_affected": LAB_USER_NAME, "access_key_id": "AKIA_DOES_NOT_EXIST"},
            None,
        )

        assert result["action"] == "contained"
        assert real_key["AccessKeyId"] in result["deactivated_key_ids"]

    def test_deactivates_multiple_active_keys(self, responder, iam_and_user):
        iam, lab_user_arn = iam_and_user
        k1 = iam.create_access_key(UserName=LAB_USER_NAME)["AccessKey"]
        k2 = iam.create_access_key(UserName=LAB_USER_NAME)["AccessKey"]
        responder.LAB_USER_ARN = lab_user_arn
        responder.SNS_TOPIC_ARN = ""
        responder._iam = iam

        result = responder.lambda_handler({"resource_affected": LAB_USER_NAME, "access_key_id": ""}, None)

        assert set(result["deactivated_key_ids"]) == {k1["AccessKeyId"], k2["AccessKeyId"]}
        live = iam.list_access_keys(UserName=LAB_USER_NAME)["AccessKeyMetadata"]
        assert all(k["Status"] == "Inactive" for k in live)

    def test_noop_when_no_active_keys(self, responder, iam_and_user):
        iam, lab_user_arn = iam_and_user
        responder.LAB_USER_ARN = lab_user_arn
        responder.SNS_TOPIC_ARN = ""
        responder._iam = iam

        result = responder.lambda_handler({"resource_affected": LAB_USER_NAME, "access_key_id": ""}, None)
        assert result["action"] == "noop"

    def test_already_inactive_key_is_left_alone_and_reported_as_noop(self, responder, iam_and_user):
        iam, lab_user_arn = iam_and_user
        key = iam.create_access_key(UserName=LAB_USER_NAME)["AccessKey"]
        iam.update_access_key(UserName=LAB_USER_NAME, AccessKeyId=key["AccessKeyId"], Status="Inactive")
        responder.LAB_USER_ARN = lab_user_arn
        responder.SNS_TOPIC_ARN = ""
        responder._iam = iam

        result = responder.lambda_handler({"resource_affected": LAB_USER_NAME, "access_key_id": ""}, None)
        assert result["action"] == "noop"


class TestContainmentNotice:
    def test_publishes_sns_notice_after_containment(self, responder, iam_and_user):
        iam, lab_user_arn = iam_and_user
        key = iam.create_access_key(UserName=LAB_USER_NAME)["AccessKey"]

        sns = boto3.client("sns", region_name="us-east-1")
        sqs = boto3.client("sqs", region_name="us-east-1")
        topic_arn = sns.create_topic(Name="cloudsentinel-alerts-test")["TopicArn"]
        queue_url = sqs.create_queue(QueueName="cloudsentinel-alerts-test-q")["QueueUrl"]
        queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

        responder.LAB_USER_ARN = lab_user_arn
        responder.SNS_TOPIC_ARN = topic_arn
        responder._iam = iam
        responder._sns = None  # force a fresh client bound to the moto-mocked region

        responder.lambda_handler(
            {"resource_affected": LAB_USER_NAME, "access_key_id": key["AccessKeyId"], "summary": "CreateAccessKey for IAM user cloudsentinel-lab-user."},
            None,
        )

        messages = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=1).get("Messages", [])
        assert len(messages) == 1
        body = json.loads(messages[0]["Body"])
        assert "CONTAINED" in body["Subject"]
        assert key["AccessKeyId"] in body["Message"]
        assert "reactivate" in body["Message"].lower()
