"""
Unit tests for the detector dispatcher: all five rules individually, plus
the dispatcher's own routing, multi-rule-match, error-isolation, and
responder-invocation-gating behavior.

SNS is exercised with moto (a real fake topic, with a real fake SQS queue
subscribed to it, so message content is verified end-to-end through an
actual AWS API contract — not just "was publish() called"). Lambda
InvokeFunction is stubbed with a plain mock instead of moto's heavier
Lambda simulation machinery: what's under test here is the DISPATCHER's
decision of *whether* and *with what payload* to invoke the responder,
not the responder's own execution (that's tests/unit/responder/).
"""
from __future__ import annotations

import json

import boto3
import pytest
from moto import mock_aws


def make_event(
    event_name,
    user_type="IAMUser",
    error=False,
    request_params=None,
    response_elems=None,
    arn="arn:aws:iam::111111111111:user/someone",
    event_source="iam.amazonaws.com",
):
    detail = {
        "eventName": event_name,
        "eventSource": event_source,
        "eventTime": "2026-08-27T00:00:00Z",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.5",
        "eventID": "abc-123",
        "userIdentity": {"type": user_type, "arn": arn},
        "requestParameters": request_params or {},
        "responseElements": response_elems or {},
    }
    if error:
        detail["errorCode"] = "AccessDenied"
    return {"detail-type": "AWS API Call via CloudTrail", "detail": detail}


# ---------------------------------------------------------------------------
# D-01 root_usage
# ---------------------------------------------------------------------------

class TestRootUsage:
    def test_matches_any_action_by_root(self, cs):
        finding = cs.rules.root_usage.check(make_event("DescribeInstances", user_type="Root"))
        assert finding is not None
        assert finding.rule_id == "D-01"
        assert finding.severity == "CRITICAL"

    def test_ignores_non_root(self, cs):
        assert cs.rules.root_usage.check(make_event("DescribeInstances", user_type="IAMUser")) is None

    def test_still_matches_on_error(self, cs):
        """Unlike every other rule, root usage does NOT skip failed calls —
        see the rule's own docstring for why."""
        finding = cs.rules.root_usage.check(make_event("ConsoleLogin", user_type="Root", error=True))
        assert finding is not None
        assert "FAILED" in finding.summary


# ---------------------------------------------------------------------------
# D-02 logging_tamper
# ---------------------------------------------------------------------------

class TestLoggingTamper:
    @pytest.mark.parametrize("name", ["StopLogging", "DeleteTrail", "PutBucketPolicy", "PutPublicAccessBlock", "DeleteBucketPublicAccessBlock"])
    def test_matches_tamper_events(self, cs, name):
        finding = cs.rules.logging_tamper.check(make_event(name))
        assert finding is not None
        assert finding.rule_id == "D-02"

    def test_ignores_unrelated_event(self, cs):
        assert cs.rules.logging_tamper.check(make_event("DescribeInstances")) is None

    def test_skips_errored_call(self, cs):
        assert cs.rules.logging_tamper.check(make_event("StopLogging", error=True)) is None


# ---------------------------------------------------------------------------
# D-03 privilege_escalation
# ---------------------------------------------------------------------------

class TestPrivilegeEscalation:
    def test_ordinary_escalation_action_is_high(self, cs):
        finding = cs.rules.privilege_escalation.check(make_event("AttachUserPolicy"))
        assert finding is not None
        assert finding.severity == "HIGH"

    def test_boundary_action_is_critical(self, cs):
        finding = cs.rules.privilege_escalation.check(make_event("DeleteUserPermissionsBoundary"))
        assert finding is not None
        assert finding.severity == "CRITICAL"

    def test_ignores_unrelated_event(self, cs):
        assert cs.rules.privilege_escalation.check(make_event("DescribeInstances")) is None

    def test_skips_errored_call(self, cs):
        assert cs.rules.privilege_escalation.check(make_event("CreateUser", error=True)) is None


# ---------------------------------------------------------------------------
# D-04 access_key_created
# ---------------------------------------------------------------------------

class TestAccessKeyCreated:
    def test_create_access_key_extracts_target_user_and_key_id(self, cs):
        event = make_event(
            "CreateAccessKey",
            response_elems={"accessKey": {"userName": "someone", "accessKeyId": "AKIA123"}},
        )
        finding = cs.rules.access_key_created.check(event)
        assert finding is not None
        assert finding.resource_affected == "someone"
        assert finding.access_key_id == "AKIA123"

    def test_update_access_key_activation_matches(self, cs):
        event = make_event(
            "UpdateAccessKey",
            request_params={"userName": "someone", "accessKeyId": "AKIA123", "status": "Active"},
        )
        finding = cs.rules.access_key_created.check(event)
        assert finding is not None

    def test_update_access_key_deactivation_does_not_match(self, cs):
        """Otherwise the responder's own deactivation would re-trigger this rule."""
        event = make_event(
            "UpdateAccessKey",
            request_params={"userName": "someone", "accessKeyId": "AKIA123", "status": "Inactive"},
        )
        assert cs.rules.access_key_created.check(event) is None

    def test_ignores_unrelated_event(self, cs):
        assert cs.rules.access_key_created.check(make_event("DescribeInstances")) is None


# ---------------------------------------------------------------------------
# D-05 bucket_exposure
# ---------------------------------------------------------------------------

class TestBucketExposure:
    def test_matches_and_extracts_bucket_name(self, cs):
        event = make_event("PutBucketAcl", request_params={"bucketName": "my-bucket"})
        finding = cs.rules.bucket_exposure.check(event)
        assert finding is not None
        assert finding.resource_affected == "my-bucket"

    def test_ignores_unrelated_event(self, cs):
        assert cs.rules.bucket_exposure.check(make_event("DescribeInstances")) is None

    def test_skips_errored_call(self, cs):
        assert cs.rules.bucket_exposure.check(make_event("PutBucketAcl", error=True)) is None


# ---------------------------------------------------------------------------
# Dispatcher: routing, multi-match, error isolation, responder gating
# ---------------------------------------------------------------------------

class TestDispatcherRouting:
    def test_unmatched_event_produces_nothing(self, cs):
        result = cs.handler.lambda_handler(make_event("DescribeInstances"), None)
        assert result["findings_count"] == 0

    def test_event_matching_two_rules_produces_both(self, cs):
        # DeleteBucket by Root matches both D-01 (root usage, any action)
        # and D-02 (logging tamper, DeleteBucket is in TAMPER_EVENTS) —
        # correct behavior, not a bug: two independent detections
        # legitimately both catching one dangerous event.
        cs.handler.SNS_TOPIC_ARN = ""  # publishing isn't under test here
        result = cs.handler.lambda_handler(make_event("DeleteBucket", user_type="Root"), None)
        assert result["findings_count"] == 2
        assert set(result["rule_ids"]) == {"D-01", "D-02"}

    def test_a_raising_rule_does_not_crash_the_others(self, cs, monkeypatch):
        def boom(event):
            raise RuntimeError("simulated bug in a rule")

        monkeypatch.setattr(cs.rules, "ALL_RULES", [boom] + [
            r for r in cs.rules.ALL_RULES if r is not cs.rules.root_usage.check
        ])
        # Re-point the dispatcher's own reference too, since it imported
        # ALL_RULES by value at import time.
        monkeypatch.setattr(cs.handler, "ALL_RULES", cs.rules.ALL_RULES)
        cs.handler.SNS_TOPIC_ARN = ""
        result = cs.handler.lambda_handler(make_event("CreateAccessKey", response_elems={"accessKey": {"userName": "x", "accessKeyId": "y"}}), None)
        # the raising rule contributed nothing, but the still-good rules
        # (e.g. D-04 matching CreateAccessKey) should have run normally.
        assert "D-04" in result["rule_ids"]


class TestDispatcherSnsPublishing:
    @mock_aws
    def test_publishes_finding_to_real_fake_sns_topic(self, cs, monkeypatch):
        sns = boto3.client("sns", region_name="us-east-1")
        sqs = boto3.client("sqs", region_name="us-east-1")

        topic_arn = sns.create_topic(Name="cloudsentinel-alerts-test")["TopicArn"]
        queue_url = sqs.create_queue(QueueName="cloudsentinel-alerts-test-q")["QueueUrl"]
        queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

        monkeypatch.setattr(cs.handler, "SNS_TOPIC_ARN", topic_arn)
        monkeypatch.setattr(cs.handler, "RESPONDER_FUNCTION_NAME", "")
        cs.handler._sns = None  # force a fresh client bound to the moto-mocked region

        cs.handler.lambda_handler(make_event("StopLogging"), None)

        messages = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=1).get("Messages", [])
        assert len(messages) == 1
        body = json.loads(messages[0]["Body"])
        assert "D-02" in body["Message"]
        assert body["MessageAttributes"]["rule_id"]["Value"] == "D-02"


class TestDispatcherResponderGating:
    def test_lab_user_access_key_invokes_responder(self, cs, monkeypatch):
        calls = []
        monkeypatch.setattr(cs.handler, "SNS_TOPIC_ARN", "")
        monkeypatch.setattr(cs.handler, "RESPONDER_FUNCTION_NAME", "cloudsentinel-responder")
        monkeypatch.setattr(cs.handler, "LAB_USER_ARN", "arn:aws:iam::111111111111:user/cloudsentinel-lab-user")
        monkeypatch.setattr(cs.handler, "_lambda_client_fn", lambda: type("M", (), {"invoke": lambda self, **kw: calls.append(kw)})())

        event = make_event("CreateAccessKey", response_elems={"accessKey": {"userName": "cloudsentinel-lab-user", "accessKeyId": "AKIALAB"}})
        cs.handler.lambda_handler(event, None)

        assert len(calls) == 1
        assert calls[0]["FunctionName"] == "cloudsentinel-responder"
        payload = json.loads(calls[0]["Payload"])
        assert payload["resource_affected"] == "cloudsentinel-lab-user"
        assert payload["access_key_id"] == "AKIALAB"

    def test_non_lab_user_access_key_does_not_invoke_responder(self, cs, monkeypatch):
        calls = []
        monkeypatch.setattr(cs.handler, "SNS_TOPIC_ARN", "")
        monkeypatch.setattr(cs.handler, "RESPONDER_FUNCTION_NAME", "cloudsentinel-responder")
        monkeypatch.setattr(cs.handler, "LAB_USER_ARN", "arn:aws:iam::111111111111:user/cloudsentinel-lab-user")
        monkeypatch.setattr(cs.handler, "_lambda_client_fn", lambda: type("M", (), {"invoke": lambda self, **kw: calls.append(kw)})())

        event = make_event("CreateAccessKey", response_elems={"accessKey": {"userName": "someone-else", "accessKeyId": "AKIAOTHER"}})
        cs.handler.lambda_handler(event, None)

        assert len(calls) == 0
