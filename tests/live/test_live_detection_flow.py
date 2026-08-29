"""
REQUIRES AWS + a completed `terraform apply` (auto-skipped otherwise —
see tests/live/conftest.py).

End-to-end: triggers a real D-04 event (creates an access key on the lab
user — the same safe, self-cleaning technique
scripts/simulate_events.sh uses for its d04 case) and polls both Lambdas'
CloudWatch Logs to confirm the full pipeline actually ran: detector found
it, responder contained it, and the key is really Inactive afterward.
This is the one test in this project that exercises EventBridge's real
routing latency end-to-end — tests/unit/ covers the Lambda logic itself
in isolation, with no timing dependency.

Does not assert a specific timing bound beyond a generous timeout — this
project does not fabricate propagation-time guarantees AWS itself
doesn't document. A timeout here means "go check manually," not "proven
broken" — see the assertion messages.
"""
from __future__ import annotations

import time

import boto3
import pytest

pytestmark = pytest.mark.live

POLL_INTERVAL_SECONDS = 5
MAX_WAIT_SECONDS = 120


def _wait_for_log_line(logs_client, log_group: str, needle: str, start_time_ms: int, max_wait: int = MAX_WAIT_SECONDS) -> bool:
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            events = logs_client.filter_log_events(
                logGroupName=log_group,
                startTime=start_time_ms,
                filterPattern=f'"{needle}"',
            )["events"]
        except logs_client.exceptions.ResourceNotFoundException:
            events = []  # the log group may not have received its first stream yet
        if events:
            return True
        time.sleep(POLL_INTERVAL_SECONDS)
    return False


@pytest.fixture(scope="module")
def iam_client(tf_outputs, aws_available):
    return boto3.client("iam", region_name=tf_outputs["aws_region"])


@pytest.fixture(scope="module")
def logs_client(tf_outputs, aws_available):
    return boto3.client("logs", region_name=tf_outputs["aws_region"])


def test_access_key_creation_is_detected_and_contained(tf_outputs, iam_client, logs_client):
    lab_user = tf_outputs["lab_user_name"]
    start_time_ms = int(time.time() * 1000)

    created = iam_client.create_access_key(UserName=lab_user)["AccessKey"]
    key_id = created["AccessKeyId"]

    try:
        detector_group = f"/aws/lambda/{tf_outputs['detector_function_name']}"
        found_detection = _wait_for_log_line(logs_client, detector_group, "FINDING D-04", start_time_ms)
        assert found_detection, (
            f"Did not see a 'FINDING D-04' log line in {detector_group} within "
            f"{MAX_WAIT_SECONDS}s of creating an access key on {lab_user}. Check the "
            f"EventBridge rule 'cloudsentinel-scoped-events' and the detector's own logs "
            f"manually before assuming this is a real failure — CloudTrail-to-EventBridge "
            f"delivery is normally fast but AWS does not publish a hard SLA for it."
        )

        responder_group = f"/aws/lambda/{tf_outputs['responder_function_name']}"
        found_containment = _wait_for_log_line(logs_client, responder_group, "Deactivated access key", start_time_ms)
        assert found_containment, (
            f"Detector fired but did not see 'Deactivated access key' in {responder_group} "
            f"within {MAX_WAIT_SECONDS}s. Check the responder's own logs manually — this "
            f"could mean the direct dispatcher-to-responder invocation failed, or the "
            f"responder's safety check refused for an unexpected reason (e.g. LAB_USER_ARN "
            f"misconfigured on the deployed function)."
        )

        final_state = iam_client.list_access_keys(UserName=lab_user)["AccessKeyMetadata"]
        matching = [k for k in final_state if k["AccessKeyId"] == key_id]
        assert matching and matching[0]["Status"] == "Inactive", (
            f"Expected access key {key_id} to be Inactive after containment; "
            f"actual state: {matching}"
        )
    finally:
        # Clean up regardless of outcome — don't leave a real credential
        # (active or not) sitting on the lab user after a test run.
        try:
            iam_client.delete_access_key(UserName=lab_user, AccessKeyId=key_id)
        except Exception:
            pass
