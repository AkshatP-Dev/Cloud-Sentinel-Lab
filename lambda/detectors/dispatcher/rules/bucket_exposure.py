"""
D-05 — S3 bucket exposure.

Fires on any successful attempt to change an S3 bucket's ACL, policy, or
public-access-block configuration in a way that COULD make it more
publicly accessible. Applies to any bucket in the account, not just the
CloudTrail log bucket — that bucket has its own dedicated protection via
the lab permission boundary's DenyTouchingTrailBucket statement. This rule
is a general "something in this account just changed its exposure
posture" signal.

Deliberate v1 limitation: this rule does not parse the ACL/policy body in
requestParameters to determine whether the change actually GRANTS public
access versus tightening it — reliably classifying that from the raw
CloudTrail payload is meaningfully harder than the other four detections.
Treating every matching event name as worth a human's attention
(alert-only, no auto-response) is the deliberately simple choice for this
project's scope — see DETECTIONS.md for the false-positive tradeoff that
implies and what a v2 would need to do instead (e.g. an
s3:GetBucketPolicyStatus / s3:GetPublicAccessBlock follow-up read to
confirm actual exposure before alerting).
"""
from __future__ import annotations

import event_utils as ev
from finding import Finding

RULE_ID = "D-05"
RULE_NAME = "bucket_exposure"

EXPOSURE_EVENTS = {
    "PutBucketAcl", "PutBucketPolicy",
    "PutBucketPublicAccessBlock", "PutPublicAccessBlock",
    "DeleteBucketPublicAccessBlock", "DeletePublicAccessBlock",
    "DeleteBucketPolicy",
}


def check(event: dict) -> Finding | None:
    if ev.is_error(event):
        return None

    name = ev.event_name(event)
    if name not in EXPOSURE_EVENTS:
        return None

    bucket_name = ev.request_parameters(event).get("bucketName", "")

    return Finding(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity="HIGH",
        summary=f"{name} on bucket {bucket_name or '(unknown)'} — verify it did not become public.",
        event_name=name,
        event_time=ev.event_time(event),
        aws_region=ev.aws_region(event),
        source_ip=ev.source_ip(event),
        actor_arn=ev.actor_arn(event),
        event_id=ev.event_id(event),
        resource_affected=bucket_name,
        raw_event_excerpt=ev.raw_excerpt(event),
    )
