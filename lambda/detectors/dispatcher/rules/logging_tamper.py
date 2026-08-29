"""
D-02 — CloudTrail / audit-logging tamper.

Fires on any successful attempt to weaken or remove the audit trail this
whole project depends on: stopping, deleting, or reconfiguring the
CloudTrail trail itself, or modifying the S3 bucket it delivers logs to
(policy, ACL, public access block, versioning, lifecycle, or deletion).

Several of these event names deliberately mirror the Deny statements in
terraform/policies/lab-weak-boundary.json.tpl (DenyTouchingAuditLogging,
DenyTouchingTrailBucket): what the boundary prevents by policy, this rule
independently watches for by event — so a misconfigured or bypassed
boundary is still visible here. See IAM_DESIGN.md.

Two event-name pairs appear because the IAM action name and the CloudTrail
eventName for S3's public-access-block operations are, confusingly, not
the same string (s3:PutBucketPublicAccessBlock the IAM action vs.
PutPublicAccessBlock / DeletePublicAccessBlock as logged eventNames) — see
the comment in terraform/policies/lab-weak-boundary.json.tpl for how that
was verified. Both spellings are matched here for the same reason both are
denied there: to close any gap from a naming mismatch either way.
"""
from __future__ import annotations

import event_utils as ev
from finding import Finding

RULE_ID = "D-02"
RULE_NAME = "logging_tamper"

TAMPER_EVENTS = {
    "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "RemoveTags",
    "PutBucketPolicy", "DeleteBucketPolicy",
    "PutBucketPublicAccessBlock", "PutPublicAccessBlock",
    "DeleteBucketPublicAccessBlock", "DeletePublicAccessBlock",
    "PutBucketAcl", "PutBucketVersioning", "DeleteBucket", "PutLifecycleConfiguration",
}


def check(event: dict) -> Finding | None:
    if ev.is_error(event):
        return None

    name = ev.event_name(event)
    if name not in TAMPER_EVENTS:
        return None

    return Finding(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity="CRITICAL",
        summary=f"Possible audit-logging tamper: {name}.",
        event_name=name,
        event_time=ev.event_time(event),
        aws_region=ev.aws_region(event),
        source_ip=ev.source_ip(event),
        actor_arn=ev.actor_arn(event),
        event_id=ev.event_id(event),
        raw_event_excerpt=ev.raw_excerpt(event),
    )
