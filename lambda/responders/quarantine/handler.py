"""
CloudSentinel responder — "quarantine" Lambda entry point.

Invoked directly by the detector dispatcher (never by EventBridge — see
terraform/modules/detection/main.tf's comments) ONLY for a confirmed D-04
finding whose affected IAM user is exactly the lab identity. This
function's entire job is to deactivate an access key on that one IAM
user, and it is deliberately paranoid about scope, because it is the one
place in this project that takes a real, if reversible, action against
live AWS state:

  1. IAM-POLICY-LEVEL scoping
     (terraform/policies/lambda-responder-exec.json.tpl): this function's
     execution role can only call iam:ListAccessKeys,
     iam:GetAccessKeyLastUsed, and iam:UpdateAccessKey against ONE
     specific ARN — the lab user's — never Resource: "*". If the checks
     below somehow had a bug, AWS itself would still reject a call
     against any other identity.

  2. APPLICATION-CODE-LEVEL check (_assert_target_is_lab_user below): even
     though the IAM policy would already reject a call against any other
     user, this code refuses to even ATTEMPT the call unless the target
     username matches the LAB_USER_ARN environment variable exactly. Two
     independent layers that both have to agree before anything happens —
     see IAM_DESIGN.md for the full defense-in-depth narrative.

  3. RE-VERIFICATION AGAINST LIVE STATE: rather than trust the access key
     ID forwarded in the invocation payload, this function calls
     iam:ListAccessKeys itself immediately before acting, and only
     deactivates keys it can currently see as Active.

Deactivating (not deleting) the key is deliberate: it's a reversible
containment action, not a destructive one — see README.md/SECURITY.md's
safety constraints. A human can reactivate the key with
`aws iam update-access-key --status Active` once they've confirmed it was
a benign test rather than a real compromise.
"""
from __future__ import annotations

import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
LAB_USER_ARN = os.environ.get("LAB_USER_ARN", "")

_iam = None
_sns = None


def _iam_client():
    global _iam
    if _iam is None:
        _iam = boto3.client("iam")
    return _iam


def _sns_client():
    global _sns
    if _sns is None:
        _sns = boto3.client("sns")
    return _sns


class ResponderRefused(Exception):
    """Raised when the safety checks below refuse to act. Treat this as
    an expected, logged outcome — not a crash. lambda_handler catches it
    and returns a structured "refused" result rather than letting it
    propagate as a Lambda error."""


def _lab_user_name() -> str:
    if not LAB_USER_ARN:
        raise ResponderRefused("LAB_USER_ARN is not configured; refusing to act on anything.")
    return LAB_USER_ARN.rsplit("/", 1)[-1]


def _assert_target_is_lab_user(target_user: str) -> str:
    """The one hard-coded safety gate this whole function exists to
    enforce. Returns the confirmed lab user name, or raises
    ResponderRefused — never silently falls through to acting on a
    different identity."""
    expected = _lab_user_name()
    if not target_user or target_user != expected:
        raise ResponderRefused(
            f"Refusing to act: target user {target_user!r} does not match "
            f"the configured lab user {expected!r}."
        )
    return expected


def _deactivate_key(user_name: str, access_key_id: str) -> None:
    _iam_client().update_access_key(
        UserName=user_name,
        AccessKeyId=access_key_id,
        Status="Inactive",
    )
    logger.info("Deactivated access key %s on %s.", access_key_id, user_name)


def _publish_containment_notice(user_name: str, deactivated_key_ids: list[str], finding_summary: str) -> None:
    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN not set; containment notice was logged but not published.")
        return
    message = "\n".join([
        "[CloudSentinel] CONTAINED — responder took action",
        "",
        f"User: {user_name}",
        f"Deactivated key(s): {', '.join(deactivated_key_ids) or '(none — see logs)'}",
        f"Triggering finding: {finding_summary}",
        "",
        "This is a REVERSIBLE containment action. If this was a benign test, "
        f"reactivate with: aws iam update-access-key --user-name {user_name} "
        "--access-key-id <key-id> --status Active",
    ])
    _sns_client().publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="[CloudSentinel][CONTAINED] Lab access key deactivated"[:100],
        Message=message,
    )


def lambda_handler(event: dict, context) -> dict:
    """`event` here is the Finding dict the dispatcher built (see
    finding.py's Finding.to_dict() / to_json()) — this function is only
    ever invoked directly by the dispatcher (InvocationType="Event"),
    never by EventBridge, so `event` is never a raw CloudTrail/EventBridge
    envelope."""
    logger.info("Responder invoked with payload: %s", json.dumps(event, default=str))

    target_user = event.get("resource_affected", "")
    requested_key_id = event.get("access_key_id", "")
    finding_summary = event.get("summary", "(no summary provided)")

    try:
        user_name = _assert_target_is_lab_user(target_user)
    except ResponderRefused as e:
        logger.error(str(e))
        return {"action": "refused", "reason": str(e)}

    active = _iam_client().list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
    active_key_ids = [k["AccessKeyId"] for k in active if k.get("Status") == "Active"]

    if requested_key_id and requested_key_id in active_key_ids:
        to_deactivate = [requested_key_id]
    else:
        # Either no specific key was named, or the named key is no longer
        # active (e.g. someone already handled it) — fall back to
        # whatever is currently active on the lab user, so this doesn't
        # silently no-op just because the payload was stale.
        to_deactivate = active_key_ids

    if not to_deactivate:
        logger.info("No active access keys found on %s; nothing to do.", user_name)
        return {"action": "noop", "reason": "no active keys found", "user": user_name}

    for key_id in to_deactivate:
        _deactivate_key(user_name, key_id)

    _publish_containment_notice(user_name, to_deactivate, finding_summary)

    return {"action": "contained", "user": user_name, "deactivated_key_ids": to_deactivate}
