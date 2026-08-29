"""
D-04 — access key created or (re)activated.

Fires on CreateAccessKey, or an UpdateAccessKey call that sets Status to
Active, against ANY IAM user in the account — this rule intentionally does
NOT filter to only the lab user, so a real account would get equal
visibility into unexpected key creation anywhere. What IS scoped to the
lab user specifically is the AUTOMATED RESPONSE: handler.py only invokes
the responder Lambda when this Finding's resource_affected matches the
configured lab user exactly (see handler.py's _is_lab_user and
IAM_DESIGN.md). This rule's only job is to detect and describe — deciding
whether to act is centralized in the dispatcher, not duplicated here.

This is the one detection with a real automated response behind it: see
lambda/responders/quarantine/handler.py.
"""
from __future__ import annotations

import event_utils as ev
from finding import Finding

RULE_ID = "D-04"
RULE_NAME = "access_key_created"

KEY_EVENTS = {"CreateAccessKey", "UpdateAccessKey"}


def check(event: dict) -> Finding | None:
    if ev.is_error(event):
        return None

    name = ev.event_name(event)
    if name not in KEY_EVENTS:
        return None

    request_params = ev.request_parameters(event)
    response_elems = ev.response_elements(event)

    if name == "UpdateAccessKey":
        # UpdateAccessKey covers both activating AND deactivating a key.
        # Only activation is "new usable credential material" — the
        # responder itself performs the deactivating half, so alerting on
        # deactivation too would mean every automated response re-triggers
        # this same rule.
        status = str(request_params.get("status", "")).lower()
        if status != "active":
            return None
        target_user = request_params.get("userName", "")
        access_key_id = request_params.get("accessKeyId", "")
    else:  # CreateAccessKey
        access_key = response_elems.get("accessKey", {}) or {}
        target_user = access_key.get("userName") or request_params.get("userName", "")
        access_key_id = access_key.get("accessKeyId", "")

    return Finding(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity="HIGH",
        summary=f"{name} for IAM user {target_user or '(unknown)'}.",
        event_name=name,
        event_time=ev.event_time(event),
        aws_region=ev.aws_region(event),
        source_ip=ev.source_ip(event),
        actor_arn=ev.actor_arn(event),
        event_id=ev.event_id(event),
        resource_affected=target_user,
        access_key_id=access_key_id,
        raw_event_excerpt=ev.raw_excerpt(event),
    )
