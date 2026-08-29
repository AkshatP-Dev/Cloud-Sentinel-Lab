"""
D-01 — root account usage.

Fires on ANY AWS API call or console sign-in performed by the AWS account
root user — successful or not. There is no legitimate routine reason to
use root for day-to-day operations; AWS's own guidance is to lock root
away behind MFA and a hardware token and use it only for the handful of
account-level tasks that genuinely require it. Any root activity in this
lab, including a FAILED attempt, is worth a human's attention — a denied
root sign-in attempt is arguably a more interesting signal than a
successful one, since it can indicate someone probing root credentials.
That's why, unlike every other rule here, this one does not skip errored
events (see event_utils.is_error).

Matches on userIdentity.type == "Root" — see the root_usage EventBridge
rule in terraform/modules/detection/main.tf, which routes every
root-performed event (any service, any action) to the dispatcher
regardless of eventName, since that pattern can't be expressed as an
eventName allowlist.
"""
from __future__ import annotations

import event_utils as ev
from finding import Finding

RULE_ID = "D-01"
RULE_NAME = "root_usage"


def check(event: dict) -> Finding | None:
    if ev.user_identity_type(event) != "Root":
        return None

    name = ev.event_name(event)
    outcome = "FAILED " if ev.is_error(event) else ""
    description = name or "a console sign-in"

    return Finding(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity="CRITICAL",
        summary=f"Root account {outcome}performed {description}.",
        event_name=name,
        event_time=ev.event_time(event),
        aws_region=ev.aws_region(event),
        source_ip=ev.source_ip(event),
        actor_arn=ev.actor_arn(event) if ev.actor_arn(event) != "unknown" else "root",
        event_id=ev.event_id(event),
        raw_event_excerpt=ev.raw_excerpt(event),
    )
