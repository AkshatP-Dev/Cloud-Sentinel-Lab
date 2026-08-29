"""
D-03 — privilege-escalation primitives.

Fires on successful use of any IAM/STS action commonly used to escalate
privilege: creating a new identity, attaching or inlining a policy onto a
user/role, passing a role to a service, assuming a role, or
adding/removing a permission boundary. None of these are inherently
malicious — the lab identity itself is allowed to use several of them on
its own scoped resources (see
terraform/policies/lab-weak-boundary.json.tpl's
AllowManagingOwnLabScopedIamResources statement) — this rule is
deliberately broad and alert-only, never auto-blocked, matching how a real
detection flags a PATTERN for a human to evaluate in context rather than
assuming every match is an actual attack.

Touching a permission boundary is treated as materially more severe than
routine policy management: a lab identity legitimately attaches its own
policies, but nothing should ever be adding or removing a boundary after
initial deployment.
"""
from __future__ import annotations

import event_utils as ev
from finding import Finding

RULE_ID = "D-03"
RULE_NAME = "privilege_escalation"

ESCALATION_EVENTS = {
    "CreateUser", "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
    "CreatePolicyVersion", "PassRole", "AssumeRole",
    "PutUserPermissionsBoundary", "DeleteUserPermissionsBoundary",
    "PutRolePermissionsBoundary", "DeleteRolePermissionsBoundary",
}

BOUNDARY_EVENTS = {
    "PutUserPermissionsBoundary", "DeleteUserPermissionsBoundary",
    "PutRolePermissionsBoundary", "DeleteRolePermissionsBoundary",
}


def check(event: dict) -> Finding | None:
    if ev.is_error(event):
        return None

    name = ev.event_name(event)
    if name not in ESCALATION_EVENTS:
        return None

    severity = "CRITICAL" if name in BOUNDARY_EVENTS else "HIGH"

    return Finding(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity=severity,
        summary=f"Privilege-escalation-capable action: {name}.",
        event_name=name,
        event_time=ev.event_time(event),
        aws_region=ev.aws_region(event),
        source_ip=ev.source_ip(event),
        actor_arn=ev.actor_arn(event),
        event_id=ev.event_id(event),
        raw_event_excerpt=ev.raw_excerpt(event),
    )
