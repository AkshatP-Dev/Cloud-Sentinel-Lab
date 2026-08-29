# D-03 — Privilege-Escalation Primitives

| | |
|---|---|
| **Severity** | HIGH (CRITICAL if a permission boundary is touched) |
| **Automated response** | None (alert only) |
| **Rule logic** | `lambda/detectors/dispatcher/rules/privilege_escalation.py` |
| **EventBridge pattern** | `D-03-privilege-escalation.json` (this directory) — this detection's own event names; merged into the deployed `cloudsentinel-scoped-events` rule alongside D-02/D-04/D-05, see `terraform/modules/detection/main.tf`. |

## What it detects

Successful use of any IAM/STS action commonly used as a building block for
privilege escalation: creating a new identity, attaching or inlining a
policy onto a user/role, passing a role to a service (`iam:PassRole`),
assuming a role, or adding/removing a permission boundary.

## Why alert-only, and why broad

None of these actions are inherently malicious — the lab identity itself
is allowed to use several of them against its own scoped resources (see
`terraform/policies/lab-weak-boundary.json.tpl`'s
`AllowManagingOwnLabScopedIamResources` statement). This rule is
deliberately broad and never auto-blocks anything: it flags a *pattern*
for a human to evaluate in context, the same way a real detection
pipeline would, rather than assuming every match is an actual attack.

## Why boundary events are CRITICAL, not just HIGH

`PutUserPermissionsBoundary`, `DeleteUserPermissionsBoundary`,
`PutRolePermissionsBoundary`, and `DeleteRolePermissionsBoundary` are
escalated to CRITICAL specifically. A lab identity legitimately creates
and attaches its own policies routinely — but nothing should ever be
touching a permission *boundary* after initial deployment. A boundary
change is the one action in this list that, if it succeeded
unexpectedly, would mean the entire safety model this project relies on
just changed.

## Testing

`scripts/simulate_events.sh` triggers this safely by creating a
throwaway, clearly-lab-scoped IAM user
(`cloudsentinel-lab-sim-user`, inside the boundary's allowed name prefix)
and attaching a policy to it, then deleting both immediately after. This
exercises `CreateUser` and `AttachUserPolicy` without leaving any standing
resource behind.

## Known false positives

`terraform apply` generates several of these event names on first
deploy (creating the lab user, attaching its policy) and the responder
Lambda's own execution role setup involves `iam:PassRole`-adjacent
activity indirectly through Lambda's own service role assumption — those
are expected, not incidents. As with D-02, the detector doesn't attempt
to distinguish "expected infrastructure setup" from "unexpected change"
automatically; that judgment is the human reviewing the alert.
