"""
Offline (no AWS credentials needed) semantic self-consistency checks on
the IAM policy documents — beyond the pure JSON/grammar checks in
scripts/dev/validate_tf_structure.py (test_terraform_validate.py).

These specifically regression-guard the permission-boundary redesign
described in IAM_DESIGN.md: if terraform/policies/lab-weak-boundary.json.tpl
is edited later and a Deny statement this project's safety claim depends
on gets accidentally removed or weakened, these tests catch it without
needing live AWS access — a fast, always-available complement to
tests/live/test_permission_boundary_simulation.py, which is the real,
load-bearing empirical verification against actual IAM policy evaluation.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICIES_DIR = REPO_ROOT / "terraform" / "policies"


def _load_stripped(filename: str) -> dict:
    text = (POLICIES_DIR / filename).read_text()
    dummy = re.sub(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", "DUMMY", text)
    return json.loads(dummy)


def _statements(doc: dict) -> list[dict]:
    stmts = doc.get("Statement", [])
    return [stmts] if isinstance(stmts, dict) else stmts


def _actions_denied(doc: dict) -> set[str]:
    denied = set()
    for stmt in _statements(doc):
        if stmt.get("Effect") != "Deny":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        denied.update(actions)
    return denied


@pytest.fixture(scope="module")
def boundary():
    return _load_stripped("lab-weak-boundary.json.tpl")


REQUIRED_DENIED_ACTIONS = {
    # privilege-escalation primitives
    "iam:PassRole", "sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity",
    # self-boundary removal
    "iam:PutUserPermissionsBoundary", "iam:DeleteUserPermissionsBoundary",
    "iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary",
    # audit-logging tamper
    "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
    # trail-bucket tamper
    "s3:PutBucketPolicy", "s3:DeleteBucket",
}


def test_boundary_denies_every_required_action(boundary):
    denied = _actions_denied(boundary)
    missing = REQUIRED_DENIED_ACTIONS - denied
    assert not missing, (
        f"lab-weak-boundary.json.tpl no longer explicitly denies: {missing} — this is "
        f"exactly the class of regression IAM_DESIGN.md's redesign exists to prevent."
    )


def test_boundary_does_not_rely_on_resourcetag_for_creation_actions(boundary):
    """The specific bug this project's redesign fixed: aws:ResourceTag
    cannot constrain resource-CREATION actions, because a not-yet-created
    resource has no tags to match yet. If aws:ResourceTag reappears
    anywhere in this file, someone likely reintroduced the original flaw."""
    text = json.dumps(boundary)
    assert "aws:ResourceTag" not in text, (
        "aws:ResourceTag found in the boundary — this condition key does not reliably "
        "constrain resource-creation actions (see IAM_DESIGN.md). Use aws:RequestTag "
        "and/or an ARN-prefix Resource pattern instead."
    )


def test_boundary_creation_allow_uses_arn_prefix_not_wildcard_resource(boundary):
    """The primary Allow statement for lab-scoped IAM management must
    scope Resource to the cloudsentinel-lab-* prefix specifically — never
    Resource: '*' — or the boundary stops being a meaningful ceiling for
    those actions at all."""
    for stmt in _statements(boundary):
        if stmt.get("Sid") == "AllowManagingOwnLabScopedIamResources":
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            assert resources, "expected a non-empty Resource list"
            assert all(r != "*" for r in resources), (
                "AllowManagingOwnLabScopedIamResources must not use Resource: '*' — the "
                "whole point of the redesign is ARN-prefix scoping."
            )
            assert all("cloudsentinel-lab-" in r for r in resources), (
                f"expected every resource pattern scoped to the cloudsentinel-lab- prefix, "
                f"got: {resources}"
            )
            return
    pytest.fail("Could not find the AllowManagingOwnLabScopedIamResources statement.")


def test_boundary_has_no_bare_allow_star_star():
    """No statement in the boundary should be Effect: Allow, Action: '*',
    Resource: '*' — that would make the boundary meaningless as a
    ceiling regardless of what else it contains. (The attached policy,
    lab-weak-attached.json, IS exactly this — deliberately, and ONLY
    safe because the boundary is not.)"""
    boundary_doc = _load_stripped("lab-weak-boundary.json.tpl")
    for stmt in _statements(boundary_doc):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        assert not ("*" in actions and "*" in resources), (
            f"Statement {stmt.get('Sid')} allows Action:'*' Resource:'*' inside the "
            f"BOUNDARY itself — this would make it provide no ceiling at all."
        )


def test_lab_weak_attached_policy_is_intentionally_broad():
    """Sanity check that the attached policy is what IAM_DESIGN.md says it
    is — deliberately Action:'*' Resource:'*', safe ONLY because of the
    boundary tested above. If this ever changes, that narrative needs to
    change with it."""
    doc = _load_stripped("lab-weak-attached.json")
    stmts = _statements(doc)
    assert len(stmts) == 1
    assert stmts[0]["Effect"] == "Allow"
    assert stmts[0]["Action"] == "*"
    assert stmts[0]["Resource"] == "*"


def test_responder_exec_policy_never_uses_wildcard_resource_for_key_actions():
    """The responder's whole safety story depends on iam:UpdateAccessKey
    (and the accompanying List/Get calls) being scoped to exactly one
    ARN, never '*' — see lambda/responders/quarantine/handler.py's module
    docstring. This is the IAM-policy half of that story; the
    application-code half is tested in tests/unit/responder/."""
    doc = _load_stripped("lambda-responder-exec.json.tpl")
    for stmt in _statements(doc):
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if "iam:UpdateAccessKey" in actions:
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            assert resources != ["*"] and "*" not in resources, (
                f"iam:UpdateAccessKey must not be granted on Resource: '*'; "
                f"got {resources}"
            )
            return
    pytest.fail("Could not find an iam:UpdateAccessKey statement in lambda-responder-exec.json.tpl")
