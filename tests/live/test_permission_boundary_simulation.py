"""
REQUIRES AWS + a completed `terraform apply` (auto-skipped otherwise —
see tests/live/conftest.py).

THE test that actually empirically verifies this project's central
security claim: that the lab identity's permission boundary
(terraform/policies/lab-weak-boundary.json.tpl) constrains it the way
IAM_DESIGN.md says it does, despite its attached policy being a
deliberately over-permissive Action:"*", Resource:"*"
(terraform/policies/lab-weak-attached.json).

Uses iam:SimulatePrincipalPolicy — a read-only IAM API that evaluates
what a principal's ACTUAL policies (identity policy intersected with its
permission boundary) would decide for a hypothetical action, without ever
performing that action. The caller (your own operator credentials) needs
iam:SimulatePrincipalPolicy permission, which a normal admin identity
already has — this does not require assuming the investigator role.

This is the direct, load-bearing verification behind the boundary
redesign documented in IAM_DESIGN.md. If any assertion here fails after a
real change to the boundary, that change broke a specific, named safety
guarantee this project claims to provide — treat a failure here as more
serious than a failure anywhere else in this test suite.
"""
from __future__ import annotations

import boto3
import pytest

pytestmark = pytest.mark.live


@pytest.fixture(scope="module")
def iam_client(tf_outputs, aws_available):
    return boto3.client("iam", region_name=tf_outputs["aws_region"])


@pytest.fixture(scope="module")
def lab_user_arn(tf_outputs):
    return tf_outputs["lab_user_arn"]


@pytest.fixture(scope="module")
def account_id(lab_user_arn):
    # arn:aws:iam::<account_id>:user/<name>
    return lab_user_arn.split(":")[4]


def _decision(iam_client, principal_arn, action, resource_arn="*", context_entries=None):
    kwargs = {
        "PolicySourceArn": principal_arn,
        "ActionNames": [action],
        "ResourceArns": [resource_arn],
    }
    if context_entries:
        kwargs["ContextEntries"] = context_entries
    result = iam_client.simulate_principal_policy(**kwargs)
    evals = result["EvaluationResults"]
    assert len(evals) == 1, f"expected exactly one evaluation result for {action}"
    return evals[0]["EvalDecision"]


class TestCreationTimeScoping:
    """The finding that triggered the boundary redesign: aws:ResourceTag
    cannot constrain resource-CREATION actions, because a not-yet-created
    resource has no tags to match against. lab-weak-boundary.json.tpl
    replaced that with ARN-prefix Resource patterns + aws:RequestTag —
    this class proves the replacement actually works both directions:
    allowed inside the lab prefix with the right tag, denied outside it."""

    def test_create_user_in_lab_prefix_with_tag_is_allowed(self, iam_client, lab_user_arn, account_id):
        target = f"arn:aws:iam::{account_id}:user/cloudsentinel-lab-sim-test"
        decision = _decision(
            iam_client, lab_user_arn, "iam:CreateUser", target,
            context_entries=[{
                "ContextKeyName": "aws:RequestTag/project",
                "ContextKeyValues": ["cloudsentinel"],
                "ContextKeyType": "string",
            }],
        )
        assert decision == "allowed", (
            "Expected the lab identity to be able to create an IAM user inside its own "
            "cloudsentinel-lab-* prefix when tagged project=cloudsentinel — if this fails, "
            "the ARN-prefix + RequestTag redesign in lab-weak-boundary.json.tpl regressed."
        )

    def test_create_user_outside_lab_prefix_is_not_allowed(self, iam_client, lab_user_arn, account_id):
        target = f"arn:aws:iam::{account_id}:user/definitely-not-lab-scoped"
        decision = _decision(
            iam_client, lab_user_arn, "iam:CreateUser", target,
            context_entries=[{
                "ContextKeyName": "aws:RequestTag/project",
                "ContextKeyValues": ["cloudsentinel"],
                "ContextKeyType": "string",
            }],
        )
        assert decision != "allowed", (
            "The lab identity should NOT be able to create an IAM user outside its own "
            "cloudsentinel-lab-* prefix, tag or no tag — this is exactly the false-safety "
            "gap this project's boundary redesign exists to close."
        )


class TestPrivilegeEscalationPrimitivesAreDenied:
    @pytest.mark.parametrize("action", [
        "iam:PassRole", "sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity",
    ])
    def test_escalation_primitive_is_explicit_deny(self, iam_client, lab_user_arn, action):
        decision = _decision(iam_client, lab_user_arn, action)
        assert decision == "explicitDeny", f"{action} should be an explicit Deny; got {decision}"

    @pytest.mark.parametrize("action", [
        "iam:PutUserPermissionsBoundary", "iam:DeleteUserPermissionsBoundary",
        "iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary",
    ])
    def test_boundary_self_removal_is_explicit_deny(self, iam_client, lab_user_arn, action):
        decision = _decision(iam_client, lab_user_arn, action)
        assert decision == "explicitDeny", f"{action} should be an explicit Deny; got {decision}"


class TestAuditLoggingProtections:
    @pytest.mark.parametrize("action", ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail"])
    def test_cloudtrail_tamper_is_explicit_deny(self, iam_client, lab_user_arn, action):
        decision = _decision(iam_client, lab_user_arn, action)
        assert decision == "explicitDeny", f"{action} should be an explicit Deny; got {decision}"

    def test_trail_bucket_policy_change_is_explicit_deny(self, iam_client, lab_user_arn, tf_outputs):
        bucket_arn = f"arn:aws:s3:::{tf_outputs['trail_bucket_name']}"
        decision = _decision(iam_client, lab_user_arn, "s3:PutBucketPolicy", bucket_arn)
        assert decision == "explicitDeny"


class TestRegionLock:
    def test_action_outside_approved_region_is_explicit_deny(self, iam_client, lab_user_arn):
        decision = _decision(
            iam_client, lab_user_arn, "ec2:RunInstances",
            context_entries=[{
                "ContextKeyName": "aws:RequestedRegion",
                "ContextKeyValues": ["eu-west-1"],
                "ContextKeyType": "string",
            }],
        )
        assert decision == "explicitDeny"

    def test_ec2_in_approved_region_is_still_not_allowed(self, iam_client, lab_user_arn, tf_outputs):
        """The attached policy grants Action:'*', Resource:'*' — but the
        boundary's own Allow list never covers EC2 at all. This is the
        concrete proof that the boundary really is the ceiling: even
        in-region, even with a fully-permissive attached policy, the lab
        identity cannot launch an EC2 instance, because the boundary
        never affirmatively allows it. This is the direct answer to
        "isn't an Action:'*' Resource:'*' attached policy dangerous" —
        see IAM_DESIGN.md."""
        decision = _decision(
            iam_client, lab_user_arn, "ec2:RunInstances",
            context_entries=[{
                "ContextKeyName": "aws:RequestedRegion",
                "ContextKeyValues": [tf_outputs["aws_region"]],
                "ContextKeyType": "string",
            }],
        )
        assert decision != "allowed"


class TestReadOnlyDemonstrationAccessWorks:
    """The boundary isn't only denies — confirm the intentionally-granted
    broad read-only access actually works, so the lab identity remains
    usable for its intended demonstration purpose."""

    @pytest.mark.parametrize("action", ["cloudtrail:LookupEvents", "sts:GetCallerIdentity", "iam:ListUsers"])
    def test_readonly_action_is_allowed(self, iam_client, lab_user_arn, action):
        decision = _decision(iam_client, lab_user_arn, action)
        assert decision == "allowed", f"{action} should be allowed (broad read-only); got {decision}"
