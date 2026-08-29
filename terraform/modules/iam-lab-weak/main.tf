# CloudSentinel — intentionally-weak lab identity module
#
# This module creates the "attack surface" the rest of the project detects
# and responds to: one IAM user with a deliberately over-permissive attached
# policy (Action:"*", Resource:"*" — see ../../policies/lab-weak-attached.json)
# representing the kind of legacy or careless over-grant this project exists
# to catch, constrained ONLY by a permission boundary.
#
# THE BOUNDARY IS THE ACTUAL SAFETY MECHANISM, not the attached policy — its
# correctness matters more than anything else in this repository. Full
# narrative in IAM_DESIGN.md, but in short:
#
#   The originally-designed boundary (any action, gated only by an
#   aws:ResourceTag condition) would NOT have reliably constrained
#   resource-CREATION actions. aws:ResourceTag evaluates against tags on a
#   resource that already exists; a not-yet-created resource has no tags to
#   match, so the condition would simply never trigger for the highest-risk
#   actions — iam:CreateUser, iam:PassRole, sts:AssumeRole, and removing
#   the boundary itself — leaving them effectively unconstrained. That is a
#   false safety guarantee, not a real one.
#
#   This boundary (../../policies/lab-weak-boundary.json.tpl) instead uses:
#     - ARN-prefix resource patterns as the primary Allow mechanism, which
#       DO reliably apply at creation time — the target ARN is derived from
#       the request's own resource-name parameter, not a lookup against an
#       existing resource's tags;
#     - aws:RequestTag (not aws:ResourceTag) as a secondary condition, since
#       RequestTag is the key that actually evaluates against the tags
#       supplied WITH the current request;
#     - explicit Deny statements for every privilege-escalation primitive
#       (iam:PassRole, sts:AssumeRole*), self-boundary-removal, audit-log
#       tampering (stopping/deleting/reconfiguring the trail), trail-bucket
#       tampering (including both plausible IAM action spellings for the S3
#       public-access-block actions — see that file's own comments), and
#       requests outside the approved region.
#
# This module deliberately does NOT create an access key on the lab user.
# Simulated "incidents" — in particular, a new access key appearing — are
# performed afterward via scripts/simulate_events.sh using the AWS CLI
# against the already-deployed user, not through Terraform. Two reasons:
#
#   1. Realism: the detection is supposed to catch something HAPPENING to
#      already-deployed infrastructure, not something present from the
#      first `terraform apply`.
#
#   2. State drift: if Terraform owned the access key resource, the
#      responder Lambda's entire job during an incident-response drill
#      (iam:UpdateAccessKey to deactivate the key) would leave live AWS
#      state at odds with Terraform state. The next `terraform apply` would
#      then try to "fix" that drift by reactivating the very key the
#      responder just quarantined — directly fighting the system this
#      project exists to demonstrate. Keeping key lifecycle out of
#      Terraform avoids that failure mode entirely.
#
# To exclude the lab identity from a deployment altogether — e.g. running
# the detection pipeline with zero standing "weak" attack surface — comment
# out the module "iam_lab_weak" block in environments/lab/main.tf. Nothing
# else in this stack depends on these resources existing at plan/apply time,
# only on the deterministic ARN string built from lab_user_name in the
# iam-hardened module.

resource "aws_iam_policy" "lab_weak_boundary" {
  name        = "cloudsentinel-lab-weak-boundary"
  description = "Permission boundary for the intentionally-weak CloudSentinel lab user. This is the real ceiling on what the lab identity can do — see this module's main.tf header and IAM_DESIGN.md before changing it."

  policy = templatefile("${path.module}/../../policies/lab-weak-boundary.json.tpl", {
    account_id       = var.account_id
    aws_region       = var.aws_region
    trail_bucket_arn = var.trail_bucket_arn
  })

  tags = {
    project = "cloudsentinel"
  }
}

resource "aws_iam_policy" "lab_weak_attached" {
  name        = "cloudsentinel-lab-weak-attached"
  description = "Intentionally over-permissive policy attached to the lab user. Safe ONLY because of the permission boundary above — never attach this policy to any identity that lacks an equivalent boundary."

  policy = file("${path.module}/../../policies/lab-weak-attached.json")

  tags = {
    project = "cloudsentinel"
  }
}

resource "aws_iam_user" "lab" {
  #checkov:skip=CKV_AWS_273:This IS the finding, not a gap. A directly-defined IAM user with a direct policy attachment (instead of SSO / group membership) is exactly the over-permissioned legacy identity pattern this entire project exists to detect and contain — see this file's header comment and IAM_DESIGN.md. Checkov flagging it here confirms the scanner works correctly, the same way tests/offline/test_checkov_scan.py's known-bad fixture does deliberately.
  name                 = var.lab_user_name
  permissions_boundary = aws_iam_policy.lab_weak_boundary.arn

  tags = {
    project = "cloudsentinel"
    purpose = "intentionally-weak-lab-identity"
  }
}

resource "aws_iam_user_policy_attachment" "lab_weak" {
  #checkov:skip=CKV_AWS_40:Same reasoning as aws_iam_user.lab above — a policy attached directly to a user (rather than a group/role) is the deliberate subject of this project, not an oversight.
  user       = aws_iam_user.lab.name
  policy_arn = aws_iam_policy.lab_weak_attached.arn
}
