# CloudSentinel — hardened IAM module
#
# Three roles, each scoped to exactly what it needs and nothing more:
#
#   1. cloudsentinel-investigator   — human-assumed, MFA-required, read-only.
#      Assume this role to review CloudTrail history and IAM state during an
#      investigation without being able to change anything.
#
#   2. cloudsentinel-detector-exec  — the detection dispatcher Lambda's
#      execution role. Can read IAM policy *content* (to evaluate findings
#      against live policy documents) and publish to SNS. Cannot modify
#      anything in the account.
#
#   3. cloudsentinel-responder-exec — the scoped responder Lambda's execution
#      role. Can list/read access keys and deactivate an access key on
#      exactly ONE IAM user — the intentionally-weak lab identity this
#      project creates to be "attacked" — and nothing else, never Resource:
#      "*". See IAM_DESIGN.md and lambda/responders/quarantine/handler.py:
#      the Lambda code ALSO hard-codes the same ARN check, so this is
#      defense in depth — the IAM policy is the ceiling even if the code had
#      a bug, and the code is a second check even if the policy had one.
#
# All three trust/permission documents live in ../../policies/ as static
# JSON or .tpl files rendered here with templatefile() — see that
# directory's own file comments for the policy semantics, and
# IAM_DESIGN.md for the full narrative (including why the lab boundary was
# redesigned from its originally-proposed form).
#
# The SNS topic ARN and the lab-user ARN are both constructed
# deterministically from name variables rather than taken as outputs from
# other modules, because those resources (the SNS topic in the detection
# module, the IAM user in the iam-lab-weak module) do not exist yet when
# this module runs, and Terraform has no "give me the ARN this resource
# WILL have" mechanism across independent modules. The calling environment
# is responsible for passing the same name variables into every module that
# needs them — see environments/lab/main.tf, which defines each name once
# in a local value and threads it through. This is the same pattern the
# logging module uses for the CloudTrail trail ARN (see that module's
# main.tf).

locals {
  sns_topic_arn         = "arn:aws:sns:${var.aws_region}:${var.account_id}:${var.sns_topic_name}"
  lab_user_arn          = "arn:aws:iam::${var.account_id}:user/${var.lab_user_name}"
  responder_function_arn = "arn:aws:lambda:${var.aws_region}:${var.account_id}:function:${var.responder_function_name}"

  common_tags = {
    project = "cloudsentinel"
  }
}

# ---------------------------------------------------------------------------
# 1. Investigator role — human-assumed, MFA-required, read-only
# ---------------------------------------------------------------------------

resource "aws_iam_role" "investigator" {
  name = "cloudsentinel-investigator"

  assume_role_policy = templatefile("${path.module}/../../policies/investigator-trust.json.tpl", {
    operator_principal_arn = var.operator_principal_arn
  })

  max_session_duration = 3600 # 1 hour — investigations are short sessions, not standing access

  tags = local.common_tags
}

resource "aws_iam_role_policy" "investigator_readonly" {
  name = "investigator-readonly"
  role = aws_iam_role.investigator.id

  policy = templatefile("${path.module}/../../policies/investigator-readonly.json.tpl", {
    trail_bucket_arn = var.trail_bucket_arn
  })
}

# ---------------------------------------------------------------------------
# 2. Detector Lambda execution role
# ---------------------------------------------------------------------------

resource "aws_iam_role" "lambda_detector_exec" {
  name               = "cloudsentinel-detector-exec"
  assume_role_policy = file("${path.module}/../../policies/lambda-trust.json")

  tags = local.common_tags
}

resource "aws_iam_role_policy" "lambda_detector_exec" {
  name = "detector-exec-policy"
  role = aws_iam_role.lambda_detector_exec.id

  policy = templatefile("${path.module}/../../policies/lambda-detector-exec.json.tpl", {
    sns_topic_arn           = local.sns_topic_arn
    region                  = var.aws_region
    account_id              = var.account_id
    detector_function_name  = var.detector_function_name
    responder_function_arn  = local.responder_function_arn
  })
}

# ---------------------------------------------------------------------------
# 3. Responder Lambda execution role
# ---------------------------------------------------------------------------

resource "aws_iam_role" "lambda_responder_exec" {
  name               = "cloudsentinel-responder-exec"
  assume_role_policy = file("${path.module}/../../policies/lambda-trust.json")

  tags = local.common_tags
}

resource "aws_iam_role_policy" "lambda_responder_exec" {
  name = "responder-exec-policy"
  role = aws_iam_role.lambda_responder_exec.id

  policy = templatefile("${path.module}/../../policies/lambda-responder-exec.json.tpl", {
    lab_user_arn             = local.lab_user_arn
    sns_topic_arn            = local.sns_topic_arn
    region                   = var.aws_region
    account_id               = var.account_id
    responder_function_name  = var.responder_function_name
  })
}
