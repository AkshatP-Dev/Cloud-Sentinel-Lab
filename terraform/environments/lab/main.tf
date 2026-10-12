# CloudSentinel — lab environment
#
# This is the one root module you actually run `terraform init/plan/apply`
# against. Four modules wire together into the full detect-and-respond
# pipeline, plus one account-wide cost tripwire:
#
#   logging      -> CloudTrail + locked-down S3 bucket
#   iam_hardened -> investigator role (human, MFA) + both Lambda exec roles
#   iam_lab_weak -> the intentionally-weak lab identity under a real boundary
#   detection    -> EventBridge rules, both Lambda functions, SNS topic
#
# Every resource NAME shared across modules (the SNS topic, both Lambda
# function names, the lab user name) is defined exactly once below, as a
# local, and threaded into every module that needs it. That's what keeps
# the deterministic-ARN pattern used throughout this project actually
# consistent — see terraform/modules/iam-hardened/main.tf and
# terraform/modules/detection/main.tf for why those ARNs have to be
# constructed before the real resources exist. If you rename anything,
# change it here and only here.

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  sns_topic_name          = "cloudsentinel-alerts"
  detector_function_name  = "cloudsentinel-detector"
  responder_function_name = "cloudsentinel-responder"
  lab_user_name           = "cloudsentinel-lab-user"
}

module "logging" {
  source = "../../modules/logging"

  account_id     = local.account_id
  aws_region     = var.aws_region
  bucket_name    = var.trail_bucket_name
  retention_days = var.retention_days
}

module "iam_hardened" {
  source = "../../modules/iam-hardened"

  account_id              = local.account_id
  aws_region              = var.aws_region
  operator_principal_arn  = var.operator_principal_arn
  trail_bucket_arn        = module.logging.trail_bucket_arn
  sns_topic_name          = local.sns_topic_name
  detector_function_name  = local.detector_function_name
  responder_function_name = local.responder_function_name
  lab_user_name           = local.lab_user_name
}

module "iam_lab_weak" {
  source = "../../modules/iam-lab-weak"

  account_id       = local.account_id
  aws_region       = var.aws_region
  lab_user_name    = local.lab_user_name
  trail_bucket_arn = module.logging.trail_bucket_arn
}

module "detection" {
  source = "../../modules/detection"

  account_id                     = local.account_id
  aws_region                     = var.aws_region
  lambda_detector_exec_role_arn  = module.iam_hardened.lambda_detector_exec_role_arn
  lambda_responder_exec_role_arn = module.iam_hardened.lambda_responder_exec_role_arn
  detector_function_name         = local.detector_function_name
  responder_function_name        = local.responder_function_name
  sns_topic_name                 = local.sns_topic_name
  alert_email                    = var.alert_email
  lab_user_arn                   = module.iam_lab_weak.lab_user_arn
  log_retention_days             = var.log_retention_days
}

# ---------------------------------------------------------------------------
# Cost tripwire
# ---------------------------------------------------------------------------
# scripts/deploy.sh applies THIS resource first, on its own
# (`terraform apply -target=aws_budgets_budget.cost_tripwire`), before
# running a full apply for everything else. That script — not a Terraform
# depends_on graph — is what actually guarantees the tripwire exists before
# any other resource is created. Terraform has no mechanism to force one
# resource to apply strictly before other, unrelated resources; a manual
# depends_on chain across all four modules just to sequence a budget would
# be a lot of coupling for a property the deploy script already gives us
# directly and verifiably.
#
# In practice, creation-time cost for every other resource in this stack is
# $0 anyway — CloudTrail, S3, Lambda, EventBridge, and SNS don't bill for
# merely existing. What this tripwire actually guards against is
# accumulated usage over the days/weeks after deployment, not the ~30
# seconds `terraform apply` takes to run. See COST.md.
#
# This is an ACCOUNT-WIDE budget, not scoped to CloudSentinel's own tagged
# resources — see the monthly_budget_usd variable description for why.

resource "aws_budgets_budget" "cost_tripwire" {
  name         = "cloudsentinel-monthly-tripwire"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # A fixed past date, not timestamp() — timestamp() re-evaluates on every
  # plan and would produce a permanent diff on every subsequent run. AWS
  # Budgets tracks the CURRENT monthly period for a MONTHLY time_unit
  # budget regardless of this value; it only needs a valid date in the past.
  time_period_start = "2024-01-01_00:00"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }
}
