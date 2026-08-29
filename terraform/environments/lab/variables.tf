variable "aws_region" {
  description = <<-EOT
    AWS region to deploy CloudSentinel into. All resources are region-scoped;
    the lab permission boundary explicitly denies activity outside this
    region (see terraform/policies/lab-weak-boundary.json.tpl).

    Defaults to us-east-1, not the ap-south-1 originally proposed during
    design: aws_budgets_budget.cost_tripwire (below) uses the AWS Budgets
    API, which AWS only serves from three regions — us-east-1, us-west-2,
    and ca-central-1 (verified against AWS's own service-endpoints
    documentation) — regardless of which region the rest of the account's
    resources live in. Since this file's single `provider "aws"` block
    (versions.tf) applies one region to every resource including the
    budget, ap-south-1 would have made the budget tripwire fail to apply
    at all. Deploying everything to us-east-1 was the simplest fix; the
    alternative (a second aliased provider pinned to us-east-1 for just the
    budget resource, letting everything else stay on ap-south-1) is real
    but adds real complexity for a single-resource exception — pick that
    instead if being in ap-south-1 for the rest of the stack matters to you.
  EOT
  type        = string
  default     = "us-east-1"
}

variable "operator_principal_arn" {
  description = <<-EOT
    YOUR OWN IAM identity's ARN — the principal allowed to assume the
    investigator role (with MFA present). This is deliberately NOT
    auto-derived from your current credentials, because if you authenticate
    via IAM Identity Center / SSO, `aws sts get-caller-identity` returns a
    session-specific assumed-role ARN
    (arn:aws:sts::ACCOUNT:assumed-role/RoleName/SessionName) that is NOT a
    valid trust-policy principal — you need the underlying ROLE ARN instead
    (arn:aws:iam::ACCOUNT:role/RoleName, found via `aws iam list-roles` or
    the IAM console). If you authenticate as a plain IAM user, your user
    ARN from `aws sts get-caller-identity --query Arn --output text` is
    already correct as-is.
  EOT
  type        = string
}

variable "alert_email" {
  description = "Email address for SNS alerts and AWS Budget notifications. AWS sends confirmation emails after `terraform apply` that must be clicked before either actually delivers — see the deployment checklist."
  type        = string
}

variable "trail_bucket_name" {
  description = "Globally-unique S3 bucket name for CloudTrail logs. S3 bucket names collide across ALL of AWS, not just your account — suffix with your account ID, e.g. cloudsentinel-trail-123456789012."
  type        = string
}

variable "monthly_budget_usd" {
  description = "Monthly AWS Budget tripwire amount, in whole US dollars. This is an ACCOUNT-WIDE budget, not scoped only to CloudSentinel resources — see COST.md for why (tag-scoped AWS Budgets require activating cost allocation tags in Billing preferences first, a manual step with up to a 24-hour propagation delay, which isn't something Terraform can provision). Notifications fire at 80% and 100% of this amount."
  type        = number
  default     = 5
}

variable "retention_days" {
  description = "Days before a CloudTrail log object expires via S3 lifecycle."
  type        = number
  default     = 90
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for both Lambda function log groups."
  type        = number
  default     = 14
}
