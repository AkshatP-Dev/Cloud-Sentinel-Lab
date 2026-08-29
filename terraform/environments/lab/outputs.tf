output "aws_region" {
  description = "Region CloudSentinel was deployed into — scripts/teardown.sh reads this to make sure its post-destroy verification checks the same region, rather than assuming it matches the AWS CLI's own default."
  value       = var.aws_region
}

output "trail_bucket_name" {
  description = "S3 bucket CloudTrail logs are delivered to."
  value       = module.logging.trail_bucket_name
}

output "trail_arn" {
  description = "ARN of the CloudTrail trail."
  value       = module.logging.trail_arn
}

output "investigator_role_arn" {
  description = "Assume this role (with MFA) to review CloudTrail/IAM state read-only: aws sts assume-role --role-arn <this> --role-session-name investigate --serial-number <your-mfa-device-arn> --token-code <code>"
  value       = module.iam_hardened.investigator_role_arn
}

output "lab_user_arn" {
  description = "ARN of the intentionally-weak lab IAM user."
  value       = module.iam_lab_weak.lab_user_arn
}

output "lab_user_name" {
  description = "Name of the intentionally-weak lab IAM user — pass this to scripts/simulate_events.sh."
  value       = module.iam_lab_weak.lab_user_name
}

output "lab_weak_boundary_arn" {
  description = "ARN of the permission boundary policy — reference this in iam:SimulatePrincipalPolicy tests."
  value       = module.iam_lab_weak.lab_weak_boundary_arn
}

output "sns_topic_arn" {
  description = "ARN of the alerts SNS topic. Confirm the email subscription (check your inbox) or you won't receive alerts."
  value       = module.detection.sns_topic_arn
}

output "detector_function_name" {
  description = "Name of the deployed detector Lambda."
  value       = module.detection.detector_function_name
}

output "responder_function_name" {
  description = "Name of the deployed responder Lambda."
  value       = module.detection.responder_function_name
}

output "budget_name" {
  description = "Name of the AWS Budget cost tripwire."
  value       = aws_budgets_budget.cost_tripwire.name
}
