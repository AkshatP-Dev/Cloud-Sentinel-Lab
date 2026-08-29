output "lab_user_arn" {
  description = "ARN of the intentionally-weak lab IAM user."
  value       = aws_iam_user.lab.arn
}

output "lab_user_name" {
  description = "Name of the intentionally-weak lab IAM user."
  value       = aws_iam_user.lab.name
}

output "lab_weak_boundary_arn" {
  description = "ARN of the permission boundary policy attached to the lab user. Reference this in tests / iam:SimulatePrincipalPolicy calls."
  value       = aws_iam_policy.lab_weak_boundary.arn
}

output "lab_weak_attached_policy_arn" {
  description = "ARN of the intentionally over-permissive policy attached to the lab user."
  value       = aws_iam_policy.lab_weak_attached.arn
}
