output "investigator_role_arn" {
  description = "ARN of the investigator role. Operators assume this (with MFA) to review CloudTrail/IAM state read-only."
  value       = aws_iam_role.investigator.arn
}

output "investigator_role_name" {
  description = "Name of the investigator role."
  value       = aws_iam_role.investigator.name
}

output "lambda_detector_exec_role_arn" {
  description = "ARN of the detector Lambda's execution role. Pass into the detection module's dispatcher aws_lambda_function.role."
  value       = aws_iam_role.lambda_detector_exec.arn
}

output "lambda_responder_exec_role_arn" {
  description = "ARN of the responder Lambda's execution role. Pass into the detection module's responder aws_lambda_function.role."
  value       = aws_iam_role.lambda_responder_exec.arn
}

output "sns_topic_arn" {
  description = "Deterministically-constructed SNS topic ARN, used by both exec-role policies above. The detection module's aws_sns_topic MUST be created with `name` (not name_prefix) equal to the same sns_topic_name value passed into this module, or the real topic's ARN will not match what these IAM policies grant sns:Publish on and Publish calls will fail with AccessDenied."
  value       = local.sns_topic_arn
}

output "lab_user_arn" {
  description = "Deterministically-constructed ARN of the lab IAM user the responder role is scoped to. The iam-lab-weak module's aws_iam_user MUST be created with `name` equal to the same lab_user_name value passed into this module, or the responder Lambda will be unable to act on the real lab user."
  value       = local.lab_user_arn
}
