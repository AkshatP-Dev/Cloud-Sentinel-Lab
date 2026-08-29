variable "account_id" {
  description = "AWS account ID CloudSentinel is deployed into."
  type        = string
}

variable "aws_region" {
  description = "Region CloudSentinel is deployed into."
  type        = string
}

variable "operator_principal_arn" {
  description = "IAM user or role ARN allowed to assume the investigator role (with MFA present). This must be YOUR OWN IAM identity's ARN — not a placeholder — or nobody will be able to assume the role."
  type        = string
}

variable "trail_bucket_arn" {
  description = "ARN of the CloudTrail log bucket, from the logging module. The investigator role is granted read-only access to exactly this bucket."
  type        = string
}

variable "sns_topic_name" {
  description = "Name of the SNS topic detector/responder Lambdas publish findings to. This module builds a deterministic topic ARN from this name (arn:aws:sns:<region>:<account_id>:<name>) so the exec-role policies can reference sns:Publish before the topic exists — the detection module creates the actual aws_sns_topic and MUST use this same name as its `name` argument (not name_prefix), or the two will diverge."
  type        = string
  default     = "cloudsentinel-alerts"
}

variable "detector_function_name" {
  description = "Name of the detector Lambda function. This module builds a deterministic CloudWatch Logs log-group ARN from this name so the detector exec role's log-write permission can be scoped to exactly that function's logs before the function exists. The detection module MUST create the Lambda function with this same name."
  type        = string
  default     = "cloudsentinel-detector"
}

variable "responder_function_name" {
  description = "Name of the responder Lambda function. Same deterministic-ARN reasoning as detector_function_name."
  type        = string
  default     = "cloudsentinel-responder"
}

variable "lab_user_name" {
  description = "Name of the intentionally-weak lab IAM user (created in the iam-lab-weak module) that the responder Lambda is allowed to act on. This module builds a deterministic user ARN from this name so the responder's IAM permissions can be scoped to exactly that one identity — never Resource: \"*\" — before the user exists. The iam-lab-weak module MUST create its aws_iam_user with this same name."
  type        = string
  default     = "cloudsentinel-lab-user"
}
