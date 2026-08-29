variable "account_id" {
  description = "AWS account ID."
  type        = string
}

variable "aws_region" {
  description = "Approved region for the region-lock Deny statement in the permission boundary."
  type        = string
}

variable "lab_user_name" {
  description = "Name of the intentionally-weak lab IAM user. MUST match the lab_user_name passed into the iam-hardened module — that module builds a deterministic ARN from this same name to scope the responder Lambda's permissions. Define this once in the calling environment's locals and pass the identical value to both modules."
  type        = string
  default     = "cloudsentinel-lab-user"
}

variable "trail_bucket_arn" {
  description = "ARN of the CloudTrail log bucket, from the logging module. The permission boundary denies tampering with this bucket specifically."
  type        = string
}
