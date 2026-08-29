variable "account_id" {
  description = "AWS account ID CloudSentinel is deployed into. Used to build a deterministic trail ARN and to scope the bucket policy."
  type        = string
}

variable "aws_region" {
  description = "Region the trail and bucket are created in."
  type        = string
}

variable "trail_name" {
  description = "Name of the CloudTrail trail."
  type        = string
  default     = "cloudsentinel-trail"
}

variable "bucket_name" {
  description = "Globally-unique S3 bucket name for CloudTrail log storage. Compute this in the calling environment (e.g. suffix with the account ID) — S3 bucket names collide across all of AWS, not just your account."
  type        = string
}

variable "retention_days" {
  description = "Days before a CloudTrail log object expires via S3 lifecycle. Bounds storage cost — see COST.md."
  type        = number
  default     = 90
}
