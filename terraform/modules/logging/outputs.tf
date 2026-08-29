output "trail_bucket_arn" {
  description = "ARN of the S3 bucket CloudTrail logs are written to."
  value       = aws_s3_bucket.trail.arn
}

output "trail_bucket_name" {
  description = "Name of the S3 bucket CloudTrail logs are written to."
  value       = aws_s3_bucket.trail.id
}

output "trail_arn" {
  description = "ARN of the CloudTrail trail."
  value       = aws_cloudtrail.this.arn
}

output "trail_name" {
  description = "Name of the CloudTrail trail."
  value       = aws_cloudtrail.this.name
}
