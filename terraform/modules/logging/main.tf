# CloudSentinel — logging module
#
# One CloudTrail trail (multi-region, management events, log file validation
# enabled) delivering to one locked-down S3 bucket. This is the single
# authoritative audit source every detection in the detection module reads
# from — see ARCHITECTURE.md and DETECTIONS.md.
#
# The trail's ARN is constructed deterministically (region/account/name are
# all known before the resource exists) rather than referenced from the
# aws_cloudtrail resource, so the bucket policy can name it without a
# dependency cycle: the bucket policy must exist and grant CloudTrail write
# access BEFORE the trail can be created successfully.

locals {
  trail_arn = "arn:aws:cloudtrail:${var.aws_region}:${var.account_id}:trail/${var.trail_name}"

  common_tags = {
    project = "cloudsentinel"
  }
}

resource "aws_s3_bucket" "trail" {
  #checkov:skip=CKV2_AWS_62:This project deliberately routes detection through EventBridge's native CloudTrail integration (see terraform/modules/detection/main.tf), not S3 event notifications on this bucket — a different, already-documented notification mechanism, not a gap. S3 event notifications would fire on "a new log object appeared," which isn't the signal this project's detections evaluate.
  #checkov:skip=CKV_AWS_18:Access logging would require a SECOND bucket to receive access logs about the trail bucket itself — cost/complexity disproportionate to a personal lab. The trail already captures management-event API calls made against this bucket (PutBucketPolicy, PutBucketAcl, etc. — see detections/D-02-logging-tamper.md); what's not captured is object-level data-plane access (GetObject/PutObject), which this project's threat model does not need visibility into.
  #checkov:skip=CKV_AWS_144:Cross-region replication is a disaster-recovery control, not a security one, and adds a second bucket's worth of ongoing cost — disproportionate to a $5/month personal lab budget. See COST.md.
  #checkov:skip=CKV_AWS_145:SSE-S3 (AES-256, set below) already encrypts all data at rest. A customer-managed KMS key costs ~$1/month for no meaningful benefit to a personal lab's non-regulated log data — the same trade-off already called out in this file's own SSE comment below and in COST.md.
  bucket = var.bucket_name

  tags = merge(local.common_tags, {
    purpose = "cloudtrail-log-storage"
  })
}

# All four public-access-block settings on, unconditionally — this bucket
# must never become publicly readable, full stop. D-05 detects any attempt
# to change this after the fact.
resource "aws_s3_bucket_public_access_block" "trail" {
  bucket = aws_s3_bucket.trail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id

  versioning_configuration {
    status = "Enabled"
  }
}

# SSE-S3 (AES-256), not SSE-KMS — encrypted at rest at no extra cost.
# See COST.md for the SSE-KMS trade-off (~$1/month/key) this project
# deliberately avoids for a lab with no cost-recovery mechanism.
resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# Bounds storage cost automatically — a lab that runs for a year doesn't
# quietly accumulate a year of logs. See COST.md.
resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    id     = "expire-cloudtrail-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = var.retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.retention_days
    }

    # Bounds storage cost from any abandoned multipart upload (CloudTrail
    # itself doesn't use multipart uploads for its own log delivery, but
    # nothing prevents some other process from starting one against this
    # bucket and never completing it) — a small, free hardening Checkov
    # flagged (CKV_AWS_300) that costs nothing to add.
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = templatefile("${path.module}/../../policies/cloudtrail-bucket-policy.json.tpl", {
    bucket_arn = aws_s3_bucket.trail.arn
    trail_arn  = local.trail_arn
    account_id = var.account_id
  })

  # The public access block must be in place before the bucket policy is
  # evaluated as "final" — ordering matters less for correctness here than
  # for making the intent explicit: access is locked down before it is
  # opened selectively to the CloudTrail service principal.
  depends_on = [aws_s3_bucket_public_access_block.trail]
}

resource "aws_cloudtrail" "this" {
  #checkov:skip=CKV_AWS_252:CloudTrail's native SNS notification (one message per delivered log file) is a legacy/alternative pattern this project deliberately does not use — detection is driven entirely through EventBridge's native CloudTrail integration instead (see terraform/modules/detection/main.tf), which was chosen during this project's design phase specifically because it's free for same-account delivery, unlike the CloudWatch Logs subscription alternative. Enabling this too would be redundant, not a fix.
  #checkov:skip=CKV_AWS_35:SSE-S3 (AES-256) on the destination bucket already encrypts the log objects at rest. A customer-managed KMS key for the trail itself costs ~$1/month for no meaningful benefit to a personal lab's non-regulated data — see the identical trade-off noted on aws_s3_bucket.trail above and in COST.md.
  #checkov:skip=CKV2_AWS_10:Deliberately not integrated with CloudWatch Logs — that delivery path costs $0.50/GB at this project's low-volume scale (AWS's ingestion pricing is tiered; verified during this project's design phase) and EventBridge's native CloudTrail integration is free for the same-account use case this project needs. See ARCHITECTURE.md/COST.md for the original cost comparison this decision was based on.
  name           = var.trail_name
  s3_bucket_name = aws_s3_bucket.trail.id

  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true

  tags = local.common_tags

  # The bucket policy granting cloudtrail.amazonaws.com write access must
  # exist first, or trail creation fails validation against the bucket.
  depends_on = [aws_s3_bucket_policy.trail]
}
