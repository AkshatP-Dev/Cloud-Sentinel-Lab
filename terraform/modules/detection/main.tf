# CloudSentinel — detection module
#
# Wires together the whole detect-and-respond pipeline:
#
#   CloudTrail (logging module)
#     -> EventBridge default bus (native CloudTrail integration — no
#        CloudWatch Logs subscription, no per-GB delivery cost; see COST.md)
#     -> two rules, both targeting the SAME detector Lambda:
#          1. root-usage   — any AWS API call or console sign-in performed
#                             by the root user, regardless of service
#          2. scoped-events — a fixed list of specific eventNames across
#                             IAM/S3/STS/CloudTrail that matter to D-02
#                             through D-05 (see detections/*.md for the
#                             per-detection rationale)
#     -> detector Lambda (lambda/detectors/dispatcher) evaluates the event
#        against all five rule functions, publishes any findings to SNS,
#        and — for a confirmed D-04 (access key created on the lab
#        identity) finding specifically — directly invokes the responder
#        Lambda
#     -> responder Lambda (lambda/responders/quarantine) deactivates the
#        access key and publishes its own containment notice to the same
#        SNS topic
#
# Why one merged "scoped-events" rule instead of one rule per detection:
# EventBridge content-based patterns AND together every top-level key you
# specify in one pattern object — there is no way to express "eventName is
# one of set A OR userIdentity.type is Root" inside a single rule, so root
# usage (which must match on userIdentity.type, not on eventName, since
# root can call literally anything) genuinely needs its own rule. The other
# four detections all match on eventName within the same handful of AWS
# services, so folding them into one rule keeps the infrastructure small;
# the real per-detection logic still lives in Python (rules/*.py), which is
# both easier to unit test and easier to extend than adding more and more
# EventBridge rules would be.
#
# Why the dispatcher invokes the responder directly (a scoped
# lambda:InvokeFunction, not a third EventBridge rule): it's one tightly
# coupled detect -> respond pair, the dispatcher's IAM policy already
# limits the call to exactly this one function ARN (see
# terraform/policies/lambda-detector-exec.json.tpl), and it keeps the
# response path simple enough to unit test directly (see
# tests/unit/test_detection_rules.py) without inventing a custom
# EventBridge event schema for something this narrow.

locals {
  common_tags = {
    project = "cloudsentinel"
  }

  # Event names covering D-02 (logging tamper), D-03 (privilege escalation),
  # D-04 (access key created), and D-05 (bucket exposure). Root usage (D-01)
  # is handled by the separate rule below since it matches on
  # userIdentity.type, not eventName. See detections/*.md for which names
  # belong to which detection — several are deliberately shared with the
  # Deny statements in terraform/policies/lab-weak-boundary.json.tpl, so
  # that what the boundary prevents by policy, the detector independently
  # watches for by event: even a misconfigured or bypassed boundary is
  # still visible here.
  scoped_event_names = [
    # D-02 logging_tamper
    "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "RemoveTags",
    "PutBucketPolicy", "DeleteBucketPolicy",
    "PutBucketPublicAccessBlock", "PutPublicAccessBlock",
    "DeleteBucketPublicAccessBlock", "DeletePublicAccessBlock",
    "PutBucketAcl", "PutBucketVersioning", "DeleteBucket", "PutLifecycleConfiguration",
    # D-03 privilege_escalation
    "CreateUser", "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
    "CreatePolicyVersion", "PassRole", "AssumeRole",
    "PutUserPermissionsBoundary", "DeleteUserPermissionsBoundary",
    "PutRolePermissionsBoundary", "DeleteRolePermissionsBoundary",
    # D-04 access_key_created
    "CreateAccessKey", "UpdateAccessKey",
  ]
}

# ---------------------------------------------------------------------------
# Lambda source packaging
# ---------------------------------------------------------------------------
# Both functions are pure Python + boto3 (already present in the Lambda
# managed runtime) with no third-party dependencies, so a plain directory
# zip is sufficient — no pip install / Docker build step is needed. If a
# real dependency is ever added, replace these with a null_resource that
# runs `pip install -t build/ -r requirements.txt` before zipping.

data "archive_file" "detector" {
  type        = "zip"
  source_dir  = "${path.module}/../../../lambda/detectors/dispatcher"
  output_path = "${path.module}/build/detector.zip"
  excludes    = ["__pycache__", "*.pyc", "tests"]
}

data "archive_file" "responder" {
  type        = "zip"
  source_dir  = "${path.module}/../../../lambda/responders/quarantine"
  output_path = "${path.module}/build/responder.zip"
  excludes    = ["__pycache__", "*.pyc", "tests"]
}

# ---------------------------------------------------------------------------
# SNS — the single alert topic both Lambdas publish to
# ---------------------------------------------------------------------------

resource "aws_sns_topic" "alerts" {
  name = var.sns_topic_name

  # AWS-managed key — free, no extra infrastructure, no key policy to
  # maintain. A customer-managed CMK would cost ~$1/month for no
  # meaningful benefit here: these messages are finding summaries and
  # containment notices, not secrets. See SECURITY.md's Checkov section
  # for the same reasoning applied to CloudWatch Logs and the CloudTrail
  # bucket, which make the identical cost/benefit call.
  kms_master_key_id = "alias/aws/sns"

  tags = local.common_tags
}

resource "aws_sns_topic_subscription" "alert_email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ---------------------------------------------------------------------------
# Detector Lambda ("dispatcher")
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "detector" {
  #checkov:skip=CKV_AWS_158:AWS-owned encryption (CloudWatch Logs' default) is sufficient for execution/detection logs containing no secrets or PII — a customer-managed CMK costs ~$1/month/key for no meaningful benefit at this project's scale. See SECURITY.md.
  #checkov:skip=CKV_AWS_338:14-day retention (var.log_retention_days) is a deliberate cost control, not an oversight — see COST.md. This is a personal lab with no compliance requirement to retain execution logs for a year.
  name              = "/aws/lambda/${var.detector_function_name}"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

resource "aws_lambda_function" "detector" {
  #checkov:skip=CKV_AWS_116:No DLQ configured — a reasonable v2 enhancement (see SECURITY.md's Known Limitations), deliberately out of scope for this project's size. EventBridge itself retries failed async Lambda invocations before giving up.
  #checkov:skip=CKV_AWS_117:Deliberately NOT in a VPC — this function only calls AWS service APIs (SNS, IAM, Lambda) and needs neither internet egress nor access to any VPC-private resource. VPC placement would require NAT Gateway (~$32/month, against this project's cost philosophy) or VPC endpoints for no security benefit against this threat model. See SECURITY.md.
  #checkov:skip=CKV_AWS_272:Code-signing (AWS Signer) is a software-supply-chain control disproportionate to a personal portfolio lab — noted as a future enhancement in SECURITY.md, not implemented here.
  #checkov:skip=CKV_AWS_173:Environment variables here (SNS_TOPIC_ARN, RESPONDER_FUNCTION_NAME, LAB_USER_ARN) are resource identifiers, not secrets — confirmed by code review. Lambda already encrypts them at rest with an AWS-owned key by default; a customer CMK adds cost/complexity for no benefit to non-sensitive values.
  #checkov:skip=CKV_AWS_50:X-Ray tracing not enabled — a reasonable observability enhancement, deliberately deferred (see SECURITY.md's Known Limitations) to keep this project's scope focused on detection/response rather than broader AWS feature coverage.
  function_name = var.detector_function_name
  role          = var.lambda_detector_exec_role_arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.12"
  timeout       = var.detector_timeout
  memory_size   = var.lambda_memory_size

  # Caps how many concurrent invocations this function can ever have —
  # a cheap, real bound on both blast radius (a CloudTrail event storm
  # can't spawn unlimited concurrent executions) and cost (concurrency is
  # the multiplier on Lambda's per-invocation price). 5 is generous for a
  # personal lab's event volume; raise it if simulate_events.sh ever
  # starts seeing throttling in its own logs.
  reserved_concurrent_executions = var.reserved_concurrency

  filename         = data.archive_file.detector.output_path
  source_code_hash = data.archive_file.detector.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN           = aws_sns_topic.alerts.arn
      RESPONDER_FUNCTION_NAME = var.responder_function_name
      # Required for handler.py's _is_lab_user() gate: without this, the
      # detector can never recognize a D-04 finding as belonging to the
      # lab user, so it would never invoke the responder at all — the
      # automated-response path would be silently dead despite every unit
      # test passing (the unit tests set this module attribute directly
      # via monkeypatch, which exercises the gating LOGIC correctly but
      # can't catch a missing wire-up between this Terraform and the
      # Lambda's real runtime environment). tests/offline/test_lambda_env_wiring.py
      # is a regression guard specifically for this class of bug.
      LAB_USER_ARN = var.lab_user_arn
    }
  }

  tags = local.common_tags

  depends_on = [aws_cloudwatch_log_group.detector]
}

# ---------------------------------------------------------------------------
# Responder Lambda ("quarantine")
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "responder" {
  #checkov:skip=CKV_AWS_158:Same reasoning as aws_cloudwatch_log_group.detector above.
  #checkov:skip=CKV_AWS_338:Same reasoning as aws_cloudwatch_log_group.detector above.
  name              = "/aws/lambda/${var.responder_function_name}"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

resource "aws_lambda_function" "responder" {
  #checkov:skip=CKV_AWS_116:Same reasoning as aws_lambda_function.detector above.
  #checkov:skip=CKV_AWS_117:Same reasoning as aws_lambda_function.detector above.
  #checkov:skip=CKV_AWS_272:Same reasoning as aws_lambda_function.detector above.
  #checkov:skip=CKV_AWS_173:Environment variables here (SNS_TOPIC_ARN, LAB_USER_ARN) are resource identifiers, not secrets — confirmed by code review. Same reasoning as aws_lambda_function.detector above.
  #checkov:skip=CKV_AWS_50:Same reasoning as aws_lambda_function.detector above.
  function_name = var.responder_function_name
  role          = var.lambda_responder_exec_role_arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.12"
  timeout       = var.responder_timeout
  memory_size   = var.lambda_memory_size

  # See the identical comment on aws_lambda_function.detector above.
  reserved_concurrent_executions = var.reserved_concurrency

  filename         = data.archive_file.responder.output_path
  source_code_hash = data.archive_file.responder.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
      LAB_USER_ARN  = var.lab_user_arn
    }
  }

  tags = local.common_tags

  depends_on = [aws_cloudwatch_log_group.responder]
}

# ---------------------------------------------------------------------------
# EventBridge — rule 1: root usage (any service, any action)
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "root_usage" {
  name        = "cloudsentinel-root-usage"
  description = "D-01: any AWS API call or console sign-in performed as the root user, in any service. Matches on userIdentity.type, not eventName, since root usage is inherently unscoped."

  event_pattern = jsonencode({
    detail-type = [
      "AWS API Call via CloudTrail",
      "AWS Console Sign In via CloudTrail",
    ]
    detail = {
      userIdentity = {
        type = ["Root"]
      }
    }
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "root_usage_to_detector" {
  rule      = aws_cloudwatch_event_rule.root_usage.name
  target_id = "cloudsentinel-detector"
  arn       = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "allow_eventbridge_root_usage" {
  statement_id  = "AllowEventBridgeRootUsage"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.root_usage.arn
}

# ---------------------------------------------------------------------------
# EventBridge — rule 2: scoped events (D-02, D-03, D-04, D-05)
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "scoped_events" {
  name        = "cloudsentinel-scoped-events"
  description = "D-02/D-03/D-04/D-05: logging tamper, privilege escalation, access key creation, and bucket exposure — matched by eventName across IAM/S3/STS/CloudTrail."

  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail"]
    source      = ["aws.iam", "aws.s3", "aws.sts", "aws.cloudtrail"]
    detail = {
      eventName = local.scoped_event_names
    }
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "scoped_events_to_detector" {
  rule      = aws_cloudwatch_event_rule.scoped_events.name
  target_id = "cloudsentinel-detector"
  arn       = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "allow_eventbridge_scoped_events" {
  statement_id  = "AllowEventBridgeScopedEvents"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scoped_events.arn
}
