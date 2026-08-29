variable "account_id" {
  description = "AWS account ID."
  type        = string
}

variable "aws_region" {
  description = "Region to deploy the Lambda functions, EventBridge rules, and SNS topic into."
  type        = string
}

variable "lambda_detector_exec_role_arn" {
  description = "ARN of the detector Lambda's execution role, from the iam-hardened module."
  type        = string
}

variable "lambda_responder_exec_role_arn" {
  description = "ARN of the responder Lambda's execution role, from the iam-hardened module."
  type        = string
}

variable "detector_function_name" {
  description = "Name of the detector Lambda function. MUST match the detector_function_name passed into the iam-hardened module — that module's exec-role policy grants log-write access scoped to exactly this name, computed before this module ever creates the function."
  type        = string
  default     = "cloudsentinel-detector"
}

variable "responder_function_name" {
  description = "Name of the responder Lambda function. MUST match the responder_function_name passed into the iam-hardened module, for the same reason, and is also the name the detector's IAM policy grants lambda:InvokeFunction on."
  type        = string
  default     = "cloudsentinel-responder"
}

variable "sns_topic_name" {
  description = "Name of the SNS topic both Lambdas publish to. MUST match the sns_topic_name passed into the iam-hardened module: the aws_sns_topic created in this module has to resolve to the exact ARN the exec-role policies already grant sns:Publish on, or every Publish call fails with AccessDenied."
  type        = string
  default     = "cloudsentinel-alerts"
}

variable "alert_email" {
  description = "Email address to subscribe to the alerts SNS topic. AWS emails a confirmation link after `terraform apply` that must be clicked before alerts actually arrive — see the deployment checklist in the handoff docs."
  type        = string
}

variable "lab_user_arn" {
  description = "ARN of the intentionally-weak lab IAM user, from the iam-lab-weak module's real output (no deterministic reconstruction needed here — this module doesn't feed anything back into iam-lab-weak, so there's no cycle to avoid). Passed as an environment variable to BOTH Lambdas: the detector uses it to recognize a D-04 finding as belonging to the lab user before invoking the responder (handler.py's _is_lab_user), and the responder hard-codes a check against this exact ARN in its own code in addition to its IAM policy scoping (lambda/responders/quarantine/handler.py). Omitting this from either function's environment silently breaks the automated-response path without causing any Terraform error — see IAM_DESIGN.md and tests/offline/test_lambda_env_wiring.py."
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for both Lambda function log groups. Bounds log storage cost — see COST.md."
  type        = number
  default     = 14
}

variable "detector_timeout" {
  description = "Detector Lambda timeout, in seconds."
  type        = number
  default     = 30
}

variable "responder_timeout" {
  description = "Responder Lambda timeout, in seconds."
  type        = number
  default     = 30
}

variable "lambda_memory_size" {
  description = "Memory (MB) allocated to both Lambda functions. 128MB is generous for lightweight JSON event processing — no heavy compute happens here."
  type        = number
  default     = 128
}

variable "reserved_concurrency" {
  description = "Maximum concurrent executions for each Lambda function. Bounds both blast radius (an event storm can't spawn unlimited concurrent invocations) and cost (concurrency is the multiplier on Lambda's per-invocation price). 5 is generous for a personal lab's event volume."
  type        = number
  default     = 5
}
