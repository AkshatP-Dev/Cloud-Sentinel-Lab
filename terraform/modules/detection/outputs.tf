output "sns_topic_arn" {
  description = "ARN of the alerts SNS topic. Must equal the deterministic ARN the iam-hardened module already computed — if it doesn't, sns_topic_name diverged between the two modules."
  value       = aws_sns_topic.alerts.arn
}

output "detector_function_name" {
  description = "Name of the deployed detector Lambda function."
  value       = aws_lambda_function.detector.function_name
}

output "detector_function_arn" {
  description = "ARN of the deployed detector Lambda function."
  value       = aws_lambda_function.detector.arn
}

output "responder_function_name" {
  description = "Name of the deployed responder Lambda function."
  value       = aws_lambda_function.responder.function_name
}

output "responder_function_arn" {
  description = "ARN of the deployed responder Lambda function. Must equal the deterministic ARN the iam-hardened module already computed — if it doesn't, responder_function_name diverged between the two modules."
  value       = aws_lambda_function.responder.arn
}

output "root_usage_rule_arn" {
  description = "ARN of the D-01 root-usage EventBridge rule."
  value       = aws_cloudwatch_event_rule.root_usage.arn
}

output "scoped_events_rule_arn" {
  description = "ARN of the D-02/D-03/D-04/D-05 scoped-events EventBridge rule."
  value       = aws_cloudwatch_event_rule.scoped_events.arn
}

output "scoped_event_names" {
  description = "The exact eventName list the scoped-events rule matches on — useful for tests/simulate_events.sh to confirm the simulated event names are actually covered."
  value       = local.scoped_event_names
}
