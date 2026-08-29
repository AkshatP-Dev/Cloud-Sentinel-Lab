{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublishFindings",
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "${sns_topic_arn}"
    },
    {
      "Sid": "InspectAttachedIamPolicyContent",
      "Effect": "Allow",
      "Action": [
        "iam:GetPolicyVersion",
        "iam:GetPolicy",
        "iam:GetUserPolicy",
        "iam:GetRolePolicy",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies"
      ],
      "Resource": "*"
    },
    {
      "Sid": "WriteOwnLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:${region}:${account_id}:log-group:/aws/lambda/${detector_function_name}*"
    },
    {
      "Sid": "InvokeResponderOnConfirmedFinding",
      "Effect": "Allow",
      "Action": "lambda:InvokeFunction",
      "Resource": "${responder_function_arn}"
    }
  ]
}
