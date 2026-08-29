{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadLabIdentityAccessKeysOnly",
      "Effect": "Allow",
      "Action": [
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed"
      ],
      "Resource": "${lab_user_arn}"
    },
    {
      "Sid": "DeactivateAccessKeyOnLabIdentityOnly",
      "Effect": "Allow",
      "Action": "iam:UpdateAccessKey",
      "Resource": "${lab_user_arn}"
    },
    {
      "Sid": "PublishContainmentNotice",
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "${sns_topic_arn}"
    },
    {
      "Sid": "WriteOwnLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:${region}:${account_id}:log-group:/aws/lambda/${responder_function_name}*"
    }
  ]
}
