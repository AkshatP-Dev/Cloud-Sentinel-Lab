{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOperatorAssumeWithMFA",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${operator_principal_arn}"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}
