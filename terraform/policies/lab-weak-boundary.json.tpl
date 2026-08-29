{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowManagingOwnLabScopedIamResources",
      "Effect": "Allow",
      "Action": [
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:TagUser",
        "iam:UntagUser",
        "iam:CreatePolicy",
        "iam:DeletePolicy",
        "iam:CreatePolicyVersion",
        "iam:DeletePolicyVersion",
        "iam:AttachUserPolicy",
        "iam:DetachUserPolicy",
        "iam:PutUserPolicy",
        "iam:DeleteUserPolicy",
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey",
        "iam:UpdateAccessKey"
      ],
      "Resource": [
        "arn:aws:iam::${account_id}:user/cloudsentinel-lab-*",
        "arn:aws:iam::${account_id}:policy/cloudsentinel-lab-*"
      ],
      "Condition": {
        "StringEqualsIfExists": {
          "aws:RequestTag/project": "cloudsentinel"
        }
      }
    },
    {
      "Sid": "AllowBroadReadOnlyForDemonstration",
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "cloudtrail:LookupEvents",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyEscapingTheBoundaryItself",
      "Effect": "Deny",
      "Action": [
        "iam:DeleteUserPermissionsBoundary",
        "iam:PutUserPermissionsBoundary",
        "iam:DeleteRolePermissionsBoundary",
        "iam:PutRolePermissionsBoundary"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyPrivilegeEscalationPrimitives",
      "Effect": "Deny",
      "Action": [
        "iam:PassRole",
        "sts:AssumeRole",
        "sts:AssumeRoleWithSAML",
        "sts:AssumeRoleWithWebIdentity"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyTouchingAuditLogging",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail",
        "cloudtrail:PutEventSelectors",
        "cloudtrail:RemoveTags"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyTouchingTrailBucket",
      "Effect": "Deny",
      "Action": [
        "s3:PutBucketPolicy",
        "s3:DeleteBucketPolicy",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutPublicAccessBlock",
        "s3:DeleteBucketPublicAccessBlock",
        "s3:DeletePublicAccessBlock",
        "s3:PutBucketAcl",
        "s3:PutBucketVersioning",
        "s3:DeleteBucket",
        "s3:PutLifecycleConfiguration"
      ],
      "Resource": [
        "${trail_bucket_arn}",
        "${trail_bucket_arn}/*"
      ]
    },
    {
      "Sid": "DenyOutsideApprovedRegion",
      "Effect": "Deny",
      "NotAction": [
        "iam:*",
        "sts:GetCallerIdentity",
        "cloudtrail:LookupEvents",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": "${aws_region}"
        }
      }
    },
    {
      "Sid": "DenyBillingAndOrgActions",
      "Effect": "Deny",
      "Action": [
        "organizations:*",
        "account:*",
        "aws-portal:*",
        "budgets:ModifyBudget",
        "budgets:DeleteBudget"
      ],
      "Resource": "*"
    }
  ]
}
