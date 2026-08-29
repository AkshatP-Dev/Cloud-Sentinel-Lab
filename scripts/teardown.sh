#!/usr/bin/env bash
# CloudSentinel — teardown
#
# Destroys everything Terraform created, then VERIFIES nothing tagged
# project=cloudsentinel is still standing. Terraform reporting success is
# not, by itself, proof the account is clean — a resource created outside
# Terraform, or a partial failure mid-destroy, would not necessarily show
# up as an error in `terraform destroy`'s own output.
#
# Usage: ./scripts/teardown.sh
# Requires: terraform, AWS CLI, valid AWS credentials.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_DIR="${REPO_ROOT}/terraform/environments/lab"

cd "$ENV_DIR"

echo "This will destroy every CloudSentinel resource Terraform created in this AWS account/region."
read -r -p "Type 'destroy' to confirm: " confirm
if [[ "$confirm" != "destroy" ]]; then
  echo "Aborted. Nothing was changed."
  exit 0
fi

# Read the region BEFORE destroying — once state is gone, `terraform
# output` can't tell us anything.
REGION="$(terraform output -raw aws_region 2>/dev/null || true)"

echo
echo "== terraform destroy =="
terraform destroy

if [[ -z "$REGION" ]]; then
  REGION="$(aws configure get region || echo "us-east-1")"
  echo "(Could not read aws_region from Terraform output after destroy — falling back to the"
  echo " AWS CLI's configured default region, ${REGION}, for the verification check below.)"
fi

echo
echo "== Verifying no CloudSentinel-tagged resources remain (region: ${REGION}) =="

REMAINING="$(aws resourcegroupstaggingapi get-resources \
  --region "$REGION" \
  --tag-filters Key=project,Values=cloudsentinel \
  --query 'ResourceTagMappingList[].ResourceARN' \
  --output text || true)"

if [[ -z "$REMAINING" ]]; then
  echo "PASS — no resources tagged project=cloudsentinel found via Resource Groups Tagging API."
else
  echo "FOUND REMAINING TAGGED RESOURCES — investigate before assuming teardown is complete:"
  echo "$REMAINING" | tr '\t' '\n'
fi

echo
echo "CAVEATS on the check above — read before trusting a PASS:"
echo "  - The Resource Groups Tagging API does not index every AWS resource type reliably in"
echo "    every region (IAM resources in particular sometimes lag or are excluded). Manually"
echo "    check the IAM console for any lingering cloudsentinel-* users, roles, or policies."
echo "  - Manually check the S3 console for the trail bucket — it may need --force-destroy or a"
echo "    manual empty if it somehow still held objects the lifecycle rule hadn't yet expired."
echo "  - The AWS Budget (cloudsentinel-monthly-tripwire) IS included in this destroy since it's"
echo "    a plain Terraform-managed resource in the same state — confirm it's gone under Billing"
echo "    and Cost Management > Budgets if you want to double check."
echo "  - CloudWatch Log groups for both Lambdas are destroyed with everything else; if you want"
echo "    to keep any logs for your evidence/ folder, copy them out BEFORE running this script."
