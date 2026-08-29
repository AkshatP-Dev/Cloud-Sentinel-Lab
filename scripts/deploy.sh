#!/usr/bin/env bash
# CloudSentinel — deploy
#
# Two-phase apply:
#   1. The AWS Budget cost tripwire, on its own — see
#      terraform/environments/lab/main.tf's comment on
#      aws_budgets_budget.cost_tripwire for why this runs first as an
#      explicit separate step, rather than relying on Terraform's
#      dependency graph (which has no mechanism to force one resource
#      ahead of other, unrelated ones).
#   2. Everything else.
#
# Usage: ./scripts/deploy.sh
# Run from anywhere — this script locates the repo root itself. Requires:
# terraform >= 1.5, valid AWS credentials, and a terraform.tfvars file
# (copy terraform.tfvars.example to terraform.tfvars and fill it in first
# — see that file's comments).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_DIR="${REPO_ROOT}/terraform/environments/lab"

cd "$ENV_DIR"

if [[ ! -f terraform.tfvars ]]; then
  echo "ERROR: terraform.tfvars not found in ${ENV_DIR}"
  echo "Copy terraform.tfvars.example to terraform.tfvars and fill in your own values first."
  exit 1
fi

echo "== terraform init =="
terraform init

echo
echo "== terraform fmt -check =="
if ! terraform fmt -check -recursive "${REPO_ROOT}/terraform"; then
  echo "NOTE: formatting differs from 'terraform fmt' output. Not blocking deploy —"
  echo "run 'terraform fmt -recursive terraform/' from the repo root to fix, then re-run."
fi

echo
echo "== terraform validate =="
terraform validate

echo
echo "== Phase 1: applying the AWS Budget cost tripwire first =="
terraform apply -target=aws_budgets_budget.cost_tripwire

echo
echo "== Phase 1 complete. Budget tripwire is live. =="
echo "Check your email for an AWS Budgets subscription confirmation and click it now —"
echo "budget notifications will not be delivered until you do."
echo
read -r -p "Continue to Phase 2 (full deployment)? [y/N] " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
  echo "Stopped after Phase 1. Re-run this script to continue when ready."
  exit 0
fi

echo
echo "== Phase 2: applying everything else =="
terraform apply

echo
echo "== Deploy complete. Outputs: =="
terraform output

echo
echo "NEXT STEPS:"
echo "  1. Check your email for an SNS subscription confirmation and click it —"
echo "     you will not receive alerts until you do."
echo "  2. Run ./scripts/security_scan.sh to check the deployed configuration with Checkov."
echo "  3. Run ./scripts/simulate_events.sh to trigger each detection and confirm alerts arrive."
echo "  4. See TESTING.md for the full verification checklist."
