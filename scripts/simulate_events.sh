#!/usr/bin/env bash
# CloudSentinel — simulate detection events
#
# Safely triggers D-02 through D-05 against already-deployed CloudSentinel
# infrastructure, using whatever AWS CLI credentials/profile you already
# have active (your own operator identity — this does NOT assume the lab
# user's role or use its credentials). D-01 (root usage) is deliberately
# NOT included here — see detections/D-01-root-usage.md for why scripting
# an automated root-credential action would be irresponsible.
#
# Every simulation either (a) re-asserts a configuration value that is
# ALREADY safe/already in place — which still generates a real, matching
# CloudTrail event, since CloudTrail logs the API *call*, not just a
# resulting state change — or (b) creates a throwaway, clearly-lab-scoped
# resource and deletes it immediately after. Nothing here ever actually
# weakens security, even briefly. See each detections/D-0X-*.md for the
# reasoning specific to that simulation.
#
# This script does NOT assert that alerts arrived — EventBridge/Lambda
# propagation is typically near-real-time but this project does not
# fabricate timing guarantees. It tells you exactly what to check after
# each step.
#
# Usage:
#   ./scripts/simulate_events.sh d02
#   ./scripts/simulate_events.sh d03
#   ./scripts/simulate_events.sh d04
#   ./scripts/simulate_events.sh d05
#   ./scripts/simulate_events.sh all
#
# Requires: AWS CLI configured with credentials that have real (not
# lab-boundary-constrained) permissions — your own operator identity.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_DIR="${REPO_ROOT}/terraform/environments/lab"

cd "$ENV_DIR"

TRAIL_BUCKET="$(terraform output -raw trail_bucket_name)"
LAB_USER="$(terraform output -raw lab_user_name)"
REGION="$(terraform output -raw aws_region)"
DETECTOR_FN="$(terraform output -raw detector_function_name)"

echo "Using:"
echo "  trail bucket:     ${TRAIL_BUCKET}"
echo "  lab user:         ${LAB_USER}"
echo "  region:           ${REGION}"
echo "  detector function: ${DETECTOR_FN}"
echo

check_logs_hint() {
  echo "  -> To watch the detector's own reasoning as it happens:"
  echo "     aws logs tail /aws/lambda/${DETECTOR_FN} --region ${REGION} --since 2m --follow"
  echo "  -> Alert should also arrive at the email you confirmed on the SNS subscription."
}

sim_d02() {
  echo "== D-02: logging tamper (re-asserting the trail bucket's existing versioning state) =="
  aws s3api put-bucket-versioning \
    --region "$REGION" \
    --bucket "$TRAIL_BUCKET" \
    --versioning-configuration Status=Enabled
  echo "Called PutBucketVersioning with Status=Enabled — the value it already had."
  echo "This is a genuine CloudTrail event; nothing about the bucket's actual protection changed."
  check_logs_hint
}

sim_d03() {
  echo "== D-03: privilege escalation (throwaway lab-scoped IAM user + policy attach) =="
  local sim_user="cloudsentinel-lab-sim-user"

  aws iam create-user \
    --user-name "$sim_user" \
    --tags Key=project,Value=cloudsentinel
  echo "Created ${sim_user} (CreateUser)."

  aws iam attach-user-policy \
    --user-name "$sim_user" \
    --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
  echo "Attached AWS-managed ReadOnlyAccess to ${sim_user} (AttachUserPolicy)."

  echo "Cleaning up immediately (detach + delete) so nothing standing is left behind..."
  aws iam detach-user-policy --user-name "$sim_user" --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
  aws iam delete-user --user-name "$sim_user"
  echo "Deleted ${sim_user}."
  check_logs_hint
}

sim_d04() {
  echo "== D-04: access key created (on the lab user — this ALSO triggers the automated responder) =="
  aws iam create-access-key --user-name "$LAB_USER" --region "$REGION" > /tmp/cloudsentinel-sim-key.json
  echo "Created a new access key on ${LAB_USER}."
  echo "(Key material was written to /tmp/cloudsentinel-sim-key.json — delete that file once you're"
  echo " done; it's a real, if now-hopefully-deactivated, credential.)"
  echo
  echo "This should trigger the responder Lambda automatically. Give it a minute, then check:"
  echo "  aws iam list-access-keys --user-name ${LAB_USER} --region ${REGION}"
  echo "  (expect Status: Inactive on the key you just created, if the responder ran successfully)"
  echo "  aws logs tail /aws/lambda/$(terraform output -raw responder_function_name) --region ${REGION} --since 2m"
  check_logs_hint
}

sim_d05() {
  echo "== D-05: bucket exposure (throwaway bucket, re-asserting a private ACL) =="
  local sim_bucket="cloudsentinel-lab-sim-$(date +%s)"
  local create_args=(--bucket "$sim_bucket" --region "$REGION")
  if [[ "$REGION" != "us-east-1" ]]; then
    create_args+=(--create-bucket-configuration "LocationConstraint=${REGION}")
  fi

  aws s3api create-bucket "${create_args[@]}"
  echo "Created throwaway bucket ${sim_bucket}."

  aws s3api put-bucket-acl --bucket "$sim_bucket" --region "$REGION" --acl private
  echo "Called PutBucketAcl with --acl private — the value a new bucket already has."
  echo "This is a genuine CloudTrail event; the bucket was never actually made public."

  echo "Cleaning up immediately..."
  aws s3api delete-bucket --bucket "$sim_bucket" --region "$REGION"
  echo "Deleted ${sim_bucket}."
  check_logs_hint
}

case "${1:-}" in
  d02) sim_d02 ;;
  d03) sim_d03 ;;
  d04) sim_d04 ;;
  d05) sim_d05 ;;
  all)
    sim_d02; echo; sim_d03; echo; sim_d04; echo; sim_d05
    ;;
  *)
    echo "Usage: $0 {d02|d03|d04|d05|all}"
    echo "(D-01 is intentionally not scriptable — see detections/D-01-root-usage.md)"
    exit 1
    ;;
esac
