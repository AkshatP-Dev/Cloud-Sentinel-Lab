#!/usr/bin/env bash
# CloudSentinel — security scan
#
# Runs Checkov (static analysis — no AWS credentials or `terraform init`
# needed) against the full Terraform tree, and terraform fmt/validate if
# the terraform binary is available locally. Saves results into
# evidence/checkov/ for the record — see that folder's own README.md.
#
# Usage: ./scripts/security_scan.sh

set -uo pipefail  # deliberately NOT -e: checkov exits non-zero when it
                   # finds failed checks, which is expected, informative
                   # output, not a script failure.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
EVIDENCE_DIR="${REPO_ROOT}/evidence/checkov"

mkdir -p "$EVIDENCE_DIR"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_JSON="${EVIDENCE_DIR}/checkov-${TIMESTAMP}.json"
OUT_TEXT="${EVIDENCE_DIR}/checkov-${TIMESTAMP}.txt"

if ! command -v checkov >/dev/null 2>&1; then
  echo "checkov not found. Install with: pip install checkov --break-system-packages"
  exit 1
fi

echo "== checkov (full Terraform tree) =="
checkov -d "${REPO_ROOT}/terraform" --compact --output cli 2>&1 | tee "$OUT_TEXT"
CHECKOV_TEXT_EXIT=${PIPESTATUS[0]}

checkov -d "${REPO_ROOT}/terraform" --compact --output json > "$OUT_JSON" 2>/dev/null
CHECKOV_JSON_EXIT=$?

echo
echo "Results saved to:"
echo "  ${OUT_TEXT}"
echo "  ${OUT_JSON}"

if [[ $CHECKOV_TEXT_EXIT -eq 0 ]]; then
  echo "Checkov: PASS — no failed checks."
else
  echo "Checkov: reported failed check(s) — review ${OUT_TEXT} above (exit code ${CHECKOV_TEXT_EXIT})."
  echo "Every finding here is either fixed in the Terraform, or has a documented, reasoned"
  echo "suppression — see SECURITY.md's Checkov section. Do not silently baseline-skip a finding"
  echo "without writing down why."
fi

if command -v terraform >/dev/null 2>&1; then
  echo
  echo "== terraform fmt -check =="
  if (cd "${REPO_ROOT}/terraform/environments/lab" && terraform fmt -check -recursive "${REPO_ROOT}/terraform"); then
    echo "OK — formatting is clean."
  else
    echo "NOTE: run 'terraform fmt -recursive terraform/' from the repo root to fix formatting."
  fi

  echo
  echo "== terraform validate =="
  (cd "${REPO_ROOT}/terraform/environments/lab" && terraform init -backend=false -input=false >/dev/null && terraform validate)
else
  echo
  echo "terraform binary not found locally — skipping fmt/validate. Install terraform >= 1.5 to run these."
fi
