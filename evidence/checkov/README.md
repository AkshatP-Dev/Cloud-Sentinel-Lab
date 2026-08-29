# evidence/checkov/

Auto-populated by `./scripts/security_scan.sh` — each run writes a timestamped
`checkov-<UTC timestamp>.txt` (human-readable) and `.json` (machine-readable) pair into this directory.
Nothing here needs to be hand-authored.

**Status:** `checkov-20260827T141820Z.{txt,json}` is a real, unedited capture from this build
environment — 59 passed, 0 failed, 23 skipped, every skip carrying its own inline reasoning (see
`SECURITY.md`). Checkov needs no AWS credentials, so this one didn't have to wait for a deployment.

Re-run `./scripts/security_scan.sh` after any change to `terraform/` to regenerate — Checkov results are
only meaningful as of the source at the time they were captured, so don't treat an old capture here as
still authoritative after the Terraform changes. Keep the newest capture; older ones are just history.
