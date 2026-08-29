# Security

## Scope and safety constraints

Everything in this repository operates against a single, dedicated AWS account/region that you deploy
it into. It never targets, scans, or interacts with anything outside that account. The one automated
response this project performs — deactivating an access key — is reversible, not destructive, and is
scoped (by IAM policy, by application code, and by a live re-check; see `IAM_DESIGN.md` §4) to exactly
one intentionally-created lab identity. Nothing here is intended to run against a production account.

## Secrets handling

No secret, credential, or key material is stored anywhere in this repository. `terraform.tfvars` (which
holds your account-specific `operator_principal_arn` and `alert_email`) is gitignored — only
`terraform.tfvars.example`, with placeholder values, is committed. The Lambda functions receive no
credentials as configuration; they use their execution role's credentials, provided automatically by the
Lambda runtime. `scripts/simulate_events.sh`'s D-04 simulation does create a real (throwaway) access key
on the lab user and writes it to `/tmp/cloudsentinel-sim-key.json` — that path is outside the repository
and the script's own output tells you to delete it once you're done. Nothing in `evidence/` should ever
contain a live credential; if you're capturing command output for `evidence/`, redact any key material
before saving it.

## Static analysis: Checkov

`scripts/security_scan.sh` runs Checkov against the full `terraform/` tree. Current result (re-run
2026-08-27, offline against the Terraform source only — no AWS credentials involved in a Checkov scan):

```
Passed checks: 59, Failed checks: 0, Skipped checks: 23
```

Every one of the 23 skipped checks is an inline `#checkov:skip=<ID>:<reason>` comment in the Terraform
source next to the resource it applies to — not a blanket baseline file, and not a silent suppression.
Each carries its own specific reasoning, grouped here by rationale:

### Deliberate subject of this project (2) — Checkov flagging these confirms the scanner works

| Check | Resource | Why it's suppressed, not fixed |
|---|---|---|
| `CKV_AWS_273` | `aws_iam_user.lab` (`iam-lab-weak`) | A directly-defined IAM user with a direct policy attachment (instead of SSO/group membership) is exactly the over-permissioned legacy-identity pattern this project exists to detect and contain. |
| `CKV_AWS_40` | `aws_iam_user_policy_attachment.lab_weak` (`iam-lab-weak`) | Same reasoning — a policy attached directly to a user is the deliberate subject, not an oversight. |

### Cost/benefit trade-offs for a personal lab (8) — see `COST.md`

| Check | Resource(s) | Reasoning |
|---|---|---|
| `CKV_AWS_145` | CloudTrail S3 bucket | SSE-S3 (AES-256) already encrypts at rest; a customer-managed KMS key costs ~$1/month/key for no meaningful benefit to non-regulated lab data. |
| `CKV_AWS_35` | `aws_cloudtrail.this` | Same SSE-S3-is-sufficient reasoning, applied to the trail resource itself. |
| `CKV_AWS_158` ×2 | Both Lambda CloudWatch Log groups | AWS-owned encryption is sufficient for execution logs containing no secrets/PII. |
| `CKV_AWS_144` | CloudTrail S3 bucket | Cross-region replication is a disaster-recovery control, not a security one — disproportionate cost for this budget. |
| `CKV_AWS_18` | CloudTrail S3 bucket | Access logging would require a second bucket; the trail itself already captures management-event API calls against this bucket. |
| `CKV_AWS_338` ×2 | Both Lambda CloudWatch Log groups | 14-day retention is a deliberate cost control (`var.log_retention_days`), not an oversight. |

### Deferred hardening, noted as future work, not gaps discovered late (8)

| Check | Resource(s) | Reasoning |
|---|---|---|
| `CKV_AWS_116` ×2 | Both Lambda functions | No dead-letter queue configured — a reasonable v2 enhancement; EventBridge itself retries failed async invocations before giving up. |
| `CKV_AWS_117` ×2 | Both Lambda functions | Deliberately not in a VPC — both functions only call AWS service APIs (SNS/IAM/Lambda), need no VPC-private resource, and VPC placement would require a NAT Gateway (~$32/month) for no security benefit against this threat model. |
| `CKV_AWS_272` ×2 | Both Lambda functions | Code-signing (AWS Signer) is a software-supply-chain control disproportionate to a personal portfolio lab. |
| `CKV_AWS_50` ×2 | Both Lambda functions | X-Ray tracing not enabled — an observability enhancement, deliberately deferred to keep scope focused on detection/response. |

(Table above lists 4 distinct check IDs across both functions = 8 individual suppressions; combined with
the 2 in the row above it and counted per-resource, see the full count below.)

### Confirmed non-issues on inspection (2)

| Check | Resource(s) | Reasoning |
|---|---|---|
| `CKV_AWS_173` ×2 | Both Lambda functions | Environment variables (`SNS_TOPIC_ARN`, `RESPONDER_FUNCTION_NAME`/`LAB_USER_ARN`) are resource identifiers, not secrets — confirmed by code review. Lambda already encrypts them at rest with an AWS-owned key by default. |

### Redundant with an already-chosen alternative mechanism (3)

| Check | Resource | Reasoning |
|---|---|---|
| `CKV_AWS_252` | `aws_cloudtrail.this` | CloudTrail's native SNS notification (one message per log file) is a legacy/alternative delivery mechanism this project doesn't use — detection is driven entirely through EventBridge's free native CloudTrail integration instead. |
| `CKV2_AWS_10` | `aws_cloudtrail.this` | Deliberately not integrated with CloudWatch Logs — that path costs $0.50/GB at this project's scale; EventBridge's native integration is free for this same-account use case (see `COST.md`). |
| `CKV2_AWS_62` | CloudTrail S3 bucket | S3 event notifications would fire on "a new log object appeared," which isn't the signal this project's detections evaluate — detection is already routed through EventBridge's CloudTrail integration, not S3 notifications. |

Counts by category: 2 (deliberate subject) + 8 (cost/benefit) + 8 (deferred hardening) + 2 (confirmed
non-issue) + 3 (redundant with an alternative) = **23**, matching Checkov's own "Skipped checks: 23"
above exactly. This tally is a reasoning index, not the authoritative source — the authoritative list is
the Terraform source itself (`grep -rn checkov:skip terraform/`) or a fresh
`evidence/checkov/checkov-<timestamp>.txt` from running `scripts/security_scan.sh` against this repo.

## Known limitations

Deliberately out of scope for this build, listed here rather than left implicit:

- **No dead-letter queue** on either Lambda (`CKV_AWS_116`). A v2 could add one for durability against a
  detector/responder crash loop.
- **No VPC placement** (`CKV_AWS_117`) — a deliberate choice (see table above), not a gap expected to
  close later, unless a future version needs to reach a VPC-private resource.
- **No code-signing** (`CKV_AWS_272`) and **no X-Ray tracing** (`CKV_AWS_50`) — both reasonable v2
  additions, deferred to keep this build's scope on detection/response logic itself.
- **D-05 (bucket exposure) does not parse ACL/policy body content** — it alerts on any matching event
  name (`PutBucketAcl`, `PutBucketPolicy`, the public-access-block actions) without checking whether the
  change actually *grants* public access versus tightening it. This is a real false-positive source,
  documented in `rules/bucket_exposure.py` and `detections/D-05-bucket-exposure.md` — a v2 would add a
  follow-up `s3:GetBucketPolicyStatus` / `s3:GetPublicAccessBlock` read before alerting.
- **The S3 public-access-block IAM action name is ambiguous** and was not fully resolved — see
  `IAM_DESIGN.md` §5 for the specific ambiguity and the defensive dual-spelling mitigation.
- **The boundary constrains only the services it explicitly names.** It is not an account-wide guardrail
  — see `IAM_DESIGN.md` §6 for the explicit non-goals.
- **`terraform fmt`/`validate`/`plan`/`apply` and every `tests/live/` test have not been run** in this
  build environment — no `terraform` binary and no AWS credentials are available in the sandbox this
  project was built in. These are marked **REQUIRES VERIFICATION** throughout this repository (see
  `TESTING.md` and `RESULTS.md`) and must be run against a real deployment before any claim about live
  behavior is treated as confirmed.

## Reporting

This is a personal portfolio/lab project, not a maintained service — there is no formal disclosure
process. If you're reviewing this as a hiring manager or engineer and spot an actual issue, the honest
answer is: open an issue or reach out directly.
