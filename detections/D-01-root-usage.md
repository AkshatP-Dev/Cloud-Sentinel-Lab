# D-01 — Root Account Usage

| | |
|---|---|
| **Severity** | CRITICAL |
| **Automated response** | None (alert only) |
| **Rule logic** | `lambda/detectors/dispatcher/rules/root_usage.py` |
| **EventBridge pattern** | `D-01-root-usage.json` (this directory) — matches the deployed `cloudsentinel-root-usage` rule exactly, see `terraform/modules/detection/main.tf` |

## What it detects

Any AWS API call or console sign-in performed by the AWS account **root**
user — successful or failed, in any AWS service. AWS's own guidance is
that root should be locked away behind MFA and used only for the small
set of account-level tasks that genuinely require it (e.g. closing the
account, changing the support plan). There is no routine reason for root
to appear in CloudTrail at all.

## Why it matters

Root cannot be constrained by any IAM policy or permission boundary — it
is the one identity that always has full account access. Every other
detection in this project (D-02 through D-05) exists specifically because
some OTHER identity's permissions might be too broad; root sidesteps that
entire model. If root is ever used unexpectedly, that is worth a human's
immediate attention regardless of what the specific action was.

## Why this rule ignores errorCode

Every other rule in this project skips failed API calls
(`errorCode` present) to avoid alerting on routine access-denied noise.
This rule deliberately does **not** — a *denied* root sign-in attempt can
indicate someone probing for root credentials, which is arguably a more
interesting signal than a successful, intentional one.

## Testing

Root usage is **not** included in `scripts/simulate_events.sh`. Scripting
an automated action using real root credentials is exactly the kind of
thing this project's safety rules exist to prevent — see SECURITY.md.
If you want to verify this rule end-to-end, the safest option is a root
**console sign-in** (which requires MFA if you've enabled it, as you
should have) followed immediately by signing back out; do not perform any
destructive root action just to trigger a test alert. Confirm the
resulting CloudTrail record for that sign-in shows
`userIdentity.type: "Root"`, and confirm you received the SNS alert.

## Known false positives

None expected in a personal lab account — root should never appear in
CloudTrail under normal use. If you see this fire and did not intend to
use root, treat it as a real signal, not noise.
