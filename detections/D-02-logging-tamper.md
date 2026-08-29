# D-02 — CloudTrail / Audit-Logging Tamper

| | |
|---|---|
| **Severity** | CRITICAL |
| **Automated response** | None (alert only) |
| **Rule logic** | `lambda/detectors/dispatcher/rules/logging_tamper.py` |
| **EventBridge pattern** | `D-02-logging-tamper.json` (this directory) — this detection's own event names. The **deployed** rule (`cloudsentinel-scoped-events` in `terraform/modules/detection/main.tf`) merges this list with D-03/D-04/D-05's into one EventBridge rule for efficiency; this file shows D-02's own slice standalone for documentation clarity. |

## What it detects

Any successful attempt to weaken or remove the audit trail this entire
project depends on:

- Stopping, deleting, or reconfiguring the CloudTrail trail itself
  (`StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`,
  `RemoveTags`).
- Modifying the S3 bucket CloudTrail delivers logs to — policy, ACL,
  public access block, versioning, lifecycle, or deleting the bucket
  outright.

## Why it matters

Every other detection in this project depends on CloudTrail actually
being enabled and actually being delivered somewhere durable. An attacker
(or a careless script) that can disable logging before doing anything
else can operate with impunity — this is one of the first things a real
intrusion often targets. Catching *attempts* to tamper with logging,
independent of whatever the attacker does next, is a foundational control.

## Defense in depth with the permission boundary

Several of these exact event names are also explicitly **denied** by the
lab identity's permission boundary
(`terraform/policies/lab-weak-boundary.json.tpl`'s
`DenyTouchingAuditLogging` and `DenyTouchingTrailBucket` statements). That
overlap is deliberate: what the boundary prevents by policy, this rule
independently watches for by event. If the boundary were ever
misconfigured, bypassed, or simply doesn't apply to some other identity in
the account, this detection still fires. See `IAM_DESIGN.md`.

## A naming quirk worth knowing

The IAM action `s3:PutBucketPublicAccessBlock` and the CloudTrail
`eventName` logged for the same underlying call are not guaranteed to use
identical spelling conventions across all of S3's newer API surface —
verified during this project's build against AWS's public documentation
(see `IAM_DESIGN.md` for the verification notes). Both plausible event
name spellings (`PutBucketPublicAccessBlock` / `PutPublicAccessBlock`, and
the Delete equivalents) are matched here for the same reason both are
denied in the boundary: to close any gap from a naming mismatch either
way.

## Testing

`scripts/simulate_events.sh` triggers this safely by **re-asserting an
already-safe configuration** — e.g. calling `PutBucketVersioning` with the
same `Enabled` status the trail bucket already has. CloudTrail logs the
API *call*, not just a resulting state change, so this generates a
genuine, matching event without ever actually weakening protection.

## Known false positives

`terraform apply` itself will generate some of these event names on
initial deployment (creating the bucket policy, enabling versioning,
etc.) — expect at least one alert on first deploy. That is correct
behavior, not a bug: the detector has no way to distinguish "Terraform is
setting this up for the first time" from "someone is changing it later,"
and arguably it shouldn't try to — both are worth a record.
