# D-04 — Access Key Created or Activated

| | |
|---|---|
| **Severity** | HIGH |
| **Automated response** | **Yes** — the only detection with one. See below. |
| **Rule logic** | `lambda/detectors/dispatcher/rules/access_key_created.py` |
| **EventBridge pattern** | `D-04-access-key-created.json` (this directory) — this detection's own event names; merged into the deployed `cloudsentinel-scoped-events` rule alongside D-02/D-03/D-05, see `terraform/modules/detection/main.tf`. |

## What it detects

`CreateAccessKey` against any IAM user, or an `UpdateAccessKey` call whose
`status` parameter is `Active` (an activation, not a deactivation) —
against **any** user in the account, not just the lab identity. Detection
here is intentionally unscoped so a real account gets equal visibility
into unexpected key creation anywhere.

## The automated response — and how it stays scoped

This is the one detection wired to an automated response
(`lambda/responders/quarantine/handler.py`). The *detection* is broad by
design (above); the *response* is not. The dispatcher only invokes the
responder when this Finding's affected user is **exactly** the
CloudSentinel lab identity (`handler.py`'s `_is_lab_user` check, comparing
against the `LAB_USER_ARN` environment variable) — never for any other
user in the account, and never for any other detection. See
`IAM_DESIGN.md` for the full defense-in-depth chain: IAM-policy scoping on
the responder's execution role, an independent application-code check
inside the responder itself, and a re-verification against live IAM state
immediately before acting.

The response deactivates the key (`Status: Inactive`) — reversible, not
destructive. See `SECURITY.md` for why the project deliberately never
deletes or takes irreversible action automatically.

## Why UpdateAccessKey is filtered to activations only

`UpdateAccessKey` covers both activating *and* deactivating a key. The
responder itself calls this same API to deactivate a key — if this rule
alerted on deactivation too, every automated response would immediately
re-trigger itself. Filtering to `status == "Active"` breaks that loop.

## Testing

`scripts/simulate_events.sh` runs
`aws iam create-access-key --user-name cloudsentinel-lab-user`, which is
both a realistic simulation of "a new credential appeared on an
over-permissioned identity" and the direct trigger for the automated
response. The script does not assert success itself — EventBridge/Lambda
propagation is typically near-real-time but not instantaneous, and this
project does not fabricate timing guarantees. It prints the exact
follow-up commands to confirm the key was deactivated
(`aws iam list-access-keys --user-name cloudsentinel-lab-user`) and to
find the SNS containment notice.

## Known false positives

None expected — nothing in this project's own Terraform creates an access
key for the lab user (see `terraform/modules/iam-lab-weak/main.tf`'s
header comment for why that's a deliberate design choice, not an
oversight). Any `CreateAccessKey` on the lab user is either your own test
simulation or worth investigating.
