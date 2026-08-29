# Results

This file is a **template**. Every section below is empty by design — filling it with plausible-looking
numbers before they're real would be exactly the kind of fabricated evidence this project's build
process was explicitly instructed to avoid. Fill each section in as you actually run the corresponding
step against a real AWS deployment; until then, "REQUIRES VERIFICATION" is the honest status.

For what's already been verified *without* a live AWS deployment (unit tests, offline structural checks,
Checkov), see `TESTING.md` — those results are real and already filled in there, because they didn't
require AWS credentials this build environment doesn't have.

---

## Deployment

- Date deployed: `[FILL IN]`
- Region: `[FILL IN]`
- `terraform apply` (Phase 1 — budget tripwire) result: `[FILL IN]`
- `terraform apply` (Phase 2 — full stack) result: `[FILL IN]`
- SNS email subscription confirmed: `[FILL IN — yes/no, timestamp]`
- AWS Budget email subscription confirmed: `[FILL IN — yes/no, timestamp]`

## terraform fmt / validate / plan

- `terraform fmt -check -recursive terraform/`: `[FILL IN]`
- `terraform validate`: `[FILL IN]`
- `terraform plan` (post-apply, expect no changes): `[FILL IN]`

## Live test suite (`pytest tests/live`)

- `tests/live/test_live_logging_config.py`: `[FILL IN — pass/fail, date run]`
- `tests/live/test_live_detection_flow.py`: `[FILL IN — pass/fail, date run]`
- `tests/live/test_permission_boundary_simulation.py`: `[FILL IN — pass/fail, date run]`

## Detection simulations (`scripts/simulate_events.sh`)

| Detection | Simulated | Alert received | Notes |
|---|---|---|---|
| D-01 (root usage) | Not scripted — see `detections/D-01-root-usage.md` | `[FILL IN if manually tested]` | |
| D-02 (logging tamper) | `[FILL IN — date/time]` | `[FILL IN]` | |
| D-03 (privilege escalation) | `[FILL IN — date/time]` | `[FILL IN]` | |
| D-04 (access key created) | `[FILL IN — date/time]` | `[FILL IN]` | See full case study in `INCIDENT_RESPONSE.md` |
| D-05 (bucket exposure) | `[FILL IN — date/time]` | `[FILL IN]` | |

## D-04 automated response timing

- Time from `CreateAccessKey` to detector log line: `[FILL IN]`
- Time from detector log line to responder deactivation: `[FILL IN]`
- Time from `CreateAccessKey` to key confirmed `Inactive`: `[FILL IN]`

## Permission boundary live verification

- `iam:SimulatePrincipalPolicy` results for creation-time ARN scoping: `[FILL IN — allowed/denied as
  expected?]`
- Privilege-escalation primitives all `explicitDeny`: `[FILL IN]`
- Region lock (including the EC2-in-region test): `[FILL IN]`
- Read-only demonstration access still works: `[FILL IN]`

## Cost

- Actual AWS bill for the evaluation period: `[FILL IN]`
- Compared to the `COST.md` estimate: `[FILL IN]`
- Budget tripwire fired?: `[FILL IN — expected: no]`

## Teardown

- `scripts/teardown.sh` run: `[FILL IN — date]`
- Resource Groups Tagging API post-destroy check: `[FILL IN — pass/fail]`
- Manual IAM/S3/Budget console double-check: `[FILL IN]`

---

Once every section above is filled in with real evidence (command output, timestamps, screenshots saved
to `evidence/`), this project's resume bullets and interview talking points should be written from what's
actually here — not the other way around.
