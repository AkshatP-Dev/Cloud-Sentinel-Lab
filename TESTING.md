# Testing

## Test suite map

```
tests/
├── unit/               — no AWS credentials needed; moto mocks all AWS calls
│   ├── dispatcher/      test_detection_rules.py  — all 5 rules + dispatcher routing/SNS/responder-gating
│   └── responder/       test_responder.py        — safety gate + real moto IAM state-transition checks
├── offline/             — no AWS credentials needed; static analysis and structural checks
│   ├── test_terraform_validate.py    — wraps scripts/dev/validate_tf_structure.py
│   ├── test_iam_policy_documents.py  — asserts boundary/policy semantics directly from the JSON/.tpl source
│   ├── test_checkov_scan.py          — proves Checkov itself works (known-bad fixture) + runs it for real
│   └── test_lambda_env_wiring.py     — asserts every os.environ var a handler reads is set in that Lambda's Terraform env block (see "A bug this caught" below)
└── live/                — REQUIRES a deployed environment + real AWS credentials; skipped otherwise
    ├── test_live_logging_config.py            — trail + bucket hardening, against real AWS state
    ├── test_live_detection_flow.py            — end-to-end D-04: real key, real detector/responder logs, real deactivation
    └── test_permission_boundary_simulation.py — iam:SimulatePrincipalPolicy against the deployed boundary (see IAM_DESIGN.md §3.4)
```

`tests/live/conftest.py` reads Terraform outputs (`terraform output -json`) to find what's deployed; if
that fails, or `CLOUDSENTINEL_SKIP_LIVE=1` is set, every live test is skipped rather than erroring —
this is why a full `pytest` run shows skips instead of failures when nothing is deployed.

## Commands

```bash
pip install -r requirements-dev.txt --break-system-packages

# Fast, no AWS needed — run this constantly during development
pytest tests/unit tests/offline

# Everything, including live tests (skips them automatically if nothing is deployed)
pytest

# Only after a real terraform apply, with valid AWS credentials active
pytest tests/live

# Static analysis
checkov -d terraform/
python3 scripts/dev/validate_tf_structure.py

# Convenience wrapper for both of the above, saving output to evidence/checkov/
./scripts/security_scan.sh
```

`Makefile` wraps these as `make test`, `make test-unit`, `make test-offline`, `make test-live`,
`make scan`.

## Results — confirmed in this build environment

This build environment has no `terraform` binary and no AWS credentials — it was used to write and unit
-test the code, not to deploy it. What follows was actually run here, today, and is not projected:

| Check | Command | Result |
|---|---|---|
| Unit tests | `pytest tests/unit -q` | **36 passed**, 0 skipped, 0 failed |
| Offline tests | `pytest tests/offline -q` | **11 passed**, 0 skipped, 0 failed |
| Live tests | `pytest tests/live -q` | 0 passed, **26 skipped** (no deployed environment available here — expected, not a failure) |
| Full suite | `pytest -q` | **47 passed, 26 skipped, 0 failed** (73 collected) |
| Checkov | `checkov -d terraform/ --compact --quiet` | **59 passed, 0 failed, 23 skipped** (all 23 documented inline — see `SECURITY.md`) |
| Custom structural validator | `python3 scripts/dev/validate_tf_structure.py` | **PASS** — 16 `.tf` files, 8 policy JSON/`.tpl` files, no `templatefile()`/`file()` wiring errors, valid JSON/IAM-statement grammar, balanced braces, valid module sources, no undeclared `var.X` references |
| Static syntax check (`pyflakes`) | `pyflakes lambda/ tests/ scripts/dev/*.py` | Zero output — no unused imports, no undefined names |

Tool versions this was run with: Python 3.11.15, pytest 9.1.1, boto3 1.35.49, moto 5.2.3, checkov 3.3.15.

## A bug this caught

`test_lambda_env_wiring.py` is not a hypothetical safeguard — it caught a real bug during this build.
The detector Lambda's `handler.py` reads `LAB_USER_ARN` from its environment to decide whether a D-04
finding belongs to the lab user before invoking the responder, but `terraform/modules/detection/main.tf`
originally only set `SNS_TOPIC_ARN` and `RESPONDER_FUNCTION_NAME` on that function — `LAB_USER_ARN` was
wired to the *responder's* environment (which does need it) but never the detector's. Every unit test
still passed, because `tests/unit/dispatcher/test_detection_rules.py` sets the module attribute directly
via `monkeypatch` to test `_is_lab_user()`'s logic in isolation — which is correct for what it tests, but
can't see a missing Terraform wire. Left unfixed, the automated-response path (the single most
demonstration-worthy behavior in this project) would have been silently dead on a real deployment: D-04
findings would still detect and alert correctly, but the responder would simply never be invoked. Caught
and fixed before any deployment; `test_lambda_env_wiring.py` now guards against this exact class of
regression recurring. See `terraform/modules/detection/main.tf`'s comment on the detector's `LAB_USER_ARN`
environment entry for the fix itself.

## Explicitly NOT run here — requires verification after a real deployment

Being direct about this rather than implying otherwise: this build sandbox has no `terraform` binary
installed (its network egress allowlist blocks both `registry.terraform.io` and
`releases.hashicorp.com`, so it couldn't be downloaded) and no AWS credentials configured, so none of the
following have been run, and nothing in this repository should be read as claiming they have:

- `terraform fmt -check`, `terraform validate`, `terraform plan`, `terraform apply` — untested here.
  `scripts/dev/validate_tf_structure.py` (above) covers a meaningful but different surface: it checks
  file-wiring and JSON/grammar correctness by parsing the `.tf`/`.tpl`/`.json` source directly, without a
  Terraform installation. It is not a substitute for `terraform validate`, which understands the actual
  provider schema (attribute names, types, required arguments) that the custom validator does not model.
- Every test in `tests/live/` — all 26 are collected and correctly skip (not fail) with no deployment
  present, but none have actually executed their assertions against real AWS.
- Anything about real-world Lambda cold-start behavior, actual CloudTrail-to-EventBridge delivery
  latency, or real SNS email delivery.

The exact command sequence to run all of the above for real, with expected results to compare against,
lives in this repo: `README.md`'s Quickstart plus this file's own Commands section above cover the
sequence itself; `RESULTS.md` is the template where actual results get recorded once a real deployment
exists. (The original author also received a one-time deployment/verification checklist as a chat
deliverable outside this repo — that was a personal handoff artifact for the first deployment, not a
tracked project file, so don't expect to find it here.)
