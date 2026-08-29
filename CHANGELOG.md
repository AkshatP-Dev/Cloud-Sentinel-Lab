# Changelog

## [0.1.0] — 2026-08-27 — Initial build

Infrastructure, application code, and offline verification complete. Not yet deployed to real AWS from
this build environment — see `RESULTS.md` and `TESTING.md` for what's verified versus what's pending a
real deployment.

**Added**
- Terraform: `logging`, `iam-hardened`, `iam-lab-weak`, and `detection` modules, wired together in the
  `lab` environment, plus an AWS Budget cost tripwire.
- Detector Lambda (`lambda/detectors/dispatcher`) with five detection rules (D-01 through D-05) and a
  responder Lambda (`lambda/responders/quarantine`) with a three-layer defense-in-depth safety gate.
- Full test suite: 36 unit tests (moto-mocked), 11 offline structural/static-analysis tests, 26 live
  tests (require a real deployment).
- Full documentation set (`README.md` plus 9 other docs) and an `evidence/` scaffold for
  post-deployment verification artifacts.

**Fixed (during build, before any deployment)**
- The originally-proposed permission boundary design (an `aws:ResourceTag` condition) would not have
  constrained resource-creation actions — redesigned to use ARN-prefix resource patterns and
  `aws:RequestTag` instead, and verified empirically against `iam:SimulatePrincipalPolicy`. See
  `IAM_DESIGN.md` §3.
- The detector Lambda's Terraform environment block did not set `LAB_USER_ARN`, which would have
  silently disabled the automated D-04 response on a real deployment despite all unit tests passing.
  Caught by a new regression test, `tests/offline/test_lambda_env_wiring.py`. See `TESTING.md`'s
  "A bug this caught" section.
