# Changelog

## [0.2.1] — 2026-10-12 — Boundary can no longer rewrite itself

**Fixed**
- The boundary policy's own name matched the `policy/cloudsentinel-lab-*` prefix on which the lab user
  is allowed `iam:CreatePolicyVersion`, so the lab user could publish a new default version of its own
  boundary and remove its ceiling in one call. Added `DenyRewritingTheBoundaryPolicyItself`, an explicit
  Deny on policy-version and delete actions against the boundary ARN. Writeup: `IAM_DESIGN.md` §3.6.

**Changed**
- `tests/offline/test_iam_policy_documents.py`: `REQUIRED_DENIED_ACTIONS` now includes
  `iam:CreatePolicyVersion` and `iam:SetDefaultPolicyVersion`. Test count unchanged.

## [0.2.0] — 2026-08-30 — Permission-boundary escalation chain closed

**Fixed (found in a resume/repo audit, not during the original build)**
- The permission boundary's `AllowManagingOwnLabScopedIamResources` statement granted `iam:CreateUser`,
  `iam:AttachUserPolicy`, and `iam:CreateAccessKey` together, scoped only to the `cloudsentinel-lab-*`
  ARN prefix, with no requirement that a newly created user carry any permission boundary at all. That
  left the standard `CreateUser` → `AttachUserPolicy` → `CreateAccessKey` privilege-escalation chain open
  entirely inside the allowed resource prefix: mint a new `cloudsentinel-lab-*` user with no boundary,
  attach an admin-equivalent policy to it, mint its access key. Fixed by moving `iam:CreateUser` into its
  own statement with a `StringEquals` condition on `iam:PermissionsBoundary`, forcing every user the lab
  identity creates to carry the exact same boundary it operates under. Full writeup, including why the
  fix has to be its own statement rather than added to the combined one: `IAM_DESIGN.md` §3.5.
- Two `terraform fmt`-style alignment regressions (misaligned `=` signs in `environments/lab/main.tf` and
  `modules/iam-hardened/main.tf`) fixed by hand, since this build environment still has no `terraform`
  binary available (network egress to `releases.hashicorp.com` remains blocked — see `TESTING.md`).

**Added**
- `tests/offline/test_iam_policy_documents.py`: two new regression tests guarding the fix above
  (`test_create_user_requires_matching_permissions_boundary`,
  `test_create_user_statement_is_not_combined_with_other_actions`).
- `tests/live/test_permission_boundary_simulation.py::TestCreateUserRequiresPermissionsBoundary`: three
  new live tests (require a real deployment) proving the fix empirically — correct boundary allowed, no
  boundary denied, wrong boundary denied.
- Test suite total: 36 unit + 13 offline + 29 live = **78 collected** (was 73).

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
