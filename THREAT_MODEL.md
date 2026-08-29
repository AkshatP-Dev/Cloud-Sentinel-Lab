# Threat Model

## Scope

CloudSentinel is a single-account, lab-scale detection-and-response pipeline. This threat model covers
exactly what's deployed by `terraform/environments/lab` — it is not a general-purpose cloud threat model
and does not claim to cover every way an AWS account can be compromised.

**In scope:** control-plane misuse inside the one AWS account this project is deployed into — misuse of
IAM identities, tampering with the audit trail, and exposure of the one S3 bucket this project manages.

**Out of scope, deliberately:**
- Any target outside this AWS account. Nothing in this project sends traffic to, scans, or otherwise
  interacts with external systems, other AWS accounts, or third parties — see the safety constraints in
  `README.md` and `SECURITY.md`.
- Data-plane threats (S3 object exfiltration via `GetObject`, database content theft, application-layer
  attacks). This project watches control-plane API calls (CloudTrail management events), not data
  access patterns.
- Network-layer threats (VPC, security groups, network ACLs) — nothing in this deployment creates
  network infrastructure.
- Supply-chain / code-signing threats to the Lambda deployment packages themselves (see `SECURITY.md`'s
  Known Limitations — AWS Signer code-signing was considered and deliberately deferred).
- Destructive or irreversible automated response of any kind. The one automated response this project
  performs (access-key deactivation) is reversible by design — see §4.

## Assets

| Asset | Why it matters |
|---|---|
| The CloudTrail trail and its S3 log bucket | The single source of truth every detection reads from. If an attacker can stop, delete, or blind this, every other control in this project is defeated silently. |
| IAM identities and their permission boundaries | The mechanism that is supposed to contain the lab identity's blast radius. If a boundary can be bypassed or removed, the "intentionally weak but contained" premise fails. |
| The lab user's access keys | The concrete credential material this project's one automated response protects — a leaked or unexpectedly-created key is the scenario D-04 and the responder exist for. |
| The detector and responder Lambdas' own execution roles | If these were over-permissioned, the detection/response pipeline itself would become an escalation path rather than a control. |

## Actors

- **The lab user** (`cloudsentinel-lab-user`) — an intentionally over-permissioned identity
  (`Action:"*"` attached policy) standing in for a real-world over-granted legacy identity or a
  credential that has fallen into the wrong hands. Everything this project detects is framed as "what
  could this identity do, and did it just try."
- **The account root user** — AWS's own highest-privilege identity, which no policy or boundary can
  constrain. D-01 exists because root usage is inherently unscoped and inherently worth a human's
  attention (see `detections/D-01-root-usage.md`).
- **The operator** (you) — the human who deploys, investigates via the `cloudsentinel-investigator`
  role (MFA-required, read-only), and runs the simulation scripts.
- **This project's own Lambdas** — treated as an actor in their own right for IAM design purposes: each
  execution role is scoped to the minimum the function actually calls, not granted broadly just because
  it's "part of the system." See `IAM_DESIGN.md`.

## Attack-scenario walkthrough

A concrete narrative tying the pieces together — this is the scenario `scripts/simulate_events.sh d04`
exercises end-to-end:

1. Something goes wrong with the lab identity's credential hygiene — a new access key gets created on
   `cloudsentinel-lab-user` (via `iam create-access-key`, whether by a misconfigured automation, a
   mistaken manual action, or a genuine compromise of whatever legitimately manages that identity).
2. CloudTrail logs `CreateAccessKey` as a management event within its usual near-real-time delivery
   window.
3. EventBridge's native CloudTrail integration matches the event against the `scoped_events` rule
   (`terraform/modules/detection/main.tf`) and invokes the detector Lambda.
4. The detector runs all five rules; `rules/access_key_created.py` (D-04) matches, builds a `Finding`,
   and the dispatcher publishes it to SNS (an alert reaches the operator's inbox) and — because
   `resource_affected` matches the configured lab user by name — directly invokes the responder Lambda.
5. The responder independently re-verifies the target identity (§4 of `IAM_DESIGN.md`'s three layers),
   re-queries live IAM state for the actually-active key(s), deactivates them, and publishes a
   containment notice distinct from the original finding alert.
6. The operator sees two SNS messages (finding, then containment), can confirm the key is
   `Inactive` via `aws iam list-access-keys`, and — since deactivation is reversible — can reactivate it
   with `aws iam update-access-key --status Active` once satisfied it was a benign test.

The other four detections (D-01, D-02, D-03, D-05) follow the same detect → alert path but stop at
alerting — see `DETECTIONS.md` for why only D-04 has an automated response and the others are
deliberately alert-only.

## What a real compromise would still need, that this project does not defend against

Being explicit about this matters for interview defensibility as much as for honesty: CloudSentinel
detects and contains specific *symptoms* of compromise inside one account. It does not:

- Prevent the initial credential exposure that leads to `CreateAccessKey` happening in the first place.
- Detect anything about how a stolen key is *used* before the responder deactivates it, beyond the five
  specific event patterns in `detections/`.
- Protect against an attacker who has root or admin-equivalent access outside the lab user's own scope —
  D-01 alerts on root usage, but nothing here can stop root from doing whatever it wants; alerting is the
  only lever available against root by design (root cannot be permission-boundaried).
- Defend the detection pipeline's own infrastructure from an attacker who already has broad IAM
  permissions in the account (e.g. deleting the EventBridge rules or the Lambda functions themselves)
  — an attacker with that level of access has already defeated the control plane this project depends
  on, which is why D-02 focuses on the audit trail specifically as the one dependency every other
  detection needs to survive.
