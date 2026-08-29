# IAM Design

This is the most load-bearing document in this repository. CloudSentinel's premise is: deploy an
intentionally over-permissioned IAM identity, then rely on a permission boundary to actually contain
it. That premise is only worth anything if the boundary's guarantee is real, not just plausible-looking
Terraform. This document exists to show the reasoning, the mistake that was caught before it shipped,
and the empirical verification that replaced "this should work" with "this was tested against live AWS
and behaves as claimed."

If you change anything under `terraform/policies/` or `terraform/modules/iam-*`, re-read this file
first, then re-run `tests/live/test_permission_boundary_simulation.py` against the deployed boundary
before trusting your change.

## 1. The three roles

| Role | Assumed by | Purpose | Module |
|---|---|---|---|
| `cloudsentinel-investigator` | A human, with MFA present | Read-only review of CloudTrail/IAM state during an investigation. 1-hour max session. | `iam-hardened` |
| `cloudsentinel-detector-exec` | The detector Lambda | Evaluate events, read IAM policy content, publish findings to SNS, invoke the responder for confirmed D-04 findings. | `iam-hardened` |
| `cloudsentinel-responder-exec` | The responder Lambda | List/read/deactivate access keys on exactly one IAM user. | `iam-hardened` |

Plus one non-role identity:

| Identity | Purpose | Module |
|---|---|---|
| `cloudsentinel-lab-user` | The intentionally weak "attack surface" this whole project detects and responds to. | `iam-lab-weak` |

The investigator role's trust policy (`policies/investigator-trust.json.tpl`) requires
`aws:MultiFactorAuthPresent: true` — a human without MFA on their session cannot assume it, full stop.
Both Lambda execution roles trust only `lambda.amazonaws.com`
(`policies/lambda-trust.json`, static, shared by both).

## 2. The lab identity: attached policy + boundary

`cloudsentinel-lab-user` has an attached policy (`policies/lab-weak-attached.json`) that is deliberately
`Action: "*", Resource: "*"` — as over-permissive as an IAM policy can be. That is the point: it stands
in for the kind of legacy, over-granted identity this project exists to catch. On its own, that policy
would let the user do anything in the account.

What actually constrains it is the **permission boundary**
(`policies/lab-weak-boundary.json.tpl`, attached via `permissions_boundary` on the `aws_iam_user`
resource). AWS evaluates a boundary as an intersection: the identity can only do what *both* its
attached policy *and* its boundary allow. A boundary's own `Allow` statements are therefore the true
ceiling — no attached policy, however broad, can grant anything the boundary doesn't also allow, and any
explicit `Deny` in the boundary wins regardless of what the attached policy says.

This means the boundary is the only thing in this repository actually keeping the lab user "lab-scoped."
Getting it wrong would not just be a bug — it would make the entire project's central claim false.

## 3. The boundary redesign

### 3.1 What was originally proposed

The blueprint's original design for the boundary was: allow broadly, but gate everything on a resource
tag condition — an `aws:ResourceTag/project: cloudsentinel` condition attached to a wide `Allow`, so the
lab user could only touch resources already tagged as part of this project.

### 3.2 Why that was wrong

`aws:ResourceTag` evaluates against tags that already exist **on the resource the request is acting
on**. That works fine for actions against an existing, already-tagged resource — but it does not work
for **creation** actions, because the resource doesn't exist yet at the moment IAM evaluates the
request. There is nothing to check the tag against, so a `ResourceTag`-gated condition simply never
matches for a creation call — which means it never *denies* one either. Any condition that never
matches is not a constraint; it is a no-op.

Concretely, this would have left the highest-risk actions in the entire policy effectively
unconstrained: `iam:CreateUser`, `iam:PassRole`, `sts:AssumeRole`, and removing the boundary itself
(`iam:PutUserPermissionsBoundary` / `iam:DeleteUserPermissionsBoundary`) are all creation-or-escalation
primitives that a `ResourceTag` condition cannot gate. Shipping that design would have produced a
boundary that *looked* restrictive in the Terraform source but provided no real ceiling on privilege
escalation — a false safety guarantee, which is exactly what this project was told not to ship (see the
project's build-phase instructions: *"if the proposed permission boundary does NOT actually provide the
claimed safety guarantee, stop and redesign that portion rather than giving a false sense of
security"*). This was caught during design review, before any of it was deployed, and the boundary was
redesigned from scratch rather than patched.

### 3.3 What replaced it

`policies/lab-weak-boundary.json.tpl` uses a different mechanism for the one thing the lab user is
actually allowed to do — create and manage its own scoped IAM resources — and falls back to explicit,
unconditional `Deny` statements for everything that must never be allowed regardless of tags:

**`AllowManagingOwnLabScopedIamResources`** — the only broad `Allow` in the policy. It uses an
**ARN-prefix resource pattern** (`arn:aws:iam::ACCOUNT:user/cloudsentinel-lab-*`,
`arn:aws:iam::ACCOUNT:policy/cloudsentinel-lab-*`) as the primary constraint, not a tag condition. An
ARN prefix *does* apply correctly at creation time, because the target ARN is derived directly from the
resource name the request itself supplies (e.g. the `UserName` parameter on `CreateUser`) — IAM can
evaluate "does this ARN match this prefix" without the resource existing yet. This is the actual fix:
replacing a condition that is blind at creation time with a resource pattern that isn't. A secondary
`aws:RequestTag/project: cloudsentinel` condition (`StringEqualsIfExists`) is layered on top — note
`RequestTag`, not `ResourceTag`: `RequestTag` evaluates tags supplied *with the current request*, which
does work at creation time, unlike `ResourceTag`. This statement only grants IAM user/policy CRUD
actions (`CreateUser`, `DeleteUser`, `TagUser`, `UntagUser`, `CreatePolicy`, `DeletePolicy`,
`CreatePolicyVersion`, `DeletePolicyVersion`, `AttachUserPolicy`, `DetachUserPolicy`, `PutUserPolicy`,
`DeleteUserPolicy`, `CreateAccessKey`, `DeleteAccessKey`, `UpdateAccessKey`) — a deliberately short list,
not `iam:*`.

**`AllowBroadReadOnlyForDemonstration`** — read-only IAM/CloudTrail/S3-listing/STS-identity actions,
`Resource: "*"`. Read access can't escalate privilege or cause damage, so it doesn't need ARN scoping.

**Everything else is an explicit, unconditional `Deny`**, which cannot be out-scoped by a missing tag or
a resource that doesn't exist yet, because a `Deny` with no condition always evaluates:

- `DenyEscapingTheBoundaryItself` — denies `iam:{Put,Delete}{User,Role}PermissionsBoundary` outright.
  The lab user can never remove or replace its own ceiling.
- `DenyPrivilegeEscalationPrimitives` — denies `iam:PassRole`, `sts:AssumeRole`,
  `sts:AssumeRoleWithSAML`, `sts:AssumeRoleWithWebIdentity` outright. These are the standard building
  blocks of IAM privilege-escalation chains (attach a role to a service, then act as that role); none of
  them are needed for the lab user's own scoped identity management, so none are allowed at all.
- `DenyTouchingAuditLogging` — denies `cloudtrail:{StopLogging,DeleteTrail,UpdateTrail,
  PutEventSelectors,RemoveTags}` outright. The lab user can never blind the audit trail this whole
  project depends on.
- `DenyTouchingTrailBucket` — denies bucket-policy, public-access-block, ACL, versioning, deletion, and
  lifecycle actions, scoped by `Resource` to exactly the CloudTrail log bucket's ARN
  (`var.trail_bucket_arn`, plus `/*`). Includes both plausible spellings of the public-access-block
  actions — see §5 below.
- `DenyOutsideApprovedRegion` — denies everything **except** a short allowlist of inherently
  region-agnostic/read-only actions (`iam:*`, `sts:GetCallerIdentity`, CloudTrail lookups, S3 bucket
  listing) whenever `aws:RequestedRegion` does not match the deployed region. This is a genuine ceiling,
  not just a detection signal — see the live-verified proof in §3.4 that it holds even for services the
  boundary never explicitly mentions.
- `DenyBillingAndOrgActions` — denies `organizations:*`, `account:*`, `aws-portal:*`, and
  `budgets:{ModifyBudget,DeleteBudget}` outright, so the lab identity can never touch the cost tripwire
  that is supposed to be watching it, nor account/org-level settings.

### 3.4 Verifying the replacement empirically

A boundary that reads correctly is still just an assertion until it's checked against how AWS actually
evaluates it. `tests/live/test_permission_boundary_simulation.py` uses the read-only
`iam:SimulatePrincipalPolicy` API — which evaluates a principal's real, live effective permissions
without performing the action — to verify, against the deployed lab user, all of the following:

- **Creation-time ARN scoping actually works** (`TestCreationTimeScoping`): `iam:CreateUser` simulated
  with a `cloudsentinel-lab-*`-prefixed target name and the `project=cloudsentinel` request tag comes
  back `allowed`; the identical call simulated against an out-of-prefix name comes back `explicitDeny`.
  This is the direct proof that the fix in §3.3 (ARN prefix, not `ResourceTag`) actually resolves the
  creation-time blind spot the original design had.
- **Every named escalation primitive is denied** (`TestPrivilegeEscalationPrimitivesAreDenied`,
  parametrized over `iam:PassRole`, `sts:AssumeRole`, and the boundary-removal actions): each comes back
  `explicitDeny`.
- **Audit logging protections hold** (`TestAuditLoggingProtections`): `cloudtrail:StopLogging` and the
  trail-bucket actions come back `explicitDeny`.
- **The region lock is a real ceiling, not just a same-service check**
  (`TestRegionLock`): an out-of-region call comes back `explicitDeny`, and —
  the stronger claim — `test_ec2_in_approved_region_is_still_not_allowed` proves that
  even *inside* the approved region, `ec2:RunInstances` is **not** allowed. The boundary's own `Allow`
  statements never mention EC2 at all; nothing needed to. This is the concrete demonstration of the
  point made in §2: a boundary's `Allow` list is the ceiling regardless of how permissive the attached
  policy is, and this test proves it holds even where the attached policy (`Action:"*"`) would
  otherwise grant it freely.
- **Intended access still works** (`TestReadOnlyDemonstrationAccessWorks`): the boundary isn't so
  strict it breaks the read-only demonstration access it's supposed to allow.

These are live tests against real AWS (see `TESTING.md`) — they require a deployed environment and are
marked accordingly; they have not been run in this build sandbox (no AWS credentials here), and are
listed as **requires verification** until run post-deployment.

## 4. The responder's defense-in-depth

The responder Lambda (`lambda/responders/quarantine/handler.py`) is the one place in this project that
takes a real, if reversible, action against live AWS state (deactivating an access key). It is
deliberately over-defended with three independent layers, so that a bug in any one of them still leaves
two more in place:

1. **IAM-policy-level scoping** (`policies/lambda-responder-exec.json.tpl`): the responder's execution
   role can call `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`, and `iam:UpdateAccessKey` only against
   `${lab_user_arn}` — one specific ARN, never `Resource: "*"`. Even if every line of application code
   below were deleted, AWS itself would reject a call against any other identity.
2. **Application-code-level check** (`_assert_target_is_lab_user` in `handler.py`): before attempting
   anything, the function compares the invocation payload's target username against the
   `LAB_USER_ARN` environment variable and refuses (`ResponderRefused`, logged and returned as
   `{"action": "refused", ...}`, never raised as an uncaught error) on any mismatch — including an unset
   or empty `LAB_USER_ARN`. This check exists even though layer 1 would already block a mismatched call;
   the goal is that the code never even *attempts* the wrong action, not just that AWS would have
   stopped it.
3. **Live re-verification immediately before acting**: rather than trust the access key ID forwarded in
   the invocation payload, `lambda_handler` calls `iam.list_access_keys()` itself right before acting,
   and only deactivates keys it can currently see as `Active` — falling back to *all* currently-active
   keys on the lab user if the specifically-requested key ID is stale or absent (see `TestContainment`
   in `tests/unit/responder/test_responder.py` for the fallback and multi-key cases). This avoids acting
   on stale information from a delayed or replayed invocation.

Deactivating (not deleting) the key is a deliberate choice — the action is reversible
(`aws iam update-access-key --status Active`), consistent with this project's constraint against
irreversible automated response (see `THREAT_MODEL.md` and `SECURITY.md`).

## 5. Known residual ambiguity: S3 public-access-block action naming

AWS's IAM action name and CloudTrail's logged `eventName` for the S3 public-access-block operations do
not obviously agree — research during this build turned up genuinely conflicting descriptions of
whether the IAM action is `s3:PutBucketPublicAccessBlock` or `s3:PutPublicAccessBlock` (and the deletion
equivalent), and this was not fully resolved with confidence either way. Rather than guess and risk a
silent gap, both spellings are included everywhere this matters:

- `DenyTouchingTrailBucket` in the boundary denies both `s3:PutBucketPublicAccessBlock` /
  `s3:PutPublicAccessBlock` and both delete-equivalent spellings.
- D-02 (`logging_tamper.py`) and D-05 (`bucket_exposure.py`)'s `*_EVENTS` sets match both spellings of
  the logged `eventName`.

Over-including a spelling in a `Deny` or a detection match set costs nothing (there is no such IAM
action as a false spelling — it simply never matches), so this is a safe way to close the gap in either
direction without resolving the ambiguity definitively. If you can confirm the correct spelling from a
live CloudTrail event once this is deployed (`aws cloudtrail lookup-events` after running
`scripts/simulate_events.sh d02` or `d05`), note the confirmed spelling in `evidence/` and this section
can be tightened.

## 6. What the boundary does not do (explicit non-goals)

- It does not prevent the lab user from reading broadly (see `AllowBroadReadOnlyForDemonstration`) —
  read access was judged low-risk and useful for the "demonstration" half of this project's purpose.
- It does not prevent data-plane S3 actions (`GetObject`/`PutObject`) against buckets other than the
  trail bucket — out of scope for this project's threat model, which is about account-level control-plane
  compromise, not S3 data exfiltration generally.
- It does not attempt to constrain every AWS service — only the ones relevant to this project's threat
  model. `TestRegionLock`'s EC2 test (§3.4) demonstrates the *region* lock holds outside the boundary's
  named services, but the boundary's `Allow` list simply never grants EC2 at all, in or out of region —
  there was no need to write an EC2-specific `Deny`.
- It is a boundary on one lab identity, not an account-wide guardrail (e.g. an SCP). It only constrains
  identities it is explicitly attached to.
