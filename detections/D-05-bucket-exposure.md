# D-05 — S3 Bucket Exposure

| | |
|---|---|
| **Severity** | HIGH |
| **Automated response** | None (alert only) |
| **Rule logic** | `lambda/detectors/dispatcher/rules/bucket_exposure.py` |
| **EventBridge pattern** | `D-05-bucket-exposure.json` (this directory) — this detection's own event names; merged into the deployed `cloudsentinel-scoped-events` rule alongside D-02/D-03/D-04, see `terraform/modules/detection/main.tf`. |

## What it detects

Any successful ACL, bucket policy, or public-access-block change against
**any** S3 bucket in the account — not just the CloudTrail log bucket,
which has its own dedicated protection via the lab permission boundary's
`DenyTouchingTrailBucket` statement (see D-02). This is a general "did
this account's S3 exposure posture just change" signal.

## Deliberate v1 limitation

This rule does **not** parse the ACL or policy JSON body in
`requestParameters` to determine whether the change actually *grants*
public access versus tightening it. Reliably classifying that from the
raw CloudTrail payload is meaningfully harder than the other four
detections (it requires understanding S3 ACL grantee semantics or
evaluating a full policy document, not just matching an event name).
Treating every matching event name as worth a human's attention — alert
only, never auto-response — is the deliberately simple choice for this
project's scope.

**What a v2 would need:** a follow-up read (`s3:GetBucketPolicyStatus` or
`s3:GetPublicAccessBlock`) immediately after the triggering event, to
confirm the bucket is *actually* more exposed before alerting, cutting the
false-positive rate for legitimate ACL/policy management. Documented here
deliberately rather than silently implied — see `RESULTS.md` for the
project's own stated limitations.

## Testing

`scripts/simulate_events.sh` triggers this safely the same way it
triggers D-02: by creating a throwaway lab-scoped bucket (never the trail
bucket) and **re-asserting** an already-private ACL
(`aws s3api put-bucket-acl --acl private`) rather than actually making
anything public. This generates a genuine, matching `PutBucketAcl` event
without ever exposing real data. The throwaway bucket is deleted
immediately after.

## Known false positives

`terraform apply` triggers this on first deploy while configuring the
trail bucket's own ACL/policy/public-access-block — expected on initial
setup. Legitimate bucket administration (tightening a policy, rotating an
ACL) will also match; this rule cannot distinguish "made safer" from "made
riskier" from the event name alone (see the limitation above), so some
manual review is inherent to this detection.
