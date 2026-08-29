# evidence/before-after/

**Status: empty — REQUIRES VERIFICATION.** Broader before/after comparisons than
`remediation/` (which is specifically about the D-04 access-key containment) — use this folder for the
other four detections' simulations, where "before" and "after" are about showing a value was
re-asserted or a throwaway resource cleaned up, not that anything was actually remediated.

Examples:
- D-02: `aws s3api get-bucket-versioning` before/after `scripts/simulate_events.sh d02` (expected:
  identical — the simulation re-asserts an already-correct value, see that script's comments).
- D-03: confirmation that `cloudsentinel-lab-sim-user` existed briefly and was fully cleaned up
  (`aws iam get-user` returning `NoSuchEntity` afterward).
- D-05: confirmation the throwaway simulation bucket no longer exists after cleanup.

The point of this folder is honesty about what the simulations do and don't change — see
`scripts/simulate_events.sh`'s header comment: every simulation either re-asserts an already-safe value
or cleans up immediately after itself, and this is where that claim gets backed by an actual captured
before/after pair instead of just asserted in a comment.
