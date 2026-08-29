# evidence/remediation/

**Status: empty — REQUIRES VERIFICATION.** Capture here the direct evidence that the responder Lambda's
automated containment action actually happened against real IAM state.

```bash
# Immediately after triggering D-04 (scripts/simulate_events.sh d04), capture the "before":
aws iam list-access-keys --user-name cloudsentinel-lab-user \
  > evidence/remediation/before-$(date -u +%Y%m%dT%H%M%SZ).json

# Wait for the responder to run (see its CloudWatch Logs, or just wait ~30s), then the "after":
aws iam list-access-keys --user-name cloudsentinel-lab-user \
  > evidence/remediation/after-$(date -u +%Y%m%dT%H%M%SZ).json
```

The meaningful evidence is the `Status` field flipping from `Active` to `Inactive` on the key you just
created, with no other change to the lab user's state — proof the responder acted precisely, not
broadly. This is the same assertion `tests/live/test_live_detection_flow.py` makes automatically; these
captures are the human-readable record of one specific run of it.
