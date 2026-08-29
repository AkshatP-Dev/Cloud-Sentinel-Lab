# evidence/investigation-logs/

**Status: empty — REQUIRES VERIFICATION.** Capture here while triaging a real (or simulated) finding
using the `cloudsentinel-investigator` role, per `INCIDENT_RESPONSE.md`'s triage flow.

Suggested captures:

```bash
# CloudWatch Logs from the detector's own reasoning for a given event
aws logs tail /aws/lambda/<detector_function_name> --since 30m \
  > evidence/investigation-logs/detector-<UTC timestamp>.txt

# Same for the responder, when a D-04 finding triggered it
aws logs tail /aws/lambda/<responder_function_name> --since 30m \
  > evidence/investigation-logs/responder-<UTC timestamp>.txt

# The investigator role's own read-only lookups during triage
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventId,AttributeValue=<event id> \
  > evidence/investigation-logs/lookup-<event id>.json
```

This folder is about demonstrating the **investigation workflow** (assuming the MFA-gated read-only
role and using it to triage) — as distinct from `cloudtrail-events/`, which holds the raw triggering
event itself.
