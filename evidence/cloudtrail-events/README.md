# evidence/cloudtrail-events/

**Status: empty — REQUIRES VERIFICATION.** Capture here after running `scripts/simulate_events.sh`
against a real deployment.

For each simulation, save the raw CloudTrail record that triggered a detection:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --max-results 1 \
  > evidence/cloudtrail-events/d04-createaccesskey-$(date -u +%Y%m%dT%H%M%SZ).json
```

Repeat with the relevant `EventName` for D-02, D-03, and D-05 (see each detection's `.md` in
`detections/` for its matched event names). This is the raw proof that the simulated action produced a
real, CloudTrail-logged API call — not a synthetic test fixture.

**Before committing:** these captures include your AWS account ID and IAM ARNs. Review each file and
redact anything more sensitive than that (there shouldn't be — CloudTrail management events don't
include credential material), consistent with `SECURITY.md`'s secrets-handling statement.
