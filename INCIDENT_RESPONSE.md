# Incident Response

This is a lab, not a production environment with an on-call rotation — but the runbook below is written
the way a real one would be, because reasoning through triage steps for each detection is part of what
this project is meant to demonstrate.

## General triage flow

1. **An SNS email arrives.** Subject format: `[CloudSentinel][<SEVERITY>] <RULE_ID>: <summary>`. The body
   (`Finding.to_sns_message()` in `lambda/detectors/dispatcher/finding.py`) includes the event name,
   time, region, actor ARN, source IP, affected resource (if any), and the CloudTrail event ID.
2. **Assume the investigator role** (MFA required) to look around read-only without being able to change
   anything: `aws sts assume-role --role-arn <investigator_role_arn output> --role-session-name
   investigate --serial-number <your MFA device ARN> --token-code <code>`.
3. **Pull the full CloudTrail record** for the event ID in the alert:
   `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventId,AttributeValue=<event id>`
   (the investigator role's `cloudtrail:LookupEvents` permission covers this).
4. **Check the detector's own reasoning** in CloudWatch Logs:
   `aws logs tail /aws/lambda/<detector_function_name output> --since 30m` — the detector logs a
   structured `FINDING <rule_id> <severity>: <summary>` line for every match.
5. **Decide**: benign (your own test, a legitimate operator action) or worth deeper investigation. For
   D-04 specifically, also check whether the responder already acted (see below) — if it did, the key is
   already contained and this step is about deciding whether to reactivate it, not about racing to
   respond.
6. **Record what you did** — this project's evidence framework (`evidence/`) exists so that "I built a
   detection pipeline" is backed by an actual example of using it, not just the code that could.

## Per-detection notes

- **D-01 (root usage)** — no automated response is possible or desirable; nothing can permission-boundary
  root. Any root activity, including a *failed* attempt, warrants attention — see
  `detections/D-01-root-usage.md`. If this fires and you didn't just deliberately use root yourself,
  treat it seriously: rotate the root credential and check for MFA tampering immediately.
- **D-02 (logging tamper)** — check first whether the audit trail itself is still intact
  (`aws cloudtrail get-trail-status --name <trail name>`) before trusting any other signal in this
  system; if logging was actually stopped, every other detection is blind until it's restored.
- **D-03 (privilege escalation)** — alert-only by design; the lab identity legitimately performs several
  of these actions on its own scoped resources (see `IAM_DESIGN.md`). Check whether the actor ARN is the
  lab user acting within its own `cloudsentinel-lab-*` prefix (expected) or something else (not
  expected — investigate). A `PutUserPermissionsBoundary`/`DeleteUserPermissionsBoundary` match
  (`BOUNDARY_EVENTS`, escalated to CRITICAL) should never fire against the lab user at all post-deploy —
  the boundary explicitly denies the lab user from touching its own boundary (`IAM_DESIGN.md` §3.3).
- **D-04 (access key created)** — see the worked case study below.
- **D-05 (bucket exposure)** — check the bucket named in the alert with
  `aws s3api get-bucket-policy-status --bucket <name>` and `get-public-access-block` before assuming the
  worst; this rule alerts on the *action* (see `SECURITY.md`'s Known Limitations — it doesn't parse
  whether the change actually granted public access).

## Worked case study: D-04

This section is a **template**, not a report of something that has actually happened yet. Every bracketed
field below gets filled in the first time `scripts/simulate_events.sh d04` (or a real D-04 event) is run
against a deployed environment — see `RESULTS.md`, which tracks this project's overall
"deployed and verified" status. Nothing below is a claim about a real run until it's filled in.

---

**Trigger:** `[FILL IN: e.g. scripts/simulate_events.sh d04, run at <timestamp>]`

**Alert received:** `[FILL IN: SNS email subject and timestamp]`

**CloudTrail event:**
```
[FILL IN: aws cloudtrail lookup-events output for the CreateAccessKey event]
```

**Detector log line:**
```
[FILL IN: aws logs tail output — the "FINDING D-04 HIGH: ..." line]
```

**Responder outcome:**
```
[FILL IN: aws logs tail output for the responder — expect "Deactivated access key <id> on
cloudsentinel-lab-user."]
```

**Verification:**
```
[FILL IN: aws iam list-access-keys --user-name cloudsentinel-lab-user output —
expect Status: Inactive on the created key]
```

**Time from trigger to contained:** `[FILL IN: wall-clock time between the CreateAccessKey call and the
responder's deactivation log line]`

**Containment notice received:** `[FILL IN: SNS email subject/body for the "[CONTAINED]" message]`

**Cleanup:** `[FILL IN: confirmation that /tmp/cloudsentinel-sim-key.json was deleted, and — if this was
only a test — whether the key was left inactive or reactivated]`

---

## Reactivating a contained key

If a D-04 response was triggered by a benign test (or any false positive), reactivate with:

```
aws iam update-access-key --user-name cloudsentinel-lab-user --access-key-id <key-id> --status Active
```

This is a manual, deliberate step — nothing in this project auto-reactivates a key, by design (see
`THREAT_MODEL.md`'s constraint against irreversible-by-default automation; reversibility means a human
can undo it, not that it undoes itself).
