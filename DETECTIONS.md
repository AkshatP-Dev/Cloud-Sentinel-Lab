# Detections

Five detections, evaluated by one detector Lambda, fed by two EventBridge rules. This is the index —
each detection also has its own `detections/D-0X-*.md` with full detail (what it matches, why, testing
approach, known false positives) and a matching `.json` describing its logical shape independent of the
Terraform rule it happens to share.

## Index

| ID | Name | Severity | Automated response? | Rule logic |
|---|---|---|---|---|
| D-01 | Root account usage | CRITICAL | No — alert only | `lambda/detectors/dispatcher/rules/root_usage.py` |
| D-02 | Audit-logging tamper | CRITICAL | No — alert only | `lambda/detectors/dispatcher/rules/logging_tamper.py` |
| D-03 | Privilege-escalation primitives | HIGH (CRITICAL for boundary tampering) | No — alert only | `lambda/detectors/dispatcher/rules/privilege_escalation.py` |
| D-04 | Access key created/activated | HIGH | **Yes** — responder deactivates the key, lab-user-scoped only | `lambda/detectors/dispatcher/rules/access_key_created.py` |
| D-05 | S3 bucket exposure | HIGH | No — alert only | `lambda/detectors/dispatcher/rules/bucket_exposure.py` |

Only D-04 has an automated response. The other four are deliberately alert-only: each fires on a
*pattern* (an action commonly associated with a real problem), not a confirmed compromise, and several
are things the lab identity or an operator can do legitimately in context (e.g. the lab user managing
its own scoped IAM resources for D-03, or a routine trail configuration change for D-02) — automatically
acting on a pattern that has legitimate uses would risk breaking normal operation. D-04 is the exception
because its blast radius is narrow (deactivating a key is fully reversible, and only ever happens to the
one identity this project owns end-to-end) and its trigger is unambiguous (a new or newly-activated
credential existing at all is worth containing immediately, pending human review) — see
`INCIDENT_RESPONSE.md` and `IAM_DESIGN.md` §4.

## Two EventBridge rules, five detections

`terraform/modules/detection/main.tf` defines exactly two EventBridge rules, both targeting the same
detector Lambda:

- **`root_usage`** — matches `detail.userIdentity.type == ["Root"]` on any `AWS API Call via CloudTrail`
  or `AWS Console Sign In via CloudTrail` event, regardless of `eventName`. This is D-01's rule, alone,
  because root usage can't be expressed as an eventName allowlist — root can call literally anything.
- **`scoped_events`** — matches a single merged list of 29 `eventName`s (`local.scoped_event_names`)
  across `source: ["aws.iam", "aws.s3", "aws.sts", "aws.cloudtrail"]`. This one rule feeds D-02, D-03,
  and D-04 — and the S3-related subset of it also feeds D-05.

Both rules exist because EventBridge ANDs together every top-level key specified in one pattern object —
there is no way to express "eventName is one of set A OR userIdentity.type is Root" in a single rule
(see `ARCHITECTURE.md`'s design-decisions section). Splitting D-02 through D-05 into their own rules
apiece was considered and rejected: they all match on `eventName` within the same handful of services,
so one merged rule keeps the Terraform small, and the actual per-detection distinctions
(which `eventName`s belong to which detection, what severity, what to extract) live in Python
(`rules/*.py`) where they're both easier to unit test and easier to extend — adding a sixth detection
means one new file in `rules/` and one new line in `rules/__init__.py`'s `ALL_RULES`, not a new
Terraform resource.

## Shared reasoning: several event names mirror the lab boundary's own Deny list

D-02's `TAMPER_EVENTS` and the boundary's `DenyTouchingAuditLogging`/`DenyTouchingTrailBucket`
statements name many of the same actions on purpose (see `policies/lab-weak-boundary.json.tpl` and
`rules/logging_tamper.py`'s docstrings): what the boundary prevents *by policy*, the detector
independently watches for *by event*. If the boundary is ever misconfigured, bypassed, or simply doesn't
apply to some other identity in the account, the same tampering attempt is still visible here — the two
mechanisms are intentionally redundant, not duplicated by accident.

## Per-detection detail

See `detections/D-01-root-usage.md` through `detections/D-05-bucket-exposure.md` for: exact matched
event names, the specific rule-logic file, why the automated-response decision was made the way it was,
the `scripts/simulate_events.sh` command that exercises it (D-01 excluded — see its own doc for why
scripting a root-credential action would be irresponsible), and documented known false positives.

## Testing a detection end to end

`scripts/simulate_events.sh {d02|d03|d04|d05|all}` triggers real CloudTrail events against the deployed
environment using your own operator credentials (never the lab user's) — see that script's own header
comment for exactly what each simulation does and why none of them ever actually weaken security, even
momentarily. Every simulated event is a real API call CloudTrail genuinely logs; nothing is faked or
replayed. See `TESTING.md` for the full verification checklist and `tests/live/test_live_detection_flow.py`
for the automated version of the D-04 end-to-end check (create a key, poll CloudWatch Logs for both the
detector's and responder's log lines, confirm the key is `Inactive`, clean up).
