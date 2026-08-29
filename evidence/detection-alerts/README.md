# evidence/detection-alerts/

**Status: empty — REQUIRES VERIFICATION.** Capture here once real SNS alert emails have been received.

For each of the five detections, save either a screenshot or a plain-text copy of the alert email
(subject + body — see `Finding.to_sns_message()` / `to_sns_subject()` in
`lambda/detectors/dispatcher/finding.py` for the exact format to expect). Suggested naming:
`d0X-<rule_name>-<UTC timestamp>.png` or `.txt`.

For D-04 specifically, capture **both** emails: the original finding alert and the separate
`[CloudSentinel][CONTAINED]` containment notice the responder publishes — the pair is the evidence that
detection and automated response are two distinct, independently observable events, not one step.

This is also where the filled-in `INCIDENT_RESPONSE.md` case study's alert references should point.
