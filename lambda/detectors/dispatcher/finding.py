"""
Finding — the structured result produced by a detection rule.

Every rule function in rules/*.py returns either None (no match) or a
Finding (a match). handler.py collects whatever Findings fired for a given
CloudTrail event, publishes each to SNS, logs it, and — for exactly one
rule (D-04, when the affected user is the lab identity) — forwards it to
the responder Lambda.

Keeping this as one small, shared class (rather than each rule inventing
its own dict shape) is what lets tests/unit/test_detection_rules.py assert
against a single consistent contract across all five rules.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

SEVERITY_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass
class Finding:
    rule_id: str          # "D-01".."D-05"
    rule_name: str        # "root_usage", "logging_tamper", ...
    severity: str         # one of SEVERITY_LEVELS
    summary: str          # one-line human summary
    event_name: str
    event_time: str
    aws_region: str
    source_ip: str
    actor_arn: str         # who performed the action
    event_id: str
    resource_affected: str = ""   # what/who the action targeted (D-04 user, D-05 bucket) — distinct from actor_arn
    access_key_id: str = ""       # D-04 only: the access key ID involved, if any
    raw_event_excerpt: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_LEVELS:
            raise ValueError(f"invalid severity {self.severity!r}, must be one of {SEVERITY_LEVELS}")

    def to_sns_message(self) -> str:
        """Human-readable message body for the SNS email subscription."""
        lines = [
            f"[CloudSentinel] {self.severity} — {self.rule_id} {self.rule_name}",
            "",
            self.summary,
            "",
            f"Event:     {self.event_name}",
            f"Time:      {self.event_time}",
            f"Region:    {self.aws_region}",
            f"Actor:     {self.actor_arn}",
            f"Source IP: {self.source_ip}",
            f"Event ID:  {self.event_id}",
        ]
        if self.resource_affected:
            lines.insert(5, f"Affected:  {self.resource_affected}")
        return "\n".join(lines)

    def to_sns_subject(self) -> str:
        # SNS subjects are capped at 100 characters.
        subject = f"[CloudSentinel][{self.severity}] {self.rule_id}: {self.summary}"
        return subject[:100]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "summary": self.summary,
            "event_name": self.event_name,
            "event_time": self.event_time,
            "aws_region": self.aws_region,
            "source_ip": self.source_ip,
            "actor_arn": self.actor_arn,
            "event_id": self.event_id,
            "resource_affected": self.resource_affected,
            "access_key_id": self.access_key_id,
            "raw_event_excerpt": self.raw_event_excerpt,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


def publish_finding(sns_client, topic_arn: str, finding: Finding) -> dict:
    """Publish one Finding to the alerts SNS topic. Kept as a plain
    function (not a Finding method) so tests can pass a stub/mock client
    without touching the dataclass itself."""
    return sns_client.publish(
        TopicArn=topic_arn,
        Subject=finding.to_sns_subject(),
        Message=finding.to_sns_message(),
        MessageAttributes={
            "rule_id": {"DataType": "String", "StringValue": finding.rule_id},
            "severity": {"DataType": "String", "StringValue": finding.severity},
        },
    )
