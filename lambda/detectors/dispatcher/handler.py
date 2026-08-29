"""
CloudSentinel detector dispatcher — Lambda entry point.

Invoked by EventBridge (see terraform/modules/detection/main.tf's two
rules, root_usage and scoped_events) with a CloudTrail event wrapped in
the EventBridge envelope. Runs every rule in rules.ALL_RULES against the
event, publishes any resulting Finding(s) to SNS, logs a structured
summary either way, and — for a confirmed D-04 finding whose affected user
is exactly the lab identity — directly invokes the responder Lambda to
contain it.

A single invocation can legitimately produce more than one Finding (e.g.
a rule set could theoretically both match the same event for different
reasons); each is published independently rather than merged, so nothing
is silently dropped.
"""
from __future__ import annotations

import json
import logging
import os

import boto3

import event_utils as ev
from finding import Finding, publish_finding
from rules import ALL_RULES

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
RESPONDER_FUNCTION_NAME = os.environ.get("RESPONDER_FUNCTION_NAME", "")
LAB_USER_ARN = os.environ.get("LAB_USER_ARN", "")  # optional — used only
# to recognize the lab user by name for the D-04 auto-response gate below.
# CreateAccessKey/UpdateAccessKey's requestParameters carry a userName,
# not an ARN, so the comparison in _is_lab_user is by name, not full ARN.

_sns = None
_lambda_client = None


def _sns_client():
    global _sns
    if _sns is None:
        _sns = boto3.client("sns")
    return _sns


def _lambda_client_fn():
    global _lambda_client
    if _lambda_client is None:
        _lambda_client = boto3.client("lambda")
    return _lambda_client


def _is_lab_user(user_name: str) -> bool:
    if not user_name or not LAB_USER_ARN:
        return False
    return LAB_USER_ARN.rsplit("/", 1)[-1] == user_name


def _invoke_responder(finding: Finding) -> None:
    if not RESPONDER_FUNCTION_NAME:
        logger.warning(
            "RESPONDER_FUNCTION_NAME not set; skipping automated response for %s",
            finding.event_id,
        )
        return
    logger.info(
        "Invoking responder %s for finding %s (%s)",
        RESPONDER_FUNCTION_NAME, finding.event_id, finding.rule_id,
    )
    _lambda_client_fn().invoke(
        FunctionName=RESPONDER_FUNCTION_NAME,
        InvocationType="Event",  # async — the dispatcher doesn't block on the responder's own run
        Payload=finding.to_json().encode("utf-8"),
    )


def _evaluate(event: dict) -> list[Finding]:
    findings: list[Finding] = []
    for rule_check in ALL_RULES:
        try:
            result = rule_check(event)
        except Exception:
            logger.exception(
                "Rule %s raised while evaluating event %s",
                getattr(rule_check, "__module__", rule_check), ev.event_id(event),
            )
            continue
        if result is not None:
            findings.append(result)
    return findings


def lambda_handler(event: dict, context) -> dict:
    logger.info(
        "Evaluating event: %s",
        json.dumps({
            "eventName": ev.event_name(event),
            "eventSource": ev.event_source(event),
            "eventId": ev.event_id(event),
        }),
    )

    findings = _evaluate(event)

    for finding in findings:
        logger.info("FINDING %s %s: %s", finding.rule_id, finding.severity, finding.summary)

        if SNS_TOPIC_ARN:
            try:
                publish_finding(_sns_client(), SNS_TOPIC_ARN, finding)
            except Exception:
                logger.exception("Failed to publish finding %s to SNS", finding.event_id)
        else:
            logger.warning("SNS_TOPIC_ARN not set; finding %s was logged but not published", finding.event_id)

        if finding.rule_id == "D-04" and _is_lab_user(finding.resource_affected):
            try:
                _invoke_responder(finding)
            except Exception:
                logger.exception("Failed to invoke responder for finding %s", finding.event_id)

    return {
        "findings_count": len(findings),
        "rule_ids": [f.rule_id for f in findings],
    }
