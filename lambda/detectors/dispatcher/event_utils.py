"""
Shared helpers for pulling fields out of a CloudTrail event as delivered by
EventBridge. Every rule in rules/*.py uses these instead of reaching into
the raw dict directly, so a change in event shape only has to be handled
in one place.

EventBridge wraps the CloudTrail record in its own envelope
(source / detail-type / account / region / time / ...) with the actual
CloudTrail record under `detail`. See AWS's "Amazon EventBridge and
CloudTrail" documentation. Unit tests are free to pass either the full
envelope or just the inner `detail` object directly — cloudtrail_detail()
below handles both, which keeps rule/tests fixtures simple.
"""
from __future__ import annotations

from typing import Any


def cloudtrail_detail(event: dict[str, Any]) -> dict[str, Any]:
    """Return the CloudTrail record itself, regardless of whether `event`
    is the full EventBridge envelope or just the `detail` object."""
    return event.get("detail", event)


def event_name(event: dict[str, Any]) -> str:
    return cloudtrail_detail(event).get("eventName", "")


def event_source(event: dict[str, Any]) -> str:
    return cloudtrail_detail(event).get("eventSource", "")


def event_time(event: dict[str, Any]) -> str:
    detail = cloudtrail_detail(event)
    return detail.get("eventTime") or event.get("time", "")


def aws_region(event: dict[str, Any]) -> str:
    detail = cloudtrail_detail(event)
    return detail.get("awsRegion") or event.get("region", "")


def source_ip(event: dict[str, Any]) -> str:
    return cloudtrail_detail(event).get("sourceIPAddress", "")


def event_id(event: dict[str, Any]) -> str:
    return cloudtrail_detail(event).get("eventID", "")


def user_identity(event: dict[str, Any]) -> dict[str, Any]:
    return cloudtrail_detail(event).get("userIdentity") or {}


def user_identity_type(event: dict[str, Any]) -> str:
    return user_identity(event).get("type", "")


def actor_arn(event: dict[str, Any]) -> str:
    ident = user_identity(event)
    return ident.get("arn") or ident.get("principalId") or "unknown"


def request_parameters(event: dict[str, Any]) -> dict[str, Any]:
    return cloudtrail_detail(event).get("requestParameters") or {}


def response_elements(event: dict[str, Any]) -> dict[str, Any]:
    return cloudtrail_detail(event).get("responseElements") or {}


def is_error(event: dict[str, Any]) -> bool:
    """True if the API call itself failed (errorCode present). Most rules
    only fire on successful calls; D-01 (root_usage) deliberately does
    not filter on this — see rules/root_usage.py's docstring for why."""
    return bool(cloudtrail_detail(event).get("errorCode"))


def raw_excerpt(event: dict[str, Any]) -> dict[str, Any]:
    """A small, stable excerpt of the raw event to carry on the Finding —
    not the entire CloudTrail record (some are large and mostly
    irrelevant to a human triaging an alert), just the fields worth
    keeping for the SNS message body and the evidence log."""
    detail = cloudtrail_detail(event)
    return {
        "eventName": detail.get("eventName"),
        "eventSource": detail.get("eventSource"),
        "requestParameters": request_parameters(event),
        "responseElements": response_elements(event),
        "userIdentity": user_identity(event),
    }
