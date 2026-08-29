"""
rules — the five CloudSentinel detection rules.

Each submodule exposes a `check(event) -> Finding | None` function plus
RULE_ID / RULE_NAME constants. ALL_RULES is the list handler.py iterates
over for every incoming CloudTrail event — adding a sixth detection means
adding one file here and one line below; nothing in handler.py changes.
"""
from . import (
    access_key_created,
    bucket_exposure,
    logging_tamper,
    privilege_escalation,
    root_usage,
)

ALL_RULES = [
    root_usage.check,
    logging_tamper.check,
    privilege_escalation.check,
    access_key_created.check,
    bucket_exposure.check,
]
