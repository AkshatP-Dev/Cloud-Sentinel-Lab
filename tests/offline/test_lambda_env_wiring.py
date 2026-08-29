"""
Offline (no AWS credentials needed) regression guard against a real bug
caught during this project's build: lambda/detectors/dispatcher/handler.py
reads LAB_USER_ARN from its environment to decide whether a D-04 finding
belongs to the lab user before invoking the responder, but the detector
Lambda's Terraform environment block did not originally set it — meaning
the automated-response path would have been silently dead on a real
deployment (the detector would find and alert on D-04 findings correctly,
but never invoke the responder), despite every unit test passing.
tests/unit/dispatcher/test_detection_rules.py sets the module attribute
directly via monkeypatch, which correctly exercises _is_lab_user()'s LOGIC
but cannot catch a missing wire-up between Terraform and the Lambda's real
runtime environment — that gap is exactly what tests/live/
test_live_detection_flow.py would eventually have caught (it polls for
the responder's own "Deactivated access key" log line), but only after a
real deployment, and only after the fact.

This test catches the same class of bug for free, offline, before any
deployment: it reads each Lambda handler's own source for the environment
variables it actually consumes, and checks each one is present in that
same function's aws_lambda_function environment block in
terraform/modules/detection/main.tf.

LOG_LEVEL is deliberately excluded — both handlers read it with a safe
default ("INFO") and neither Terraform resource sets it; that's an
intentional optional runtime override, not a required wire, so its
absence is correct rather than a gap.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
LAMBDA_DIR = REPO_ROOT / "lambda"
DETECTION_TF = REPO_ROOT / "terraform" / "modules" / "detection" / "main.tf"

ENV_READ_PATTERN = re.compile(
    r'os\.environ(?:\.get\(\s*["\'](?P<get_name>[A-Z_][A-Z0-9_]*)["\']'
    r'|\[\s*["\'](?P<index_name>[A-Z_][A-Z0-9_]*)["\']\s*\])'
)

# Read with a safe default and never gates behavior — an intentional
# optional override, not something Terraform is required to set.
OPTIONAL_ENV_VARS = {"LOG_LEVEL"}


def _env_vars_read(handler_path: Path) -> set[str]:
    text = handler_path.read_text()
    found = set()
    for m in ENV_READ_PATTERN.finditer(text):
        found.add(m.group("get_name") or m.group("index_name"))
    return found - OPTIONAL_ENV_VARS


def _extract_resource_block(tf_text: str, resource_type: str, resource_name: str) -> str:
    """Return the full text of one `resource "type" "name" { ... }` block,
    matched by brace-depth counting from its opening brace — simple and
    sufficient here because no value in this file's aws_lambda_function
    blocks contains a literal '{' or '}' character. Same spirit as the
    whole-file brace-balance check in scripts/dev/validate_tf_structure.py,
    scoped down to one resource."""
    marker = f'resource "{resource_type}" "{resource_name}"'
    start = tf_text.index(marker)
    brace_start = tf_text.index("{", start)
    depth = 0
    for i in range(brace_start, len(tf_text)):
        if tf_text[i] == "{":
            depth += 1
        elif tf_text[i] == "}":
            depth -= 1
            if depth == 0:
                return tf_text[brace_start : i + 1]
    raise AssertionError(f"Unbalanced braces while extracting {marker} from {DETECTION_TF}")


def _env_vars_set_in_terraform(resource_block: str) -> set[str]:
    env_match = re.search(
        r"environment\s*\{\s*variables\s*=\s*\{(?P<body>.*?)\}\s*\}", resource_block, re.DOTALL
    )
    assert env_match, "expected an environment { variables = { ... } } block"
    keys = re.findall(r"^\s*([A-Z_][A-Z0-9_]*)\s*=", env_match.group("body"), re.MULTILINE)
    return set(keys)


@pytest.mark.parametrize(
    "handler_rel_path,tf_resource_name,label",
    [
        ("detectors/dispatcher/handler.py", "detector", "detector Lambda"),
        ("responders/quarantine/handler.py", "responder", "responder Lambda"),
    ],
)
def test_every_env_var_the_handler_reads_is_wired_in_terraform(handler_rel_path, tf_resource_name, label):
    handler_path = LAMBDA_DIR / handler_rel_path
    referenced = _env_vars_read(handler_path)
    assert referenced, f"expected to find at least one os.environ read in {handler_path}"

    tf_text = DETECTION_TF.read_text()
    block = _extract_resource_block(tf_text, "aws_lambda_function", tf_resource_name)
    wired = _env_vars_set_in_terraform(block)

    missing = referenced - wired
    assert not missing, (
        f"{handler_path} reads {sorted(missing)} from os.environ, but the {label}'s "
        f"aws_lambda_function.{tf_resource_name} resource in {DETECTION_TF} does not set "
        f"{sorted(missing)} in its environment block. A handler that reads an env var "
        f"Terraform never sets silently falls back to that read's default (or empty string) "
        f"on every real invocation — exactly the bug this test exists to catch (see this "
        f"file's module docstring)."
    )
