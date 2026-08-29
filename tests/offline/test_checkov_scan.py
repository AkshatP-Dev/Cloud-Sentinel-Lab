"""
Offline (no AWS credentials, no `terraform init` needed) — proves Checkov
is actually wired up and capable of catching a real misconfiguration,
using a small deliberately-insecure fixture that is never deployed
anywhere (tests/fixtures/checkov_known_bad/). This is the "does your
negative test actually detect badness" check — the same philosophy as
Project 1's (HMS Security Lab) hardened-passes/weakened-fails pytest
pattern, applied here to static analysis instead of runtime behavior: a
clean Checkov scan of the real terraform/ tree is only meaningful
evidence if Checkov is demonstrably capable of finding problems when they
exist.

Also runs Checkov against the REAL terraform/ tree and records (does not
hard-fail the build on) the result — see evidence/checkov/ (produced by
scripts/security_scan.sh) and RESULTS.md for the actual findings from a
real run. This test's job is proving the capability, not asserting a
specific finding count that could go stale as the upstream AWS provider
checks Checkov ships evolve.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
KNOWN_BAD_DIR = REPO_ROOT / "tests" / "fixtures" / "checkov_known_bad"

pytestmark = pytest.mark.skipif(
    shutil.which("checkov") is None,
    reason="checkov not installed (pip install checkov --break-system-packages)",
)


def _run_checkov(directory: Path) -> list[dict]:
    result = subprocess.run(
        ["checkov", "-d", str(directory), "--compact", "--output", "json"],
        capture_output=True,
        text=True,
    )
    # checkov exits non-zero when it finds failed checks — expected,
    # informative output, not a subprocess failure. Only empty/unparseable
    # stdout indicates something actually went wrong running it.
    stdout = result.stdout.strip()
    assert stdout, f"checkov produced no output at all (stderr: {result.stderr})"
    data = json.loads(stdout)
    # checkov emits a single object for one framework, or a list of
    # objects when multiple frameworks apply to the scanned directory —
    # normalize to a list either way.
    return data if isinstance(data, list) else [data]


def test_checkov_detects_the_known_bad_fixture():
    reports = _run_checkov(KNOWN_BAD_DIR)
    failed_total = sum(len(r.get("results", {}).get("failed_checks", [])) for r in reports)
    assert failed_total > 0, (
        "Checkov reported zero failed checks against a deliberately insecure fixture "
        "(public-read S3 ACL, no encryption, no versioning, no public access block) — "
        "either checkov is misconfigured, the fixture regressed, or checkov isn't "
        "actually running. A clean scan of the real terraform/ tree is not meaningful "
        "evidence of anything until this test passes."
    )


def test_checkov_runs_against_real_terraform_tree():
    """Presence check, not a pass/fail gate on specific findings — see
    evidence/checkov/ and RESULTS.md for the actual recorded output from a
    real run against this project's own Terraform."""
    reports = _run_checkov(REPO_ROOT / "terraform")
    total_checks = sum(
        len(r.get("results", {}).get("failed_checks", [])) + len(r.get("results", {}).get("passed_checks", []))
        for r in reports
    )
    assert total_checks > 0, "Checkov found no checks at all to run against terraform/ — did the tree move or empty out?"
