"""
Shared fixtures for tests/live/ — these tests exercise REAL, deployed AWS
resources and require valid AWS credentials plus a completed
`terraform apply`. They are automatically SKIPPED (not failed) when
either is unavailable, so `pytest tests/` runs cleanly with no AWS access
at all — including the sandbox this project was originally built in,
which had neither AWS credentials nor a terraform binary (see
README.md / the build status notes).

Force-skip explicitly even with a live deployment present via
CLOUDSENTINEL_SKIP_LIVE=1 (e.g. to run the full suite quickly with zero
AWS API calls).
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError, NoCredentialsError

REPO_ROOT = Path(__file__).resolve().parents[2]
ENV_DIR = REPO_ROOT / "terraform" / "environments" / "lab"


def _terraform_outputs() -> dict | None:
    if os.environ.get("CLOUDSENTINEL_SKIP_LIVE") == "1":
        return None
    try:
        result = subprocess.run(
            ["terraform", "output", "-json"],
            cwd=ENV_DIR,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    if not raw:
        return None
    return {k: v.get("value") for k, v in raw.items()}


@pytest.fixture(scope="session")
def tf_outputs():
    outputs = _terraform_outputs()
    if outputs is None:
        pytest.skip(
            "No Terraform outputs available (not deployed, terraform not installed, "
            "or CLOUDSENTINEL_SKIP_LIVE=1) — tests/live/ requires a completed "
            "`terraform apply` in terraform/environments/lab."
        )
    return outputs


@pytest.fixture(scope="session")
def aws_available(tf_outputs):
    try:
        boto3.client("sts", region_name=tf_outputs["aws_region"]).get_caller_identity()
    except (NoCredentialsError, ClientError) as e:
        pytest.skip(f"AWS credentials not usable: {e}")
    return True
