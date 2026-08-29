"""
Offline structural validation of the Terraform tree — wraps
scripts/dev/validate_tf_structure.py as a pytest test so it's part of the
standard `pytest tests/` run. See that script's own docstring for exactly
what it checks (templatefile()/file() wiring, JSON/IAM-grammar validity,
brace balance, module source paths, var.X declarations) and why it exists:
this project's original build sandbox could not install the terraform
binary at all (registry.terraform.io and releases.hashicorp.com were both
blocked by its network egress allowlist) — this is the offline substitute
for `terraform validate` that sandbox could actually run. Once you have a
real terraform binary, run `terraform validate` too (scripts/deploy.sh and
scripts/security_scan.sh both do) — this test does not replace it, it
covers what was checkable before that was ever possible.
"""
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_terraform_structural_validation():
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "dev" / "validate_tf_structure.py")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"Terraform structural validation failed:\n{result.stdout}\n{result.stderr}"
    )
