# evidence/terraform-validate/

**Status: empty — REQUIRES VERIFICATION.** No `terraform` binary was available in this project's build
environment (see `TESTING.md`), so none of the commands below have been run yet.

Capture here, after a real deployment:

```bash
terraform fmt -check -recursive terraform/ > evidence/terraform-validate/fmt-check-$(date -u +%Y%m%dT%H%M%SZ).txt 2>&1
cd terraform/environments/lab
terraform validate > ../../../evidence/terraform-validate/validate-$(date -u +%Y%m%dT%H%M%SZ).txt 2>&1
terraform plan > ../../../evidence/terraform-validate/plan-post-apply-$(date -u +%Y%m%dT%H%M%SZ).txt 2>&1
```

The `plan` capture should be taken **after** a completed `terraform apply` — an empty diff
("No changes.") is the meaningful evidence: it shows the deployed state matches the source exactly, not
just that the syntax is valid.

What was actually checked without a `terraform` binary: `scripts/dev/validate_tf_structure.py` (see
`TESTING.md`) — a real but narrower offline substitute. Its own output is not duplicated here; it's part
of the standard `pytest tests/offline` run.
