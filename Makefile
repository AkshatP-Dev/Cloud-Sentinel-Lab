.PHONY: init fmt validate deploy teardown test test-unit test-offline test-live scan simulate clean help

ENV_DIR := terraform/environments/lab

help:
	@echo "CloudSentinel — available targets:"
	@echo "  init         terraform init (in $(ENV_DIR))"
	@echo "  fmt          terraform fmt -recursive terraform/"
	@echo "  validate     terraform validate (in $(ENV_DIR))"
	@echo "  deploy       ./scripts/deploy.sh (two-phase apply)"
	@echo "  teardown     ./scripts/teardown.sh (destroy + verify)"
	@echo "  test         full pytest suite (unit + offline + live; live auto-skips if not deployed)"
	@echo "  test-unit    pytest tests/unit (no AWS needed)"
	@echo "  test-offline pytest tests/offline (no AWS needed)"
	@echo "  test-live    pytest tests/live (requires a deployed environment + AWS credentials)"
	@echo "  scan         ./scripts/security_scan.sh (Checkov + fmt/validate if terraform is installed)"
	@echo "  simulate     ./scripts/simulate_events.sh all (requires a deployed environment)"
	@echo "  clean        remove Python/pytest caches and Terraform build artifacts"

init:
	cd $(ENV_DIR) && terraform init

fmt:
	terraform fmt -recursive terraform/

validate:
	cd $(ENV_DIR) && terraform validate

deploy:
	./scripts/deploy.sh

teardown:
	./scripts/teardown.sh

test:
	pytest

test-unit:
	pytest tests/unit

test-offline:
	pytest tests/offline

test-live:
	pytest tests/live

scan:
	./scripts/security_scan.sh

simulate:
	./scripts/simulate_events.sh all

clean:
	find . -type d -name '__pycache__' -not -path './.git/*' -exec rm -rf {} +
	rm -rf .pytest_cache terraform/modules/detection/build
