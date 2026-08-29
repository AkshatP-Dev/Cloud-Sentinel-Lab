"""
CloudSentinel test suite layout:

  tests/unit/dispatcher/  — pure logic, no AWS credentials needed. Each of
                             the 5 rules plus the dispatcher's own
                             routing/multi-match/error-handling/
                             responder-invocation decisions. SNS/Lambda
                             boto3 calls are stubbed with plain mocks.

  tests/unit/responder/   — pure logic, no AWS credentials needed, EXCEPT
                             that it uses moto (an in-memory fake AWS) to
                             exercise real IAM state transitions — a real
                             fake user gets a real fake access key
                             deactivated, not just a mocked function call.

  tests/offline/          — no AWS credentials needed. Structural/semantic
                             validation of the Terraform tree and IAM
                             policy documents, plus a Checkov run against
                             both this project's real Terraform and a
                             small deliberately-insecure fixture (proving
                             Checkov is actually capable of catching
                             something, not just silently passing).

  tests/live/             — REQUIRES real AWS credentials and a completed
                             `terraform apply`. Auto-skipped (not failed)
                             when neither is available — see
                             tests/live/conftest.py. This is where the
                             project's central security claim (the
                             permission boundary redesign) gets verified
                             empirically against live IAM, via
                             iam:SimulatePrincipalPolicy.

tests/unit/dispatcher/ and tests/unit/responder/ both need their own
local conftest.py, not a shared one here — see the module docstring on
tests/unit/dispatcher/conftest.py for why (both Lambda packages define a
top-level handler.py; Python caches imports by bare module name, so a
single global sys.path setup would let whichever test module runs first
silently "win" the name).
"""
