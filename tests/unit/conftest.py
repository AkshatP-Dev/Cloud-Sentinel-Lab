"""
Fake AWS credentials + a default region for every test under tests/unit/.

moto needs SOME region to be resolvable before it can intercept a boto3
call at all — client CONSTRUCTION fails with NoRegionError before moto
gets a chance to intercept anything if none is configured. A real Lambda
execution environment always provides AWS_DEFAULT_REGION automatically;
this sandbox's plain `pytest` invocation does not, so tests supply it.
Fake (not empty) credentials additionally stop boto3 from falling back to
scanning for real credentials (~/.aws/credentials, instance metadata,
etc.) during a unit test run — moto's own documented recommendation.

Scoped to tests/unit/ specifically (this conftest.py, not the top-level
tests/conftest.py) so tests/live/ is completely unaffected — those tests
need the user's REAL AWS credentials and region to reach real AWS, and
must never have them silently overridden.
"""
import pytest


@pytest.fixture(autouse=True)
def fake_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
