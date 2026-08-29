"""
REQUIRES AWS + a completed `terraform apply` (auto-skipped otherwise —
see tests/live/conftest.py).

Verifies the DEPLOYED CloudTrail trail and S3 bucket actually match what
this project claims: multi-region, log file validation, actively logging,
all four public-access-block settings, versioning enabled, encrypted.
Reading the Terraform source is not proof any of this is actually live in
the account — this test reads the real AWS API responses instead.
"""
from __future__ import annotations

import boto3
import pytest

pytestmark = pytest.mark.live


@pytest.fixture(scope="module")
def cloudtrail_client(tf_outputs, aws_available):
    return boto3.client("cloudtrail", region_name=tf_outputs["aws_region"])


@pytest.fixture(scope="module")
def s3_client(tf_outputs, aws_available):
    return boto3.client("s3", region_name=tf_outputs["aws_region"])


def test_trail_is_multi_region_and_validated(tf_outputs, cloudtrail_client):
    trails = cloudtrail_client.describe_trails(trailNameList=[tf_outputs["trail_arn"]])["trailList"]
    assert len(trails) == 1, f"expected exactly one trail for {tf_outputs['trail_arn']}"
    trail = trails[0]
    assert trail["IsMultiRegionTrail"] is True
    assert trail["LogFileValidationEnabled"] is True
    assert trail["IncludeGlobalServiceEvents"] is True


def test_trail_is_actively_logging(tf_outputs, cloudtrail_client):
    status = cloudtrail_client.get_trail_status(Name=tf_outputs["trail_arn"])
    assert status["IsLogging"] is True


def test_trail_bucket_blocks_all_public_access(tf_outputs, s3_client):
    block = s3_client.get_public_access_block(
        Bucket=tf_outputs["trail_bucket_name"]
    )["PublicAccessBlockConfiguration"]
    assert block["BlockPublicAcls"] is True
    assert block["BlockPublicPolicy"] is True
    assert block["IgnorePublicAcls"] is True
    assert block["RestrictPublicBuckets"] is True


def test_trail_bucket_versioning_enabled(tf_outputs, s3_client):
    versioning = s3_client.get_bucket_versioning(Bucket=tf_outputs["trail_bucket_name"])
    assert versioning.get("Status") == "Enabled"


def test_trail_bucket_encrypted(tf_outputs, s3_client):
    enc = s3_client.get_bucket_encryption(Bucket=tf_outputs["trail_bucket_name"])
    rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
    algorithms = {r["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] for r in rules}
    assert "AES256" in algorithms


def test_trail_bucket_policy_grants_only_cloudtrail_service_principal(tf_outputs, s3_client):
    """A quick sanity check that the bucket policy is the confused-deputy
    -safe standard CloudTrail pattern (Principal is the service, gated by
    aws:SourceArn) — not, say, accidentally left wide open."""
    policy = s3_client.get_bucket_policy(Bucket=tf_outputs["trail_bucket_name"])["Policy"]
    assert "cloudtrail.amazonaws.com" in policy
    assert '"Principal": "*"' not in policy.replace(" ", "")
    assert '"Principal":"*"' not in policy.replace(" ", "")
