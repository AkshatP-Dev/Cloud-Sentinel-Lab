# Deliberately insecure — NEVER deployed anywhere, NEVER referenced by any
# real environment/module in this repository. This exists only so
# tests/offline/test_checkov_scan.py can prove Checkov is actually capable
# of catching a real misconfiguration before trusting a clean scan of the
# real terraform/ tree as meaningful evidence of anything.
#
# Deliberately bad in several independent ways: a public-read ACL, no
# versioning, no encryption, no public access block at all.

resource "aws_s3_bucket" "known_bad_example" {
  bucket = "checkov-known-bad-example-do-not-deploy"
}

resource "aws_s3_bucket_acl" "known_bad_example" {
  bucket = aws_s3_bucket.known_bad_example.id
  acl    = "public-read"
}
