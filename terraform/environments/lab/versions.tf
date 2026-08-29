terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region

  # Belt-and-suspenders alongside the explicit `tags = { project =
  # "cloudsentinel" }` already set on most resources in the child modules:
  # default_tags fills in tags on anything that doesn't set its own, and
  # the AWS provider merges rather than overwrites, so the two don't
  # conflict.
  default_tags {
    tags = {
      project    = "cloudsentinel"
      managed_by = "terraform"
    }
  }
}
