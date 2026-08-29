# Cost

## Architecture-level cost choices

CloudSentinel was deliberately designed around AWS services and configurations that are free or
near-free at lab scale, with several explicit trade-offs documented inline in the Terraform (and
cross-referenced from `SECURITY.md`'s Checkov section) rather than defaulted into without thought:

- **EventBridge's native CloudTrail integration**, not a CloudWatch Logs subscription. CloudWatch Logs
  ingestion is billed per GB (~$0.50/GB as of this project's design phase — verify current pricing before
  relying on this number); EventBridge's native integration is free for same-account delivery. This is
  the single biggest cost-shaping decision in the architecture (see `ARCHITECTURE.md`).
- **SSE-S3 (AES-256), not SSE-KMS**, on the CloudTrail bucket, and AWS-owned keys (not customer-managed
  CMKs) on CloudWatch Log groups. A customer-managed KMS key costs roughly $1/month *per key* regardless
  of usage; this project would need several (bucket, both log groups, arguably SNS) for no confidentiality
  benefit to non-regulated lab data that's already encrypted at rest by default. SNS's topic *does* use a
  KMS key (`alias/aws/sns`, the AWS-managed one, not a customer-managed one) — free, no key policy to
  maintain.
- **No VPC placement** for either Lambda. Both functions only call AWS service APIs (SNS/IAM/Lambda) —
  no VPC-private resource, no need for internet egress. Placing them in a VPC would require either a NAT
  Gateway (~$32/month — by far the single most expensive thing this architecture avoids) or VPC
  endpoints, for zero security benefit against this threat model.
- **Reserved concurrency of 5** on both Lambdas — bounds worst-case invocation cost (and blast radius) in
  the event of an unexpected event storm, at no cost during normal, low-volume lab operation.
- **A 14-day CloudWatch Logs retention** and a 90-day (default `var.retention_days`) S3 lifecycle
  expiration on CloudTrail logs, rather than indefinite retention — bounds storage cost from unbounded
  accumulation.
- **No cross-region replication, no second access-logging bucket** on the CloudTrail bucket — both are
  legitimate hardening options for a production account, both add a second bucket's worth of ongoing
  cost, both are disproportionate for a personal lab (see `SECURITY.md`'s Checkov table for the specific
  checks this trades off).

## Estimated monthly cost

**This table is an estimate based on AWS's published pricing structure at design time, not a bill this
project has actually incurred** — nothing has been deployed from this build environment. Treat every
number below as **requires verification** against your actual AWS bill after a real deployment; costs
vary by region and change over time.

| Resource | Basis | Estimated cost |
|---|---|---|
| CloudTrail (management events, one trail) | First trail's management events are free | $0 |
| S3 (CloudTrail log bucket) | A personal lab's log volume is tiny — well under 1 GB/month | ~$0.02–0.05/month |
| Lambda (both functions) | Free tier covers 1M requests + 400,000 GB-seconds/month; a lab's invocation volume is far below that | $0 (within free tier) |
| EventBridge (native CloudTrail integration) | Free for this delivery path | $0 |
| SNS | Free tier covers 1,000 email notifications/month; a lab generates far fewer | $0 (within free tier) |
| CloudWatch Logs | 14-day retention, low volume | ~$0.01–0.05/month |
| AWS Budgets | First 2 budgets/account are free | $0 |
| **Estimated total** | | **well under $1/month**, against the $5/month tripwire |

The $5/month figure (`monthly_budget_usd`) was chosen as a tripwire with real headroom above the
estimated actual cost, not as a "this is what it costs" number — see the mechanics below.

## Why this deploys to us-east-1

The design phase originally proposed `ap-south-1` (Mumbai) as the default region. The build changed
that default to `us-east-1`: AWS Budgets — which `aws_budgets_budget.cost_tripwire` below depends on —
is only served from three regions (`us-east-1`, `us-west-2`, `ca-central-1`), and this stack's single
AWS provider block applies one region to every resource, budget included. `ap-south-1` would have made
the cost tripwire fail to apply. See `terraform/environments/lab/variables.tf`'s `aws_region`
description for the full reasoning and the alternative (a second, aliased provider pinned to
`us-east-1` for just the budget resource, if deploying the rest of the stack to `ap-south-1` matters to
you) — that alternative is not implemented here, `aws_region` just defaults to `us-east-1` for the whole
stack.

## Budget mechanics

`aws_budgets_budget.cost_tripwire` (`terraform/environments/lab/main.tf`) is an **account-wide** COST
budget (not scoped to only CloudSentinel's tagged resources — see `variables.tf`'s
`monthly_budget_usd` description: a tag-scoped budget requires activating cost-allocation tags in
Billing preferences first, a manual console step with up to a 24-hour propagation delay that Terraform
cannot provision). It notifies `var.alert_email` at both 80% and 100% of `monthly_budget_usd`
(`ACTUAL` spend, not forecasted).

`scripts/deploy.sh` applies this resource **first**, in its own `terraform apply -target=...` phase,
before the rest of the stack — see that script's and `main.tf`'s comments for why this is a script-level
guarantee (an explicit two-phase apply), not something Terraform's dependency graph can express on its
own (there's no mechanism to force one resource to apply strictly before other, unrelated resources).
Creation-time cost for every other resource in this stack is $0 regardless of ordering — CloudTrail, S3,
Lambda, EventBridge, and SNS don't bill for merely existing — so what the tripwire actually guards
against is accumulated usage over the days/weeks after deployment, not the ~30 seconds `terraform apply`
itself takes.

## Teardown

Nothing in this project is meant to run indefinitely as a bill-generating background service beyond what
a quick lab deployment costs. `scripts/teardown.sh` destroys everything Terraform created and then
independently verifies (via the Resource Groups Tagging API) that nothing tagged `project=cloudsentinel`
remains — see that script's own caveats about IAM resources sometimes lagging in that API, and manually
double-checking the S3 console and Billing > Budgets. Run it when you're done evaluating this project, or
periodically confirm the AWS Budget hasn't fired, whichever comes first.
