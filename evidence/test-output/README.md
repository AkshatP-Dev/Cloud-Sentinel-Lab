# evidence/test-output/

**Status: partially available — see below.** This folder is for saved `pytest` output, particularly
`tests/live/` runs that could not happen in this project's build environment.

What's already true and doesn't need to wait for a deployment (reproduce and save here if you want a
timestamped record of your own run — not required, since `TESTING.md` already states these results):

```bash
pytest tests/unit tests/offline -v > evidence/test-output/unit-offline-$(date -u +%Y%m%dT%H%M%SZ).txt 2>&1
```

What genuinely requires a real deployment and hasn't run yet:

```bash
pytest tests/live -v > evidence/test-output/live-$(date -u +%Y%m%dT%H%M%SZ).txt 2>&1
```

The `tests/live/` capture is the single most important file this folder is waiting on — it's the
automated version of most of the manual evidence collected elsewhere in `evidence/`, including the
permission-boundary `iam:SimulatePrincipalPolicy` checks (`IAM_DESIGN.md` §3.4) and the end-to-end D-04
flow (`INCIDENT_RESPONSE.md`).
