"""
Puts the dispatcher Lambda's own directory at the front of sys.path for
tests in this directory, so `import handler`, `from finding import
Finding`, `import event_utils`, `import rules` resolve exactly the way
they do inside the real Lambda deployment package — see
lambda/detectors/dispatcher/: the Terraform detection module's
archive_file zips this directory's CONTENTS, so handler.py / finding.py /
event_utils.py / rules/ all land at the zip root with no wrapping package
name, and that's the sys.path layout tests need to match.

The responder Lambda (lambda/responders/quarantine/) ALSO defines its own
top-level handler.py. Python caches imported modules by bare name in
sys.modules — without deliberately scrubbing that cache, whichever test
module (this one, or tests/unit/responder/'s) runs FIRST in a given
pytest process would "win", and the other would silently get the wrong
handler.py. That's why the imports below happen lazily, inside a
module-scoped fixture, rather than as a plain top-level `import handler`
in each test file: a top-level import would execute at pytest's
COLLECTION time, before any fixture has run and before sys.path has been
set up at all.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

DISPATCHER_DIR = Path(__file__).resolve().parents[3] / "lambda" / "detectors" / "dispatcher"
_OWN_MODULE_NAMES = ("handler", "finding", "event_utils", "rules")


def _scrub_cache():
    for name in list(sys.modules):
        if name in _OWN_MODULE_NAMES or name.startswith("rules."):
            del sys.modules[name]


@pytest.fixture(scope="module")
def cs():
    """Bundle of the dispatcher's own modules, imported fresh with the
    dispatcher directory on sys.path for the lifetime of this fixture.
    Test functions use cs.handler, cs.rules.<name>, cs.Finding, etc."""
    _scrub_cache()
    sys.path.insert(0, str(DISPATCHER_DIR))
    try:
        import event_utils
        import handler
        import rules
        from finding import Finding, publish_finding
    finally:
        pass  # keep DISPATCHER_DIR on sys.path until teardown below — the
        # imported modules' own internal `import event_utils` etc. calls
        # (inside handler.py, rules/__init__.py) already resolved during
        # the imports above, but leaving the path in place for the
        # fixture's lifetime is simpler and safer than trying to prove
        # nothing lazy-imports later.

    yield SimpleNamespace(
        handler=handler,
        event_utils=event_utils,
        rules=rules,
        Finding=Finding,
        publish_finding=publish_finding,
    )

    sys.path.remove(str(DISPATCHER_DIR))
    _scrub_cache()
