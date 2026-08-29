"""
Same pattern as tests/unit/dispatcher/conftest.py, mirrored for the
responder Lambda — see that file's module docstring for the full
explanation of why this can't just be a top-level `import handler` in
each test file (both Lambda packages define their own top-level
handler.py, and Python caches imports by bare module name).
"""
import sys
from pathlib import Path

import pytest

RESPONDER_DIR = Path(__file__).resolve().parents[3] / "lambda" / "responders" / "quarantine"


def _scrub_cache():
    sys.modules.pop("handler", None)


@pytest.fixture(scope="module")
def responder():
    _scrub_cache()
    sys.path.insert(0, str(RESPONDER_DIR))
    import handler

    yield handler

    sys.path.remove(str(RESPONDER_DIR))
    _scrub_cache()
