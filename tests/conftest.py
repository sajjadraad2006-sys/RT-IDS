"""Suite-wide isolation for generated application state."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile


# This file is loaded before test modules import backend.config/models. A fresh
# database therefore backs the entire run; data/cyberguard.db is never required.
_TEST_STATE = tempfile.TemporaryDirectory(prefix="cyberguard-pytest-")
os.environ["CG_DB_PATH"] = str(Path(_TEST_STATE.name) / "cyberguard-test.sqlite")

from backend.db.init_db import init_all  # noqa: E402  (environment must be first)

init_all()


def pytest_sessionfinish(session, exitstatus):
    try:
        from backend.db.models import engine
        engine.dispose()
    except Exception:
        pass

