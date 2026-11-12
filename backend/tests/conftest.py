import os
import tempfile
from pathlib import Path

import pytest

# Isolated database for the test session; must be set before app modules read settings.
_tmp = tempfile.mkdtemp(prefix="trace-test-")
os.environ["TRACE_DATABASE_PATH"] = str(Path(_tmp) / "test.sqlite")

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def sample():
    return lambda name: (SAMPLES / name).read_text()
