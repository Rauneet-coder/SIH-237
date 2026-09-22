import os
import pytest

# ── Use mock MongoDB URL so init_db() is skipped in tests ─────────────
os.environ["MONGODB_URL"] = "mongodb://mock:27017"
os.environ["SECRET_KEY"] = "test_secret_key_for_ci_only"

from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture(scope="module")
def client():
    """FastAPI sync test client — no real DB needed for M0 smoke tests."""
    with TestClient(app) as c:
        yield c
