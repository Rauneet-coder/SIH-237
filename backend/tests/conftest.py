import os
import pytest

# ── Patch env BEFORE any app module is imported ───────────────────────
# Ensures no asyncpg/greenlet needed for unit tests (health check, etc.)
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["SECRET_KEY"] = "test_secret_key_for_ci_only"

from fastapi.testclient import TestClient
from app.main import app

# ── Sync test client (no DB needed for M0 health tests) ───────────────
@pytest.fixture(scope="module")
def client():
    """Synchronous HTTPX test client — used for M0 smoke tests."""
    with TestClient(app) as c:
        yield c
