"""
THREATSHIELD  ·  tests/conftest.py
Shared pytest fixtures — sets up a clean test database.
"""
import asyncio
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.core.database import init_db, drop_db


@pytest.fixture(scope="session")
def event_loop():
    """Single event loop for entire test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_test_db():
    """Create test database tables before all tests, drop after."""
    # Use SQLite for tests — no PostgreSQL needed
    import os
    os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_threatshield.db"
    await init_db()
    yield
    await drop_db()
    import os
    try:
        os.remove("./test_threatshield.db")
    except FileNotFoundError:
        pass


@pytest_asyncio.fixture
async def client():
    """Async HTTP test client for each test."""
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def scanned_url(client):
    """A pre-created safe scan result for use in tests."""
    r = await client.post("/api/scan/url", json={"url": "https://github.com", "device_id": "FIXTURE-DEV"})
    return r.json()
