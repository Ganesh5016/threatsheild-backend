"""
THREATSHIELD  ·  tests/test_scan.py
Basic API tests — run with: pytest tests/
"""
import pytest
from httpx import AsyncClient, ASGITransport
from main import app

@pytest.mark.asyncio
async def test_health():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        r = await ac.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

@pytest.mark.asyncio
async def test_scan_url_safe():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        r = await ac.post("/api/scan/url", json={"url": "https://github.com"})
    assert r.status_code == 200
    data = r.json()
    assert "risk_score" in data
    assert data["threat_level"] in ("safe", "warn", "danger")

@pytest.mark.asyncio
async def test_scan_url_invalid():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        r = await ac.post("/api/scan/url", json={"url": ""})
    # Empty URL should return validation error
    assert r.status_code in (400, 422)

@pytest.mark.asyncio
async def test_stats_overview():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        r = await ac.get("/api/stats/overview")
    assert r.status_code == 200
    data = r.json()
    assert "total" in data
    assert "safe" in data
    assert "blocked" in data

@pytest.mark.asyncio
async def test_sandbox_status():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        r = await ac.get("/api/sandbox/status")
    assert r.status_code == 200
    assert "vm" in r.json()
