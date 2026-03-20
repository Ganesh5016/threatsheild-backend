"""
THREATSHIELD  ·  tests/test_api.py
Full API integration tests — run with: pytest tests/ -v
"""
import pytest
from httpx import AsyncClient, ASGITransport
from main import app


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


# ── Health ────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_root(client):
    r = await client.get("/")
    assert r.status_code == 200
    assert "ThreatShield" in r.json()["name"]


@pytest.mark.asyncio
async def test_health(client):
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_api_health(client):
    r = await client.get("/api/health")
    assert r.status_code == 200
    assert "services" in r.json()


# ── Auth ──────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_register_device(client):
    r = await client.post("/api/auth/register", json={"device_name": "Test Device"})
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert "device_id"    in data


@pytest.mark.asyncio
async def test_register_with_device_id(client):
    r = await client.post("/api/auth/register", json={"device_id": "TEST-DEV-001"})
    assert r.status_code == 200
    assert r.json()["device_id"] == "TEST-DEV-001"


# ── URL Scan ──────────────────────────────────────────────
@pytest.mark.asyncio
async def test_scan_url_returns_fields(client):
    r = await client.post("/api/scan/url", json={"url": "https://github.com"})
    assert r.status_code == 200
    data = r.json()
    for field in ["scan_id","scan_type","status","threat_level","risk_score","verdict","tags","meter_scores"]:
        assert field in data, f"Missing field: {field}"


@pytest.mark.asyncio
async def test_scan_url_safe(client):
    r = await client.post("/api/scan/url", json={"url": "https://github.com"})
    assert r.status_code == 200
    assert r.json()["threat_level"] in ("safe", "warn")


@pytest.mark.asyncio
async def test_scan_url_phishing(client):
    r = await client.post("/api/scan/url", json={"url": "http://paypal-verify.suspicious.tk"})
    assert r.status_code == 200
    assert r.json()["risk_score"] >= 20


@pytest.mark.asyncio
async def test_scan_url_empty(client):
    r = await client.post("/api/scan/url", json={"url": ""})
    assert r.status_code in (400, 422)


@pytest.mark.asyncio
async def test_scan_url_without_scheme(client):
    r = await client.post("/api/scan/url", json={"url": "github.com"})
    assert r.status_code == 200   # auto-prefixed with https://


@pytest.mark.asyncio
async def test_scan_email(client):
    r = await client.post("/api/scan/email", json={
        "sender":  "security@paypal-update.com",
        "subject": "Urgent: Your account will be suspended"
    })
    assert r.status_code == 200
    data = r.json()
    assert data["scan_type"] == "email"
    assert data["risk_score"] >= 0


# ── Scan History ──────────────────────────────────────────
@pytest.mark.asyncio
async def test_scan_history(client):
    # First do a scan
    await client.post("/api/scan/url", json={"url": "https://example.com", "device_id": "TEST-001"})
    r = await client.get("/api/scan/history/list?device_id=TEST-001&limit=5")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


@pytest.mark.asyncio
async def test_get_scan_by_id(client):
    scan_r = await client.post("/api/scan/url", json={"url": "https://example.com"})
    scan_id = scan_r.json()["scan_id"]
    r = await client.get(f"/api/scan/{scan_id}")
    assert r.status_code == 200
    assert r.json()["scan_id"] == scan_id


@pytest.mark.asyncio
async def test_get_nonexistent_scan(client):
    r = await client.get("/api/scan/nonexistent-id-12345")
    assert r.status_code == 404


# ── Stats ─────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_stats_overview(client):
    r = await client.get("/api/stats/overview")
    assert r.status_code == 200
    data = r.json()
    for field in ["total","safe","warn","blocked"]:
        assert field in data


@pytest.mark.asyncio
async def test_stats_weekly(client):
    r = await client.get("/api/stats/weekly")
    assert r.status_code == 200
    assert "days" in r.json()
    assert len(r.json()["days"]) == 7


@pytest.mark.asyncio
async def test_stats_threat_types(client):
    r = await client.get("/api/stats/threat-types")
    assert r.status_code == 200
    assert "total" in r.json()
    assert "categories" in r.json()


@pytest.mark.asyncio
async def test_stats_recent_activity(client):
    r = await client.get("/api/stats/recent-activity?limit=5")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


@pytest.mark.asyncio
async def test_stats_top_threats(client):
    r = await client.get("/api/stats/top-threats")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


@pytest.mark.asyncio
async def test_stats_protection_rates(client):
    r = await client.get("/api/stats/protection-rates")
    assert r.status_code == 200
    data = r.json()
    assert "phishing_detection" in data


# ── Sandbox ───────────────────────────────────────────────
@pytest.mark.asyncio
async def test_sandbox_status(client):
    r = await client.get("/api/sandbox/status")
    assert r.status_code == 200
    assert "vm" in r.json()
    assert "heal_protocol" in r.json()


@pytest.mark.asyncio
async def test_sandbox_logs(client):
    r = await client.get("/api/sandbox/logs")
    assert r.status_code == 200
    assert "logs" in r.json()


@pytest.mark.asyncio
async def test_sandbox_behaviors(client):
    r = await client.get("/api/sandbox/behaviors")
    assert r.status_code == 200
    assert "behaviors" in r.json()


@pytest.mark.asyncio
async def test_sandbox_reset(client):
    r = await client.post("/api/sandbox/reset")
    assert r.status_code == 200
    assert r.json()["success"] is True


# ── Alerts ────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_alerts_recent(client):
    r = await client.get("/api/alerts/recent")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


@pytest.mark.asyncio
async def test_alerts_test_push(client):
    r = await client.post("/api/alerts/test")
    assert r.status_code == 200
    assert r.json()["sent"] is True
