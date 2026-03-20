"""
THREATSHIELD  ·  tests/test_url_scanner.py
Unit tests for URL scanner heuristics (no API keys required)
"""
import pytest
import asyncio
from app.services.url_scanner import URLScanner, _tag_boost, _check_redirect_risk


@pytest.fixture
def scanner():
    return URLScanner()


@pytest.mark.asyncio
async def test_safe_url(scanner):
    result = await scanner._check_heuristics("https://github.com/microsoft/vscode")
    assert result["score"] < 30
    assert "Trusted Domain" in result["tags"] or result["score"] <= 15


@pytest.mark.asyncio
async def test_phishing_url(scanner):
    result = await scanner._check_heuristics("http://paypal-verify-account.suspicious.tk/login")
    assert result["score"] >= 40
    assert len(result["tags"]) > 0


@pytest.mark.asyncio
async def test_url_shortener(scanner):
    result = await scanner._check_heuristics("https://bit.ly/3xYmK9")
    assert result["score"] >= 20
    assert any("shortener" in t.lower() or "URL" in t for t in result["tags"])


@pytest.mark.asyncio
async def test_ip_url(scanner):
    result = await scanner._check_heuristics("http://192.168.1.100/download.exe")
    assert result["score"] >= 25


@pytest.mark.asyncio
async def test_no_https(scanner):
    result = await scanner._check_heuristics("http://legit-site.com")
    assert result["score"] >= 5


def test_tag_boost_with_matching():
    tags  = ["Phishing Pattern", "SSL Spoof"]
    boost = _tag_boost(tags, "phish")
    assert boost == 15


def test_tag_boost_without_matching():
    tags  = ["Adware", "Trackers"]
    boost = _tag_boost(tags, "phish")
    assert boost == 0


def test_redirect_risk_shortener():
    risk = _check_redirect_risk("https://bit.ly/abc")
    assert risk >= 50


def test_redirect_risk_long():
    risk = _check_redirect_risk("https://legit.com/" + "a" * 110)
    assert risk >= 30


def test_redirect_risk_clean():
    risk = _check_redirect_risk("https://google.com")
    assert risk <= 10


@pytest.mark.asyncio
async def test_full_scan_safe(scanner):
    """End-to-end scan with no API keys (heuristics only)."""
    result = await scanner.scan("https://github.com")
    assert "risk_score"   in result
    assert "threat_level" in result
    assert result["threat_level"] in ("safe", "warn", "danger")
    assert 0 <= result["risk_score"] <= 100


@pytest.mark.asyncio
async def test_full_scan_phishing(scanner):
    result = await scanner.scan("http://paypal-secure-login.suspicious.xyz/auth")
    assert result["risk_score"] >= 30
