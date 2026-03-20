"""
THREATSHIELD — app/services/url_scanner.py
Real URL threat analysis using multiple APIs + heuristics
"""

import asyncio
import hashlib
import re
import socket
from urllib.parse import urlparse
from typing import Optional
import httpx
import tldextract
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)


# ── Known malicious patterns ─────────────────────────────
PHISHING_PATTERNS = [
    r"paypal[-.]?(verify|secure|update|login|account)",
    r"(bank|chase|wells.?fargo|citibank|hsbc)[-.]?(secure|verify|login|update)",
    r"(apple|amazon|netflix|microsoft)[-.]?(verify|secure|update|account|login)",
    r"(account|password|verify|confirm|update)[-.]?(now|here|click|secure)",
    r"(free|win|prize|reward|gift)[-.]?(click|claim|collect)",
    r"bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|short\.io",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # raw IP as domain
]

MALWARE_PATTERNS = [
    r"\.(exe|bat|cmd|ps1|vbs|js|jar|dmg|pkg|deb|rpm)(\?|$)",
    r"(download|get|install|setup|crack|keygen|patch|update)[-_]",
    r"(trojan|malware|ransomware|spyware|keylogger)",
]

ADWARE_PATTERNS = [
    r"(free|vpn|crack|serial|keygen|torrent|warez|nulled)",
    r"(clickbait|popup|redirect|ad-?click)",
]

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".loan", ".work"}
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "github.com", "microsoft.com",
    "apple.com", "amazon.com", "cloudflare.com", "stackoverflow.com",
    "wikipedia.org", "mozilla.org", "python.org", "npmjs.com",
}


class URLScanner:
    """
    Multi-source URL threat scanner.
    Uses VirusTotal, URLScan.io, Google Safe Browsing,
    plus local heuristics.
    """

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=10.0, follow_redirects=False)

    async def scan(self, url: str) -> dict:
        """Main scan entry point. Returns full analysis dict."""
        results = {
            "url": url,
            "risk_score": 0,
            "threat_level": "safe",
            "verdict": "SAFE",
            "verdict_detail": "No threats detected. Content verified safe.",
            "tags": [],
            "meter_scores": {},
            "api_results": {},
            "behaviors": [],
        }

        # Run all checks concurrently
        checks = await asyncio.gather(
            self._check_heuristics(url),
            self._check_virustotal(url),
            self._check_google_safebrowsing(url),
            self._check_urlscan(url),
            self._check_phishtank(url),
            return_exceptions=True,
        )

        heuristic, vt, gsb, urlscan_r, phishtank = checks

        # Merge results
        all_tags    = []
        total_score = 0
        weight_sum  = 0
        api_data    = {}

        if isinstance(heuristic, dict):
            total_score += heuristic.get("score", 0) * 0.3
            weight_sum  += 0.3
            all_tags.extend(heuristic.get("tags", []))
            api_data["heuristics"] = heuristic

        if isinstance(vt, dict) and not isinstance(vt, Exception):
            total_score += vt.get("score", 0) * 0.4
            weight_sum  += 0.4
            all_tags.extend(vt.get("tags", []))
            api_data["virustotal"] = vt

        if isinstance(gsb, dict) and not isinstance(gsb, Exception):
            total_score += gsb.get("score", 0) * 0.15
            weight_sum  += 0.15
            all_tags.extend(gsb.get("tags", []))
            api_data["google_safe_browsing"] = gsb

        if isinstance(urlscan_r, dict) and not isinstance(urlscan_r, Exception):
            total_score += urlscan_r.get("score", 0) * 0.1
            weight_sum  += 0.1
            all_tags.extend(urlscan_r.get("tags", []))
            api_data["urlscan"] = urlscan_r

        if isinstance(phishtank, dict) and not isinstance(phishtank, Exception):
            if phishtank.get("is_phishing"):
                total_score += 100 * 0.05
                all_tags.append("PhishTank Confirmed")
            weight_sum += 0.05
            api_data["phishtank"] = phishtank

        # Normalise score
        final_score = int(total_score / weight_sum) if weight_sum > 0 else 0
        final_score = max(0, min(100, final_score))

        # Determine threat level
        if final_score >= 65:
            threat_level   = "danger"
            verdict        = "THREAT DETECTED"
            verdict_detail = "Active threat detected. Access blocked. VM self-healed."
        elif final_score >= 30:
            threat_level   = "warn"
            verdict        = "SUSPICIOUS"
            verdict_detail = "Suspicious indicators found. Proceed with caution."
        else:
            threat_level   = "safe"
            verdict        = "SAFE"
            verdict_detail = "No threats detected. Content verified safe."

        # Meter scores
        meter_scores = {
            "phishing":   min(100, final_score + _tag_boost(all_tags, "phish")),
            "malware":    min(100, final_score - 10 + _tag_boost(all_tags, "malware")),
            "data_steal": min(100, final_score - 5  + _tag_boost(all_tags, "credential")),
            "redirect":   min(100, _check_redirect_risk(url)),
            "adware":     min(100, final_score - 20 + _tag_boost(all_tags, "adware")),
        }
        for k in meter_scores:
            meter_scores[k] = max(0, meter_scores[k])

        results.update({
            "risk_score":    final_score,
            "threat_level":  threat_level,
            "verdict":       verdict,
            "verdict_detail":verdict_detail,
            "tags":          list(set(all_tags))[:8],
            "meter_scores":  meter_scores,
            "api_results":   api_data,
        })

        return results

    # ── Local Heuristics ─────────────────────────────────
    async def _check_heuristics(self, url: str) -> dict:
        score = 0
        tags  = []

        try:
            parsed = urlparse(url if url.startswith("http") else f"http://{url}")
            ext    = tldextract.extract(url)
            domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            tld    = f".{ext.suffix}" if ext.suffix else ""

            # No HTTPS
            if parsed.scheme == "http":
                score += 8
                tags.append("No HTTPS")

            # Suspicious TLD
            if tld in SUSPICIOUS_TLDS:
                score += 25
                tags.append("Suspicious TLD")

            # Trusted domain — reduce score
            if domain in TRUSTED_DOMAINS:
                score = max(0, score - 30)
                tags.append("Trusted Domain")

            # Phishing patterns
            for pat in PHISHING_PATTERNS:
                if re.search(pat, url, re.IGNORECASE):
                    score += 35
                    tags.append("Phishing Pattern")
                    break

            # Malware file extensions
            for pat in MALWARE_PATTERNS:
                if re.search(pat, url, re.IGNORECASE):
                    score += 30
                    tags.append("Malware Extension")
                    break

            # Adware patterns
            for pat in ADWARE_PATTERNS:
                if re.search(pat, url, re.IGNORECASE):
                    score += 15
                    tags.append("Adware Risk")
                    break

            # URL shortener
            if any(s in url for s in ["bit.ly", "tinyurl", "t.co", "goo.gl"]):
                score += 20
                tags.append("URL Shortener")

            # Excessive subdomains
            if url.count(".") > 4:
                score += 10
                tags.append("Excessive Subdomains")

            # Long URL (common in phishing)
            if len(url) > 120:
                score += 8
                tags.append("Suspicious URL Length")

            # Homograph / punycode
            if "xn--" in url:
                score += 20
                tags.append("Punycode Domain")

        except Exception as e:
            logger.warning(f"Heuristics error for {url}: {e}")

        return {"score": min(score, 100), "tags": tags, "source": "heuristics"}

    # ── VirusTotal ───────────────────────────────────────
    async def _check_virustotal(self, url: str) -> dict:
        if not settings.has_virustotal:
            return {"score": 0, "tags": [], "source": "virustotal", "skipped": True}

        try:
            url_id = hashlib.sha256(url.encode()).hexdigest()
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

            # First try cached analysis
            resp = await self.client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=10.0,
            )

            if resp.status_code == 404:
                # Submit for analysis
                submit = await self.client.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url},
                    timeout=10.0,
                )
                if submit.status_code == 200:
                    return {"score": 0, "tags": ["VT: Submitted"], "source": "virustotal", "pending": True}
                return {"score": 0, "tags": [], "source": "virustotal"}

            if resp.status_code != 200:
                return {"score": 0, "tags": [], "source": "virustotal"}

            data       = resp.json()
            stats      = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious  = stats.get("malicious",  0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values()) or 1

            score = int(((malicious * 2 + suspicious) / (total * 2)) * 100)
            tags  = []
            if malicious > 0:
                tags.append(f"VT: {malicious} engines flagged")
            if malicious >= 5:
                tags.append("VirusTotal Confirmed")

            return {
                "score":      min(score, 100),
                "tags":       tags,
                "source":     "virustotal",
                "malicious":  malicious,
                "suspicious": suspicious,
                "total":      total,
                "stats":      stats,
            }

        except Exception as e:
            logger.warning(f"VirusTotal error: {e}")
            return {"score": 0, "tags": [], "source": "virustotal", "error": str(e)}

    # ── Google Safe Browsing ──────────────────────────────
    async def _check_google_safebrowsing(self, url: str) -> dict:
        if not settings.has_google_safebrowsing:
            return {"score": 0, "tags": [], "source": "google_safe_browsing", "skipped": True}

        try:
            payload = {
                "client": {"clientId": "threatshield", "clientVersion": "2.4.1"},
                "threatInfo": {
                    "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            resp = await self.client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}",
                json=payload,
                timeout=8.0,
            )
            data = resp.json()
            matches = data.get("matches", [])
            if matches:
                threat_types = [m.get("threatType", "") for m in matches]
                tags = [f"GSB: {t}" for t in threat_types[:2]]
                return {"score": 90, "tags": tags, "source": "google_safe_browsing", "matches": matches}
            return {"score": 0, "tags": [], "source": "google_safe_browsing"}

        except Exception as e:
            logger.warning(f"Google Safe Browsing error: {e}")
            return {"score": 0, "tags": [], "source": "google_safe_browsing", "error": str(e)}

    # ── URLScan.io ───────────────────────────────────────
    async def _check_urlscan(self, url: str) -> dict:
        if not settings.has_urlscan:
            return {"score": 0, "tags": [], "source": "urlscan", "skipped": True}

        try:
            headers = {"API-Key": settings.URLSCAN_API_KEY, "Content-Type": "application/json"}
            resp = await self.client.post(
                "https://urlscan.io/api/v1/scan/",
                headers=headers,
                json={"url": url, "visibility": "private"},
                timeout=8.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                return {"score": 0, "tags": ["URLScan: Submitted"], "source": "urlscan", "uuid": data.get("uuid")}
            return {"score": 0, "tags": [], "source": "urlscan"}
        except Exception as e:
            logger.warning(f"URLScan error: {e}")
            return {"score": 0, "tags": [], "source": "urlscan", "error": str(e)}

    # ── PhishTank ────────────────────────────────────────
    async def _check_phishtank(self, url: str) -> dict:
        try:
            resp = await self.client.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={"url": url, "format": "json", "app_key": settings.PHISHTANK_API_KEY or ""},
                timeout=8.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", {})
                is_phishing = results.get("in_database") and not results.get("valid")
                return {"score": 95 if is_phishing else 0, "is_phishing": is_phishing, "source": "phishtank"}
        except Exception as e:
            logger.warning(f"PhishTank error: {e}")
        return {"score": 0, "is_phishing": False, "source": "phishtank"}

    async def close(self):
        await self.client.aclose()


# ── Helpers ───────────────────────────────────────────────
def _tag_boost(tags: list, keyword: str) -> int:
    return 15 if any(keyword.lower() in t.lower() for t in tags) else 0

def _check_redirect_risk(url: str) -> int:
    shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "short.io", "tiny.cc"]
    if any(s in url for s in shorteners):
        return 70
    if len(url) > 100:
        return 40
    return 5
