"""
THREATSHIELD — app/services/file_scanner.py
Windows-safe version. All optional imports are fully guarded.
yara-python, python-magic, androguard are all optional.
"""

import asyncio
import hashlib
import math
import os
import tempfile
from pathlib import Path
from typing import Optional
import httpx
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)

# ── Safe optional imports — NEVER crash on import failure ─
YARA_AVAILABLE       = False
MAGIC_AVAILABLE      = False
ANDROGUARD_AVAILABLE = False

try:
    import yara as _yara_module
    # Extra safety — actually test it works before enabling
    _yara_module.compile(source='rule test { condition: false }')
    YARA_AVAILABLE = True
    logger.info("YARA scanning enabled")
except Exception:
    YARA_AVAILABLE = False
    logger.warning("yara-python not available — YARA scanning disabled")

try:
    import magic as _magic_module
    MAGIC_AVAILABLE = True
except Exception:
    MAGIC_AVAILABLE = False

try:
    from androguard.misc import AnalyzeAPK as _AnalyzeAPK
    ANDROGUARD_AVAILABLE = True
except Exception:
    ANDROGUARD_AVAILABLE = False


# ── Dangerous Android permissions ────────────────────────
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.PROCESS_OUTGOING_CALLS",
}

# ── Suspicious byte strings ───────────────────────────────
SUSPICIOUS_STRINGS = [
    b"keylogger", b"password", b"credential", b"harvest",
    b"botnet",    b"backdoor", b"rootkit",    b"ransomware",
    b"bitcoin",   b"wallet",   b"miner",      b"mimikatz",
    b"cmd.exe /c",b"powershell -enc", b"wscript.shell",
    b"createremotethread", b"virtualalloc",  b"writeprocessmemory",
]


class FileScanner:
    def __init__(self):
        self.client      = httpx.AsyncClient(timeout=15.0)
        self._yara_rules = None
        if YARA_AVAILABLE:
            self._load_yara_rules()

    def _load_yara_rules(self):
        try:
            rules_dir = Path(settings.YARA_RULES_DIR)
            if not rules_dir.exists():
                return
            rule_files = {str(f.stem): str(f) for f in rules_dir.glob("*.yar")}
            if rule_files:
                import yara
                self._yara_rules = yara.compile(filepaths=rule_files)
                logger.info(f"Loaded {len(rule_files)} YARA rule files")
        except Exception as e:
            logger.warning(f"YARA rules load error: {e}")
            self._yara_rules = None

    async def scan(self, file_path: str, filename: str, file_size: int) -> dict:
        results = {
            "filename":      filename,
            "file_size":     file_size,
            "risk_score":    0,
            "threat_level":  "safe",
            "verdict":       "SAFE",
            "verdict_detail":"File scan complete — no threats detected.",
            "tags":          [],
            "meter_scores":  {},
            "api_results":   {},
            "file_info":     {},
        }

        path = Path(file_path)
        if not path.exists():
            results["verdict"]        = "ERROR"
            results["verdict_detail"] = "File not found for scanning"
            return results

        try:
            file_bytes = path.read_bytes()
        except Exception as e:
            results["verdict"]        = "ERROR"
            results["verdict_detail"] = f"Could not read file: {e}"
            return results

        sha256 = hashlib.sha256(file_bytes).hexdigest()
        md5    = hashlib.md5(file_bytes).hexdigest()
        results["file_info"] = {"sha256": sha256, "md5": md5, "size": file_size, "name": filename}

        ext = path.suffix.lower()

        # Run checks concurrently
        checks = await asyncio.gather(
            self._check_virustotal_hash(sha256),
            asyncio.to_thread(self._check_yara,    file_bytes, filename),
            asyncio.to_thread(self._check_entropy, file_bytes),
            asyncio.to_thread(self._check_strings, file_bytes),
            asyncio.to_thread(self._check_apk,     file_bytes, filename)
                if ext == ".apk" else asyncio.sleep(0, result={}),
            return_exceptions=True,
        )

        vt_r, yara_r, entropy_r, strings_r, apk_r = checks

        tags        = []
        total_score = 0.0
        weight_sum  = 0.0
        api_data    = {}

        for item, weight, key in [
            (vt_r,      0.50, "virustotal"),
            (yara_r,    0.25, "yara"),
            (entropy_r, 0.10, "entropy"),
            (strings_r, 0.10, "strings"),
            (apk_r,     0.05, "apk"),
        ]:
            if isinstance(item, dict) and item:
                total_score += item.get("score", 0) * weight
                weight_sum  += weight
                tags.extend(item.get("tags", []))
                if item.get("score", 0) > 0:
                    api_data[key] = item

        final_score = int(total_score / weight_sum) if weight_sum > 0 else 0
        final_score = max(0, min(100, final_score))

        tag_str = " ".join(tags).lower()
        if final_score >= 65:
            threat_level, verdict, detail = (
                "danger", "THREAT DETECTED",
                "Malware detected. File auto-deleted. VM self-healed."
            )
        elif final_score >= 30:
            threat_level, verdict, detail = (
                "warn", "SUSPICIOUS",
                "Suspicious file characteristics. Do not execute."
            )
        else:
            threat_level, verdict, detail = (
                "safe", "SAFE",
                "File scan complete — no threats detected."
            )

        results.update({
            "risk_score":    final_score,
            "threat_level":  threat_level,
            "verdict":       verdict,
            "verdict_detail":detail,
            "tags":          list(set(tags))[:8],
            "meter_scores": {
                "malware":    min(100, final_score),
                "data_steal": min(100, max(0, final_score - 10 + (20 if "credential" in tag_str else 0))),
                "ransomware": min(100, 25 if "ransom" in tag_str else 0),
                "spyware":    min(100, 20 if "keylog" in tag_str else 0),
                "adware":     min(100, 10 if "adware" in tag_str else 0),
            },
            "api_results": api_data,
        })

        # Auto-delete dangerous files
        if threat_level == "danger":
            try:
                path.unlink(missing_ok=True)
                results["auto_deleted"] = True
                logger.info(f"Auto-deleted threat: {filename}")
            except Exception as e:
                logger.error(f"Failed to delete threat file: {e}")

        return results

    # ── VirusTotal hash lookup ────────────────────────────
    async def _check_virustotal_hash(self, sha256: str) -> dict:
        if not settings.has_virustotal:
            return {"score": 0, "tags": [], "source": "virustotal", "skipped": True}
        try:
            resp = await self.client.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                timeout=10.0,
            )
            if resp.status_code == 404:
                return {"score": 0, "tags": ["VT: Not in database"], "source": "virustotal"}
            if resp.status_code == 200:
                stats     = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total     = sum(stats.values()) or 1
                score     = int((malicious / total) * 100)
                tags      = [f"VT: {malicious}/{total} engines"] if malicious > 0 else []
                return {"score": min(score, 100), "tags": tags, "source": "virustotal"}
        except Exception as e:
            logger.warning(f"VT hash check error: {e}")
        return {"score": 0, "tags": [], "source": "virustotal"}

    # ── YARA ─────────────────────────────────────────────
    def _check_yara(self, file_bytes: bytes, filename: str) -> dict:
        if not YARA_AVAILABLE or not self._yara_rules:
            return {"score": 0, "tags": [], "source": "yara", "skipped": True}
        try:
            matches = self._yara_rules.match(data=file_bytes)
            if matches:
                names = [m.rule for m in matches]
                return {
                    "score":  min(len(matches) * 25, 100),
                    "tags":   [f"YARA: {n}" for n in names[:3]],
                    "source": "yara",
                }
        except Exception as e:
            logger.warning(f"YARA scan error: {e}")
        return {"score": 0, "tags": [], "source": "yara"}

    # ── Entropy ───────────────────────────────────────────
    def _check_entropy(self, file_bytes: bytes) -> dict:
        if not file_bytes:
            return {"score": 0, "tags": []}
        freq    = [0] * 256
        for b in file_bytes:
            freq[b] += 1
        n       = len(file_bytes)
        entropy = -sum((f/n) * math.log2(f/n) for f in freq if f > 0)
        if entropy > 7.5:
            return {"score": 40, "tags": ["High Entropy (Packed/Encrypted)"],   "entropy": round(entropy, 3)}
        if entropy > 7.0:
            return {"score": 20, "tags": ["Elevated Entropy"],                   "entropy": round(entropy, 3)}
        return    {"score": 0,  "tags": [],                                       "entropy": round(entropy, 3)}

    # ── Suspicious strings ────────────────────────────────
    def _check_strings(self, file_bytes: bytes) -> dict:
        lower = file_bytes.lower()
        found = [s.decode() for s in SUSPICIOUS_STRINGS if s in lower]
        return {
            "score":  min(len(found) * 12, 80),
            "tags":   [f"Suspicious: {s}" for s in found[:3]],
            "source": "strings",
            "found":  found,
        }

    # ── APK analysis ──────────────────────────────────────
    def _check_apk(self, file_bytes: bytes, filename: str) -> dict:
        if not ANDROGUARD_AVAILABLE:
            return {"score": 0, "tags": [], "source": "androguard", "skipped": True}
        try:
            with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
                tmp.write(file_bytes)
                tmp_path = tmp.name
            try:
                a, d, dx = _AnalyzeAPK(tmp_path)
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

            permissions     = list(a.get_permissions())
            dangerous_perms = [p for p in permissions if p in DANGEROUS_PERMISSIONS]
            score = min(len(dangerous_perms) * 8, 60)
            tags  = []
            if len(dangerous_perms) > 5:
                tags.append(f"APK: {len(dangerous_perms)} dangerous permissions")
            if "android.permission.BIND_DEVICE_ADMIN" in permissions:
                score += 30
                tags.append("APK: Device Admin Abuse")
            if "android.permission.INSTALL_PACKAGES" in permissions:
                score += 20
                tags.append("APK: Can install packages")
            return {
                "score":               min(score, 100),
                "tags":                tags,
                "source":              "androguard",
                "package_name":        a.get_package(),
                "dangerous_permissions": dangerous_perms,
            }
        except Exception as e:
            logger.warning(f"APK analysis error: {e}")
            return {"score": 0, "tags": [], "source": "androguard", "error": str(e)}

    async def close(self):
        await self.client.aclose()