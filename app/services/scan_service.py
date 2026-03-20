"""
THREATSHIELD — app/services/scan_service.py
Orchestrates URL, file, APK and email scans.
Saves results to DB, updates stats.
"""

import asyncio
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update
import logging

from app.models.scan import ScanResult, ScannedFile, BehaviorEvent, ThreatStats, ScanType, ThreatLevel, ScanStatus
from app.services.url_scanner  import URLScanner
from app.services.file_scanner import FileScanner
from app.core.config import settings

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self, db: AsyncSession):
        self.db           = db
        self.url_scanner  = URLScanner()
        self.file_scanner = FileScanner()

    # ── URL Scan ─────────────────────────────────────────
    async def scan_url(
        self,
        url: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_id: Optional[str]  = None,
    ) -> ScanResult:
        started = time.time()

        # Create pending record
        record = ScanResult(
            scan_type   = ScanType.URL,
            status      = ScanStatus.SCANNING,
            input_value = url,
            input_hash  = hashlib.sha256(url.encode()).hexdigest(),
            ip_address  = ip_address,
            user_agent  = user_agent,
            device_id   = device_id,
            scan_started_at = datetime.now(timezone.utc),
        )
        self.db.add(record)
        await self.db.flush()

        try:
            result = await asyncio.wait_for(
                self.url_scanner.scan(url),
                timeout=settings.URL_SCAN_TIMEOUT_SECONDS,
            )
            await self._populate_record(record, result, started)
        except asyncio.TimeoutError:
            record.status        = ScanStatus.TIMEOUT
            record.verdict       = "TIMEOUT"
            record.verdict_detail = "Scan timed out"
        except Exception as e:
            logger.error(f"URL scan failed: {e}")
            record.status        = ScanStatus.FAILED
            record.verdict       = "ERROR"
            record.verdict_detail = str(e)

        await self.db.flush()
        await self._update_daily_stats(record)
        return record

    # ── File Scan ────────────────────────────────────────
    async def scan_file(
        self,
        file_path: str,
        filename:  str,
        file_size: int,
        mime_type: Optional[str] = None,
        ip_address: Optional[str] = None,
        device_id:  Optional[str] = None,
    ) -> ScanResult:
        started = time.time()
        ext     = Path(filename).suffix.lower()
        scan_type = ScanType.APK if ext == ".apk" else ScanType.FILE

        record = ScanResult(
            scan_type   = scan_type,
            status      = ScanStatus.SCANNING,
            input_value = filename,
            input_hash  = None,
            ip_address  = ip_address,
            device_id   = device_id,
            scan_started_at = datetime.now(timezone.utc),
        )
        self.db.add(record)
        await self.db.flush()

        try:
            timeout = settings.APK_SCAN_TIMEOUT_SECONDS if ext == ".apk" else settings.FILE_SCAN_TIMEOUT_SECONDS
            result  = await asyncio.wait_for(
                self.file_scanner.scan(file_path, filename, file_size),
                timeout=timeout,
            )
            await self._populate_record(record, result, started)

            # Store file metadata
            file_info = result.get("file_info", {})
            apk_info  = file_info.get("apk", {})
            scanned_file = ScannedFile(
                scan_id          = record.id,
                filename         = filename,
                original_name    = filename,
                file_size_bytes  = file_size,
                mime_type        = mime_type,
                file_extension   = ext,
                sha256_hash      = file_info.get("sha256"),
                md5_hash         = file_info.get("md5"),
                yara_matches     = result.get("api_results", {}).get("yara", {}).get("matches", []),
                strings_found    = result.get("api_results", {}).get("strings", {}).get("found", []),
                is_apk_file      = (ext == ".apk"),
                apk_package_name = apk_info.get("package_name"),
                apk_version      = apk_info.get("version"),
                apk_permissions  = apk_info.get("permissions", []),
                apk_dangerous_perms = apk_info.get("dangerous_permissions", []),
                auto_deleted     = result.get("auto_deleted", False),
            )
            self.db.add(scanned_file)

        except asyncio.TimeoutError:
            record.status        = ScanStatus.TIMEOUT
            record.verdict       = "TIMEOUT"
            record.verdict_detail = "Scan timed out"
        except Exception as e:
            logger.error(f"File scan failed: {e}")
            record.status        = ScanStatus.FAILED
            record.verdict       = "ERROR"
            record.verdict_detail = str(e)

        await self.db.flush()
        await self._update_daily_stats(record)
        return record

    # ── Email Scan (basic) ────────────────────────────────
    async def scan_email(self, sender: str, subject: str = "", device_id: Optional[str] = None) -> ScanResult:
        """Analyse email sender / subject for phishing indicators."""
        combined = f"{sender} {subject}"
        # Reuse URL scanner heuristics on email content
        record = ScanResult(
            scan_type   = ScanType.EMAIL,
            status      = ScanStatus.SCANNING,
            input_value = combined[:512],
            device_id   = device_id,
            scan_started_at = datetime.now(timezone.utc),
        )
        self.db.add(record)
        await self.db.flush()

        started = time.time()
        try:
            heuristic = await self.url_scanner._check_heuristics(sender)
            score     = heuristic.get("score", 0)
            tags      = heuristic.get("tags", [])
            # Extra email-specific checks
            if any(w in subject.lower() for w in ["urgent","verify","suspended","locked","unusual activity"]):
                score += 20
                tags.append("Urgent Language")
            if any(c in sender for c in ["@gmail.com", "@yahoo.com", "@hotmail.com"]) and "support" in sender.lower():
                score += 15
                tags.append("Free Mail Impersonation")

            score = min(score, 100)
            record.risk_score   = score
            record.threat_level = ThreatLevel.DANGER if score >= 65 else ThreatLevel.WARN if score >= 30 else ThreatLevel.SAFE
            record.verdict      = "THREAT DETECTED" if score >= 65 else "SUSPICIOUS" if score >= 30 else "SAFE"
            record.verdict_detail = "Phishing email detected." if score >= 65 else "Suspicious email indicators." if score >= 30 else "Email appears safe."
            record.threat_tags  = tags
            record.status       = ScanStatus.COMPLETED
            record.scan_finished_at = datetime.now(timezone.utc)
            record.scan_duration_ms = int((time.time() - started) * 1000)
        except Exception as e:
            record.status = ScanStatus.FAILED
            record.verdict = "ERROR"

        await self.db.flush()
        await self._update_daily_stats(record)
        return record

    # ── Get Scan History ─────────────────────────────────
    async def get_scan_history(self, device_id: Optional[str] = None, limit: int = 20) -> list:
        q = select(ScanResult).order_by(ScanResult.created_at.desc()).limit(limit)
        if device_id:
            q = q.where(ScanResult.device_id == device_id)
        result = await self.db.execute(q)
        return result.scalars().all()

    # ── Get Stats ─────────────────────────────────────────
    async def get_stats(self, days: int = 7) -> dict:
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        result = await self.db.execute(
            select(
                func.count(ScanResult.id).label("total"),
                func.sum((ScanResult.threat_level == ThreatLevel.SAFE).cast(int)).label("safe"),
                func.sum((ScanResult.threat_level == ThreatLevel.WARN).cast(int)).label("warn"),
                func.sum((ScanResult.threat_level == ThreatLevel.DANGER).cast(int)).label("blocked"),
            ).where(ScanResult.created_at >= cutoff)
        )
        row = result.one()
        return {
            "total":   row.total   or 0,
            "safe":    row.safe    or 0,
            "warn":    row.warn    or 0,
            "blocked": row.blocked or 0,
        }

    # ── Private Helpers ───────────────────────────────────
    async def _populate_record(self, record: ScanResult, result: dict, started: float):
        level_map = {"safe": ThreatLevel.SAFE, "warn": ThreatLevel.WARN, "danger": ThreatLevel.DANGER}
        record.risk_score      = result.get("risk_score", 0)
        record.threat_level    = level_map.get(result.get("threat_level", "safe"), ThreatLevel.SAFE)
        record.verdict         = result.get("verdict", "SAFE")
        record.verdict_detail  = result.get("verdict_detail", "")
        record.threat_tags     = result.get("tags", [])
        record.meter_scores    = result.get("meter_scores", {})
        record.api_results     = result.get("api_results", {})
        record.status          = ScanStatus.COMPLETED
        record.scan_finished_at = datetime.now(timezone.utc)
        record.scan_duration_ms = int((time.time() - started) * 1000)

    async def _update_daily_stats(self, record: ScanResult):
        try:
            today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            result = await self.db.execute(select(ThreatStats).where(ThreatStats.date == today))
            stats  = result.scalar_one_or_none()
            if not stats:
                stats = ThreatStats(date=today)
                self.db.add(stats)
                await self.db.flush()

            stats.total_scans += 1
            if record.threat_level == ThreatLevel.SAFE:
                stats.safe_count += 1
            elif record.threat_level == ThreatLevel.WARN:
                stats.warn_count += 1
            elif record.threat_level == ThreatLevel.DANGER:
                stats.danger_count += 1
                if "phish" in " ".join(record.threat_tags or []).lower():
                    stats.phishing_count += 1
                elif "malware" in " ".join(record.threat_tags or []).lower():
                    stats.malware_count += 1
        except Exception as e:
            logger.warning(f"Stats update failed: {e}")
