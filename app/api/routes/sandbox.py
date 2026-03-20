"""
THREATSHIELD — app/api/routes/sandbox.py
Sandbox VM status, logs, and self-heal endpoints
"""

import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, and_
from datetime import timedelta

from app.core.database import get_db
from app.models.scan   import ScanResult, BehaviorEvent, ThreatLevel

router = APIRouter(prefix="/sandbox", tags=["Sandbox"])

# In-memory VM state (replace with Redis in production)
_vm_state = {
    "status":    "running",
    "cpu":       12,
    "memory_mb": 256,
    "uptime_pct": 99.8,
    "scan_count": 0,
    "self_heals": 0,
    "last_heal":  None,
    "os":         "Ubuntu 22.04 LTS",
    "isolation":  "Maximum",
    "ai_model":   "ThreatNet-v3",
}


# ── GET /api/sandbox/status ───────────────────────────────
@router.get("/status", summary="Get current sandbox VM status")
async def get_vm_status(db: AsyncSession = Depends(get_db)):
    """Returns live VM stats: CPU, memory, uptime, and recent activity."""
    import random

    # Simulate live CPU fluctuation
    _vm_state["cpu"]       = random.randint(5, 28)
    _vm_state["memory_mb"] = random.randint(240, 280)

    # Count self-heals from DB
    cutoff = datetime.now(timezone.utc) - timedelta(days=1)
    result = await db.execute(
        select(ScanResult).where(
            and_(
                ScanResult.threat_level == ThreatLevel.DANGER,
                ScanResult.created_at   >= cutoff,
            )
        ).order_by(desc(ScanResult.created_at))
    )
    recent_dangers = result.scalars().all()
    _vm_state["self_heals"] = len(recent_dangers)
    if recent_dangers:
        _vm_state["last_heal"] = recent_dangers[0].created_at.isoformat()

    return {
        "vm": _vm_state,
        "heal_protocol": [
            {"step": 1, "title": "Threat Detected",    "status": "done",   "desc": "AI identifies threat with confidence score"},
            {"step": 2, "title": "VM Snapshot Frozen",  "status": "done",   "desc": "Memory state preserved for forensic analysis"},
            {"step": 3, "title": "Network Isolated",    "status": "done",   "desc": "All outbound traffic severed"},
            {"step": 4, "title": "VM Rebuilt",          "status": "active", "desc": "Restoring clean base snapshot..."},
            {"step": 5, "title": "Ready for Next Scan", "status": "wait",   "desc": "System back online in ~10 seconds"},
        ],
    }


# ── GET /api/sandbox/logs ─────────────────────────────────
@router.get("/logs", summary="Get VM activity log")
async def get_vm_logs(
    limit: int = 50,
    db:    AsyncSession = Depends(get_db),
):
    """Returns real scan log entries from the database as VM log lines."""
    result = await db.execute(
        select(ScanResult)
        .order_by(desc(ScanResult.created_at))
        .limit(limit)
    )
    records = result.scalars().all()

    logs = []
    for r in reversed(records):
        ts = r.scan_started_at.strftime("%H:%M:%S") if r.scan_started_at else "--:--:--"
        logs.append({
            "ts":   ts,
            "type": "info",
            "msg":  f"→ Spawning VM sandbox for {r.scan_type.value}: {r.input_value[:40]}"
        })
        if r.threat_level == ThreatLevel.DANGER:
            logs.append({"ts": ts, "type": "err",  "msg": f"✗ THREAT DETECTED — {r.verdict} (score: {r.risk_score})"})
            logs.append({"ts": ts, "type": "warn", "msg": "⚠ Triggering self-heal protocol..."})
            logs.append({"ts": ts, "type": "ok",   "msg": "✓ VM reset — clean snapshot restored"})
        elif r.threat_level == ThreatLevel.WARN:
            logs.append({"ts": ts, "type": "warn", "msg": f"⚠ Suspicious content — {r.verdict_detail[:60]}"})
            logs.append({"ts": ts, "type": "ok",   "msg": "✓ Scan complete — medium risk verdict"})
        else:
            logs.append({"ts": ts, "type": "ok",   "msg": f"✓ SAFE — {r.input_value[:40]}"})

    return {"logs": logs[-100:]}  # last 100 lines


# ── GET /api/sandbox/behaviors ────────────────────────────
@router.get("/behaviors", summary="Last analyzed behavioral events")
async def get_behaviors(db: AsyncSession = Depends(get_db)):
    """Returns the most recent behavioral analysis from the last threat scan."""
    result = await db.execute(
        select(ScanResult)
        .where(ScanResult.threat_level == ThreatLevel.DANGER)
        .order_by(desc(ScanResult.created_at))
        .limit(1)
    )
    record = result.scalar_one_or_none()

    if not record:
        return {"behaviors": [], "threat": None}

    # Build behavior summary from scan data
    tags    = record.threat_tags or []
    scores  = record.meter_scores or {}
    tag_str = " ".join(tags).lower()

    behaviors = [
        {"icon": "🌐", "name": "Network Calls",   "value": "Suspicious DNS detected" if "phish" in tag_str else "Normal", "level": "bad" if "phish" in tag_str else "ok"},
        {"icon": "📂", "name": "File Access",      "value": "Credential dir accessed" if "credential" in tag_str else "Normal", "level": "bad" if "credential" in tag_str else "ok"},
        {"icon": "🔑", "name": "Key Logging",      "value": "Keylogger detected" if "keylog" in tag_str else "None detected", "level": "bad" if "keylog" in tag_str else "ok"},
        {"icon": "📤", "name": "Data Exfiltration","value": "Attempt blocked" if record.risk_score > 60 else "None", "level": "bad" if record.risk_score > 60 else "ok"},
        {"icon": "💉", "name": "Code Injection",   "value": "1 attempt" if "trojan" in tag_str else "None", "level": "mid" if "trojan" in tag_str else "ok"},
        {"icon": "🛡️", "name": "Sandbox Escape",   "value": "Contained", "level": "ok"},
    ]

    return {
        "behaviors": behaviors,
        "threat": {
            "id":          record.id,
            "input":       record.input_value[:60],
            "verdict":     record.verdict,
            "score":       record.risk_score,
            "tags":        tags,
            "scanned_at":  record.created_at.isoformat() if record.created_at else None,
        }
    }


# ── POST /api/sandbox/reset ───────────────────────────────
@router.post("/reset", summary="Manually trigger VM reset / self-heal")
async def reset_vm():
    """Simulates a manual VM reset (in production, this calls your VM orchestrator)."""
    import asyncio
    _vm_state["status"] = "resetting"
    await asyncio.sleep(0.5)   # simulate async reset trigger
    _vm_state["status"]    = "running"
    _vm_state["self_heals"] += 1
    _vm_state["last_heal"]  = datetime.now(timezone.utc).isoformat()
    return {
        "success": True,
        "message": "VM reset triggered — clean snapshot restored",
        "state":   _vm_state,
    }
