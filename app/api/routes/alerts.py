"""
THREATSHIELD  ·  app/api/routes/alerts.py
Real-time threat alerts — Server-Sent Events (SSE) stream.
Frontend subscribes and receives live threat notifications.
"""
import asyncio
import json
from datetime import datetime, timezone, timedelta
from typing import AsyncGenerator, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, and_

from app.core.database import get_db
from app.models.scan   import ScanResult, ThreatLevel

router = APIRouter(prefix="/alerts", tags=["Alerts"])

# ── In-memory alert queue (use Redis pub/sub in production) ─
_alert_queues: dict[str, asyncio.Queue] = {}


async def push_alert(device_id: str, alert: dict):
    """Called by scan_service when a threat is detected."""
    q = _alert_queues.get(device_id)
    if q:
        await q.put(alert)
    # Also push to broadcast queue
    q = _alert_queues.get("__broadcast__")
    if q:
        await q.put({**alert, "device_id": device_id})


# ── GET /api/alerts/stream ────────────────────────────────
@router.get("/stream", summary="SSE stream for real-time threat alerts")
async def alert_stream(
    request:   Request,
    device_id: Optional[str] = None,
):
    """
    Server-Sent Events stream. Connect once and receive live alerts.

    Example (JavaScript):
        const es = new EventSource('/api/alerts/stream?device_id=DEV-ABC123');
        es.onmessage = e => console.log(JSON.parse(e.data));
    """
    key = device_id or "__broadcast__"
    if key not in _alert_queues:
        _alert_queues[key] = asyncio.Queue(maxsize=50)

    async def event_generator() -> AsyncGenerator[str, None]:
        # Send initial "connected" event
        yield f"data: {json.dumps({'type': 'connected', 'message': 'ThreatShield alert stream active'})}\n\n"

        try:
            while True:
                if await request.is_disconnected():
                    break

                try:
                    alert = await asyncio.wait_for(_alert_queues[key].get(), timeout=25.0)
                    yield f"data: {json.dumps(alert)}\n\n"
                except asyncio.TimeoutError:
                    # Send heartbeat to keep connection alive
                    yield f": heartbeat\n\n"

        except asyncio.CancelledError:
            pass
        finally:
            if key in _alert_queues:
                del _alert_queues[key]

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":              "no-cache",
            "X-Accel-Buffering":          "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


# ── GET /api/alerts/recent ────────────────────────────────
@router.get("/recent", summary="Recent threat alerts from database")
async def get_recent_alerts(
    limit:     int = 20,
    device_id: Optional[str] = None,
    db:        AsyncSession = Depends(get_db),
):
    """Returns the last N threat-level scan results as alerts."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    q = (
        select(ScanResult)
        .where(
            and_(
                ScanResult.threat_level  == ThreatLevel.DANGER,
                ScanResult.created_at   >= cutoff,
            )
        )
        .order_by(desc(ScanResult.created_at))
        .limit(limit)
    )
    if device_id:
        q = q.where(ScanResult.device_id == device_id)

    result  = await db.execute(q)
    records = result.scalars().all()

    def _fmt(r):
        delta = datetime.now(timezone.utc) - r.created_at
        secs  = int(delta.total_seconds())
        ago   = f"{secs}s ago" if secs < 60 else f"{secs//60}m ago" if secs < 3600 else f"{secs//3600}h ago"
        return {
            "id":          r.id,
            "type":        "threat",
            "title":       r.verdict or "THREAT DETECTED",
            "body":        r.verdict_detail or "",
            "input":       r.input_value[:50],
            "scan_type":   r.scan_type.value,
            "risk_score":  r.risk_score or 0,
            "tags":        (r.threat_tags or [])[:3],
            "time":        ago,
            "created_at":  r.created_at.isoformat(),
        }

    return [_fmt(r) for r in records]


# ── POST /api/alerts/test ─────────────────────────────────
@router.post("/test", summary="Send a test alert (dev only)")
async def send_test_alert(device_id: Optional[str] = None):
    """Push a test alert to verify SSE connection is working."""
    alert = {
        "type":       "threat",
        "title":      "TEST ALERT",
        "body":       "ThreatShield alert system is working correctly",
        "risk_score": 95,
        "tags":       ["Test", "Phishing"],
        "time":       "just now",
    }
    await push_alert(device_id or "__broadcast__", alert)
    return {"sent": True, "alert": alert}
