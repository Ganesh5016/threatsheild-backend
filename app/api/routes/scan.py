"""
THREATSHIELD — app/api/routes/scan.py
Fixed for Windows + Python 3.13 — no aiofiles dependency.
"""

import os
import uuid
import shutil
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, File, UploadFile, Form, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.config   import settings
from app.services.scan_service import ScanService

router = APIRouter(prefix="/scan", tags=["Scan"])


# ── Schemas ───────────────────────────────────────────────
class URLScanRequest(BaseModel):
    url:       str
    device_id: Optional[str] = None

    @validator("url", pre=True)
    def clean_url(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        if len(v) > 2048:
            raise ValueError("URL too long (max 2048 chars)")
        return v


class EmailScanRequest(BaseModel):
    sender:    str
    subject:   Optional[str] = ""
    device_id: Optional[str] = None


def _to_response(record) -> dict:
    return {
        "scan_id":       record.id,
        "scan_type":     record.scan_type.value,
        "status":        record.status.value,
        "threat_level":  record.threat_level.value if record.threat_level else "safe",
        "risk_score":    record.risk_score or 0,
        "verdict":       record.verdict or "SAFE",
        "verdict_detail":record.verdict_detail or "",
        "tags":          record.threat_tags or [],
        "meter_scores":  record.meter_scores or {},
        "input_value":   record.input_value,
        "duration_ms":   record.scan_duration_ms,
        "auto_deleted":  False,
        "api_results":   record.api_results or {},
        "created_at":    record.created_at.isoformat() if record.created_at else None,
    }


# ── POST /api/scan/url ────────────────────────────────────
@router.post("/url", summary="Scan a URL for threats")
async def scan_url(
    request: Request,
    body:    URLScanRequest,
    db:      AsyncSession = Depends(get_db),
):
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    dev_id = body.device_id or request.headers.get("x-device-id")

    service = ScanService(db)
    record  = await service.scan_url(
        url        = body.url,
        ip_address = ip,
        user_agent = ua,
        device_id  = dev_id,
    )
    return _to_response(record)



# ── POST /api/scan/file ───────────────────────────────────
@router.post("/file", summary="Scan an uploaded file for malware")
async def scan_file(
    request:   Request,
    file:      UploadFile = File(...),
    device_id: Optional[str] = Form(None),
    db:        AsyncSession = Depends(get_db),
):
    # Validate extension
    filename = file.filename or "unknown"
    ext      = Path(filename).suffix.lower()

    allowed = settings.allowed_extensions_list
    if ext and allowed and ext not in allowed:
        raise HTTPException(
            status_code = 400,
            detail      = f"File type '{ext}' not supported. Allowed: {', '.join(allowed)}"
        )

    # Read file bytes directly (no aiofiles needed)
    file_bytes = await file.read()

    if len(file_bytes) == 0:
        raise HTTPException(status_code=400, detail="File is empty")

    if len(file_bytes) > settings.max_upload_bytes:
        raise HTTPException(
            status_code = 413,
            detail      = f"File too large. Max size: {settings.MAX_UPLOAD_SIZE_MB}MB"
        )

    # Save to temp directory using standard Python (no aiofiles)
    upload_dir = Path(settings.UPLOAD_DIR)
    upload_dir.mkdir(parents=True, exist_ok=True)

    temp_name = f"{uuid.uuid4()}{ext}"
    temp_path = upload_dir / temp_name

    # Write synchronously — fast enough for files up to 50MB
    with open(temp_path, "wb") as f:
        f.write(file_bytes)

    ip = request.client.host if request.client else None

    try:
        service = ScanService(db)
        record  = await service.scan_file(
            file_path  = str(temp_path),
            filename   = filename,
            file_size  = len(file_bytes),
            mime_type  = file.content_type,
            ip_address = ip,
            device_id  = device_id,
        )
    finally:
        # Always clean up temp file
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass

    return _to_response(record)


# ── POST /api/scan/email ──────────────────────────────────
@router.post("/email", summary="Scan an email sender / subject for phishing")
async def scan_email(
    body: EmailScanRequest,
    db:   AsyncSession = Depends(get_db),
):
    service = ScanService(db)
    record  = await service.scan_email(
        sender    = body.sender,
        subject   = body.subject or "",
        device_id = body.device_id,
    )
    return _to_response(record)


# ── GET /api/scan/{scan_id} ───────────────────────────────
@router.get("/{scan_id}", summary="Get result of a specific scan")
async def get_scan_result(
    scan_id: str,
    db:      AsyncSession = Depends(get_db),
):
    from sqlalchemy import select
    from app.models.scan import ScanResult

    result = await db.execute(select(ScanResult).where(ScanResult.id == scan_id))
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _to_response(record)


# ── GET /api/scan/history/list ────────────────────────────
@router.get("/history/list", summary="Get recent scan history")
async def get_scan_history(
    device_id: Optional[str] = None,
    limit:     int = 20,
    db:        AsyncSession = Depends(get_db),
):
    if limit > 100:
        limit = 100
    service = ScanService(db)
    records = await service.get_scan_history(device_id=device_id, limit=limit)
    return [_to_response(r) for r in records]
