"""
THREATSHIELD — app/api/routes/auth.py
Device-based JWT auth.
Uses python-jose[cryptography] — make sure you installed the RIGHT package.
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from app.core.config import settings

router   = APIRouter(prefix="/auth", tags=["Auth"])
security = HTTPBearer(auto_error=False)


# ── JWT helpers ───────────────────────────────────────────
def _get_jwt():
    """Lazy import so startup doesn't crash if jose is missing."""
    try:
        from jose import jwt as _jwt, JWTError as _JWTError
        return _jwt, _JWTError
    except ImportError:
        return None, None


def create_access_token(device_id: str) -> str:
    jwt, JWTError = _get_jwt()
    if not jwt:
        # Return a simple base64 token if jose not available
        import base64, json
        payload = {"sub": device_id, "type": "device"}
        return base64.b64encode(json.dumps(payload).encode()).decode()

    expire  = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    payload = {
        "sub":  device_id,
        "exp":  expire,
        "iat":  datetime.now(timezone.utc),
        "type": "device",
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def verify_token(token: str) -> Optional[str]:
    jwt, JWTError = _get_jwt()
    if not jwt:
        try:
            import base64, json
            payload = json.loads(base64.b64decode(token).decode())
            return payload.get("sub")
        except Exception:
            return None
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return payload.get("sub")
    except Exception:
        return None


# ── Schemas ───────────────────────────────────────────────
class DeviceRegisterRequest(BaseModel):
    device_id:   Optional[str] = None
    device_name: Optional[str] = "ThreatShield App"
    platform:    Optional[str] = "web"


class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    device_id:    str
    expires_in:   int


# ── Optional auth dependency ──────────────────────────────
async def get_optional_device_id(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_device_id: Optional[str] = None,
) -> Optional[str]:
    if credentials and credentials.credentials:
        device_id = verify_token(credentials.credentials)
        if device_id:
            return device_id
    if x_device_id:
        return x_device_id
    return None


# ── POST /api/auth/register ───────────────────────────────
@router.post("/register", response_model=TokenResponse)
async def register_device(body: DeviceRegisterRequest):
    device_id    = body.device_id or str(uuid.uuid4())
    access_token = create_access_token(device_id)
    return TokenResponse(
        access_token = access_token,
        device_id    = device_id,
        expires_in   = settings.JWT_EXPIRE_MINUTES * 60,
    )


# ── POST /api/auth/refresh ────────────────────────────────
@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
):
    if not credentials:
        raise HTTPException(status_code=401, detail="No token provided")
    device_id = verify_token(credentials.credentials)
    if not device_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return TokenResponse(
        access_token = create_access_token(device_id),
        device_id    = device_id,
        expires_in   = settings.JWT_EXPIRE_MINUTES * 60,
    )


# ── GET /api/auth/me ──────────────────────────────────────
@router.get("/me")
async def get_me(device_id: Optional[str] = Depends(get_optional_device_id)):
    if not device_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"device_id": device_id, "authenticated": True}
