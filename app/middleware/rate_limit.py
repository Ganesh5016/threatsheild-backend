"""
THREATSHIELD  ·  app/middleware/rate_limit.py
Per-IP and per-device-ID rate limiting with Redis backing.
Falls back to in-memory if Redis is unavailable.
"""
import time
import asyncio
from collections import defaultdict
from typing import Optional
from fastapi import Request, HTTPException
import logging

logger = logging.getLogger(__name__)

# ── In-memory fallback store ──────────────────────────────
_memory_store: dict = defaultdict(list)


class RateLimiter:
    """
    Sliding-window rate limiter.
    Uses Redis when available, falls back to in-memory dict.
    """

    def __init__(self, redis_client=None):
        self.redis = redis_client

    async def is_allowed(
        self,
        key: str,
        limit: int,
        window_seconds: int,
    ) -> tuple[bool, int, int]:
        """
        Returns (allowed, remaining, reset_in_seconds).
        """
        now = time.time()

        if self.redis:
            try:
                return await self._redis_check(key, limit, window_seconds, now)
            except Exception as e:
                logger.warning(f"Redis rate-limit error, falling back to memory: {e}")

        return self._memory_check(key, limit, window_seconds, now)

    async def _redis_check(self, key, limit, window, now):
        pipe = self.redis.pipeline()
        window_start = now - window
        full_key = f"rl:{key}"

        pipe.zremrangebyscore(full_key, 0, window_start)
        pipe.zadd(full_key, {str(now): now})
        pipe.zcard(full_key)
        pipe.expire(full_key, window)
        results = await pipe.execute()

        count     = results[2]
        remaining = max(0, limit - count)
        allowed   = count <= limit
        return allowed, remaining, window

    def _memory_check(self, key, limit, window, now):
        window_start = now - window
        timestamps   = _memory_store[key]
        # Remove expired
        _memory_store[key] = [t for t in timestamps if t > window_start]
        _memory_store[key].append(now)
        count     = len(_memory_store[key])
        remaining = max(0, limit - count)
        allowed   = count <= limit
        return allowed, remaining, window


# ── Dependency factory ────────────────────────────────────
def rate_limit(limit: int = 30, window: int = 60, scope: str = "ip"):
    """
    FastAPI dependency. Usage:
        @router.post("/scan/url")
        async def scan(request: Request, _=Depends(rate_limit(30, 60))):
    """
    async def _check(request: Request):
        from app.core.config import settings

        if scope == "ip":
            key = request.client.host if request.client else "unknown"
        else:
            key = request.headers.get("X-Device-ID", request.client.host if request.client else "unknown")

        limiter = RateLimiter()  # no Redis in base version; extend for Redis
        allowed, remaining, reset = await limiter.is_allowed(key, limit, window)

        if not allowed:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Max {limit} requests per {window}s. Try again in {reset}s.",
                headers={
                    "X-RateLimit-Limit":     str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset":     str(int(time.time() + reset)),
                    "Retry-After":           str(reset),
                },
            )

        return {"remaining": remaining, "limit": limit}

    return _check
