"""
THREATSHIELD  ·  app/utils/cache.py
Simple Redis cache with fallback to in-memory dict.
Used to cache scan results so identical URLs/hashes aren't re-scanned.
"""
import json
import hashlib
import asyncio
from typing import Optional, Any
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)

# ── In-memory fallback ────────────────────────────────────
_mem_cache: dict = {}


class Cache:
    """
    Async key-value cache.
    Uses Redis when available, in-memory dict as fallback.
    TTL in seconds.
    """

    def __init__(self):
        self._redis = None

    async def init_redis(self, redis_url: str):
        try:
            import aioredis
            self._redis = await aioredis.from_url(redis_url, encoding="utf-8", decode_responses=True)
            await self._redis.ping()
            logger.info("✅ Redis cache connected")
        except Exception as e:
            logger.warning(f"Redis unavailable, using in-memory cache: {e}")
            self._redis = None

    async def get(self, key: str) -> Optional[Any]:
        full_key = f"ts_cache:{key}"
        try:
            if self._redis:
                val = await self._redis.get(full_key)
                return json.loads(val) if val else None
        except Exception:
            pass
        entry = _mem_cache.get(full_key)
        if entry and entry["expires"] > asyncio.get_event_loop().time():
            return entry["value"]
        return None

    async def set(self, key: str, value: Any, ttl: int = 3600):
        full_key = f"ts_cache:{key}"
        try:
            if self._redis:
                await self._redis.setex(full_key, ttl, json.dumps(value))
                return
        except Exception:
            pass
        _mem_cache[full_key] = {
            "value":   value,
            "expires": asyncio.get_event_loop().time() + ttl,
        }

    async def delete(self, key: str):
        full_key = f"ts_cache:{key}"
        try:
            if self._redis:
                await self._redis.delete(full_key)
        except Exception:
            pass
        _mem_cache.pop(full_key, None)

    async def exists(self, key: str) -> bool:
        return (await self.get(key)) is not None

    @staticmethod
    def make_url_key(url: str) -> str:
        return "url:" + hashlib.sha256(url.encode()).hexdigest()[:16]

    @staticmethod
    def make_file_key(sha256: str) -> str:
        return "file:" + sha256[:16]


# ── Singleton ─────────────────────────────────────────────
cache = Cache()
