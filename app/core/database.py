"""
THREATSHIELD — app/core/database.py
Compatible with SQLAlchemy 1.4 AND 2.x — no async_sessionmaker needed.
"""

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

# ── Engine ───────────────────────────────────────────────
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
)

# ── Session factory ──────────────────────────────────────
# Uses sessionmaker(class_=AsyncSession) — works on SQLAlchemy 1.4 AND 2.x
# (async_sessionmaker was only added in SQLAlchemy 2.0)
AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


# ── Base model ───────────────────────────────────────────
class Base(DeclarativeBase):
    pass


# ── Dependency (FastAPI) ─────────────────────────────────
async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ── Init tables ──────────────────────────────────────────
async def init_db():
    """Create all tables on startup."""
    async with engine.begin() as conn:
        from app.models import scan  # noqa: F401
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables initialised")


async def drop_db():
    """Drop all tables (testing only)."""
    async with engine.begin() as conn:
        from app.models import scan  # noqa: F401
        await conn.run_sync(Base.metadata.drop_all)
