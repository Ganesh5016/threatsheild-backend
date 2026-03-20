"""
THREATSHIELD — main.py
FastAPI app — CORS fixed for localhost development.
"""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from app.core.config   import settings
from app.core.database import init_db
from app.api           import api_router

# ── Logging ───────────────────────────────────────────────
logging.basicConfig(
    level   = logging.DEBUG if settings.DEBUG else logging.INFO,
    format  = "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt = "%H:%M:%S",
)
logger = logging.getLogger("threatshield")

for _lib in ("uvicorn.access", "sqlalchemy.engine", "httpx", "httpcore"):
    logging.getLogger(_lib).setLevel(logging.WARNING)


# ── Lifespan ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"🚀 ThreatShield {settings.APP_VERSION} starting [{settings.APP_ENV}]")
    await init_db()
    logger.info("✅ Database ready")
    yield
    logger.info("👋 ThreatShield shutting down")


# ── App Factory ───────────────────────────────────────────
def create_app() -> FastAPI:
    app = FastAPI(
        title       = "ThreatShield API",
        description = "AI-Based Personal Digital Threat Isolation & Self-Healing System",
        version     = settings.APP_VERSION,
        docs_url    = "/docs",
        redoc_url   = "/redoc",
        openapi_url = "/openapi.json",
        lifespan    = lifespan,
    )

    # ── CORS — allow ALL origins in development ───────────
    # This fixes "Failed to fetch" / "Backend Offline" errors
    app.add_middleware(
        CORSMiddleware,
        allow_origins     = ["*"],          # allow every origin
        allow_credentials = False,          # must be False when allow_origins=["*"]
        allow_methods     = ["*"],
        allow_headers     = ["*"],
    )

    # ── Gzip ─────────────────────────────────────────────
    app.add_middleware(GZipMiddleware, minimum_size=500)

    # ── Timing header ─────────────────────────────────────
    @app.middleware("http")
    async def add_timing(request: Request, call_next):
        start    = time.time()
        response = await call_next(request)
        ms       = round((time.time() - start) * 1000, 1)
        response.headers["X-Response-Time"] = f"{ms}ms"
        response.headers["X-Powered-By"]    = "ThreatShield"
        return response

    # ── Security headers ──────────────────────────────────
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"]         = "SAMEORIGIN"
        return response

    # ── Global error handler ──────────────────────────────
    @app.exception_handler(Exception)
    async def global_error_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception on {request.url.path}: {exc}")
        return JSONResponse(
            status_code = 500,
            content = {
                "detail": "Internal server error",
                "error":  str(exc) if settings.DEBUG else "An error occurred",
            },
        )

    # ── Routers ───────────────────────────────────────────
    app.include_router(api_router)

    # ── Health endpoints ──────────────────────────────────
    @app.get("/", tags=["Health"])
    async def root():
        return {
            "name":    settings.APP_NAME,
            "version": settings.APP_VERSION,
            "status":  "🛡️ Armed and operational",
            "docs":    "/docs",
        }

    @app.get("/health", tags=["Health"])
    async def health():
        return {
            "status":  "ok",
            "version": settings.APP_VERSION,
            "env":     settings.APP_ENV,
        }

    @app.get("/api/health", tags=["Health"])
    async def api_health():
        return {
            "status": "ok",
            "services": {
                "database":            "connected",
                "virustotal":          "configured" if settings.has_virustotal          else "not configured",
                "google_safebrowsing": "configured" if settings.has_google_safebrowsing else "not configured",
                "urlscan":             "configured" if settings.has_urlscan             else "not configured",
                "abuseipdb":           "configured" if settings.has_abuseipdb           else "not configured",
            },
        }

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host      = "0.0.0.0",
        port      = 8000,
        reload    = settings.DEBUG,
        log_level = "debug" if settings.DEBUG else "info",
    )
