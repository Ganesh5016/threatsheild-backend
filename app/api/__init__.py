"""THREATSHIELD  ·  app/api/__init__.py — all route registrations"""
from fastapi import APIRouter
from app.api.routes import scan, stats, sandbox, auth, alerts

api_router = APIRouter(prefix="/api")
api_router.include_router(auth.router)
api_router.include_router(scan.router)
api_router.include_router(stats.router)
api_router.include_router(sandbox.router)
api_router.include_router(alerts.router)
