"""
THREATSHIELD  ·  app/utils/logger.py
Structured JSON logging for production, pretty console for dev.
"""
import logging
import sys
import json
from datetime import datetime, timezone
from app.core.config import settings


class JSONFormatter(logging.Formatter):
    """Outputs each log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        log = {
            "ts":      datetime.now(timezone.utc).isoformat(),
            "level":   record.levelname,
            "logger":  record.name,
            "msg":     record.getMessage(),
        }
        if record.exc_info:
            log["exc"] = self.formatException(record.exc_info)
        if hasattr(record, "extra"):
            log.update(record.extra)
        return json.dumps(log)


class PrettyFormatter(logging.Formatter):
    COLORS = {
        "DEBUG":    "\033[36m",
        "INFO":     "\033[32m",
        "WARNING":  "\033[33m",
        "ERROR":    "\033[31m",
        "CRITICAL": "\033[35m",
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelname, "")
        ts    = datetime.now().strftime("%H:%M:%S")
        msg   = record.getMessage()
        return f"{color}[{ts}] {record.levelname:<8}{self.RESET} {record.name} — {msg}"


def setup_logging():
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)

    # Remove existing handlers
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        PrettyFormatter() if settings.DEBUG else JSONFormatter()
    )
    root.addHandler(handler)

    # Silence noisy libraries
    for lib in ("uvicorn.access", "sqlalchemy.engine", "httpx", "httpcore"):
        logging.getLogger(lib).setLevel(
            logging.DEBUG if settings.DEBUG else logging.WARNING
        )

    return root


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
