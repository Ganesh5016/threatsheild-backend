"""
THREATSHIELD — app/models/scan.py
Database models for scan results, files, and history
"""

from sqlalchemy import (
    Column, String, Integer, Float, Boolean,
    DateTime, Text, JSON, Enum, Index, ForeignKey
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
import enum
import uuid


def generate_uuid():
    return str(uuid.uuid4())


# ── Enums ────────────────────────────────────────────────
class ScanType(str, enum.Enum):
    URL   = "url"
    FILE  = "file"
    APK   = "apk"
    EMAIL = "email"


class ThreatLevel(str, enum.Enum):
    SAFE   = "safe"
    WARN   = "warn"
    DANGER = "danger"


class ScanStatus(str, enum.Enum):
    PENDING    = "pending"
    SCANNING   = "scanning"
    COMPLETED  = "completed"
    FAILED     = "failed"
    TIMEOUT    = "timeout"


# ── Scan Result ──────────────────────────────────────────
class ScanResult(Base):
    __tablename__ = "scan_results"

    id             = Column(String(36), primary_key=True, default=generate_uuid)
    scan_type      = Column(Enum(ScanType),   nullable=False, index=True)
    threat_level   = Column(Enum(ThreatLevel), nullable=True,  index=True)
    status         = Column(Enum(ScanStatus), nullable=False, default=ScanStatus.PENDING, index=True)

    # Input
    input_value    = Column(Text, nullable=False)   # URL, filename, package name
    input_hash     = Column(String(64), nullable=True, index=True)  # SHA-256 of input

    # Risk scoring
    risk_score     = Column(Integer, default=0)     # 0–100
    confidence     = Column(Float,   default=0.0)   # 0.0–1.0 AI confidence

    # Verdict details
    verdict        = Column(String(255), nullable=True)
    verdict_detail = Column(Text,        nullable=True)

    # Threat breakdown (JSON)
    threat_tags    = Column(JSON, default=list)     # ["Phishing","Credential Steal"]
    meter_scores   = Column(JSON, default=dict)     # {"phishing":94,"malware":78,...}
    api_results    = Column(JSON, default=dict)     # raw responses from VT, URLScan etc

    # Metadata
    ip_address     = Column(String(45),  nullable=True)
    user_agent     = Column(String(512), nullable=True)
    device_id      = Column(String(64),  nullable=True, index=True)

    # Timing
    scan_started_at  = Column(DateTime(timezone=True), server_default=func.now())
    scan_finished_at = Column(DateTime(timezone=True), nullable=True)
    scan_duration_ms = Column(Integer, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    file_info = relationship("ScannedFile", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    behaviors = relationship("BehaviorEvent", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_scan_created_device", "created_at", "device_id"),
        Index("ix_scan_type_threat",    "scan_type",  "threat_level"),
    )

    def __repr__(self):
        return f"<ScanResult id={self.id[:8]} type={self.scan_type} level={self.threat_level} score={self.risk_score}>"


# ── Scanned File ─────────────────────────────────────────
class ScannedFile(Base):
    __tablename__ = "scanned_files"

    id          = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id     = Column(String(36), ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False, index=True)

    filename        = Column(String(512), nullable=False)
    original_name   = Column(String(512), nullable=True)
    file_size_bytes = Column(Integer,     nullable=True)
    mime_type       = Column(String(128), nullable=True)
    file_extension  = Column(String(20),  nullable=True)
    sha256_hash     = Column(String(64),  nullable=True, index=True)
    md5_hash        = Column(String(32),  nullable=True)

    # Analysis results
    is_pe_file      = Column(Boolean, default=False)
    is_apk_file     = Column(Boolean, default=False)
    is_encrypted    = Column(Boolean, default=False)
    entropy         = Column(Float,   nullable=True)     # High entropy = packed/encrypted
    yara_matches    = Column(JSON,    default=list)      # matched YARA rule names
    strings_found   = Column(JSON,    default=list)      # suspicious strings

    # APK-specific
    apk_package_name     = Column(String(256), nullable=True)
    apk_version          = Column(String(64),  nullable=True)
    apk_permissions      = Column(JSON,        default=list)
    apk_dangerous_perms  = Column(JSON,        default=list)
    apk_activities       = Column(JSON,        default=list)

    stored_path = Column(String(512), nullable=True)   # server storage path
    auto_deleted = Column(Boolean, default=False)      # True if auto-deleted as threat

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("ScanResult", back_populates="file_info")


# ── Behavior Event ───────────────────────────────────────
class BehaviorEvent(Base):
    __tablename__ = "behavior_events"

    id          = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id     = Column(String(36), ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False, index=True)

    category    = Column(String(64),  nullable=False)   # "network","file","registry","process"
    event_type  = Column(String(128), nullable=False)   # "dns_query","file_write","credential_access"
    severity    = Column(String(20),  nullable=False)   # "info","warn","critical"
    description = Column(Text,        nullable=True)
    raw_data    = Column(JSON,        default=dict)

    timestamp   = Column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("ScanResult", back_populates="behaviors")


# ── Threat Stats (daily aggregate) ───────────────────────
class ThreatStats(Base):
    __tablename__ = "threat_stats"

    id           = Column(String(36), primary_key=True, default=generate_uuid)
    date         = Column(DateTime(timezone=True), nullable=False, index=True, unique=True)

    total_scans   = Column(Integer, default=0)
    safe_count    = Column(Integer, default=0)
    warn_count    = Column(Integer, default=0)
    danger_count  = Column(Integer, default=0)

    phishing_count  = Column(Integer, default=0)
    malware_count   = Column(Integer, default=0)
    adware_count    = Column(Integer, default=0)
    spyware_count   = Column(Integer, default=0)
    ransomware_count= Column(Integer, default=0)

    vm_self_heals   = Column(Integer, default=0)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
