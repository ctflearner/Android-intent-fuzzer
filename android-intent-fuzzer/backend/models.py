import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Column, Integer, String, Text, Float, Boolean, DateTime,
    ForeignKey, Enum, JSON,
)
from sqlalchemy.orm import relationship

from backend.database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    STATIC = "static_analysis"
    INSTALLING = "installing"
    FUZZING = "fuzzing"
    VALIDATING = "validating"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ValidationStatus(str, enum.Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    PARTIAL = "partial"
    NEEDS_MANUAL = "needs_manual"


class DeviceType(str, enum.Enum):
    DOCKER = "docker"
    LOCAL_ADB = "local_adb"
    REMOTE_ADB = "remote_adb"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    apk_path = Column(String(1024), nullable=False)
    package_name = Column(String(512))
    app_version = Column(String(64))
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    device_type = Column(Enum(DeviceType), nullable=True)
    device_id = Column(String(256), nullable=True)

    static_only = Column(Boolean, default=False)
    enabled_plugins = Column(JSON, default=list)
    config_overrides = Column(JSON, default=dict)

    progress_pct = Column(Float, default=0.0)
    current_phase = Column(String(128), default="")
    coverage_pct = Column(Float, default=0.0)
    total_intents_sent = Column(Integer, default=0)
    total_crashes = Column(Integer, default=0)

    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    error_message = Column(Text, nullable=True)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    components = relationship("Component", back_populates="scan", cascade="all, delete-orphan")


class Component(Base):
    __tablename__ = "components"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    component_type = Column(String(64), nullable=False)
    name = Column(String(512), nullable=False)
    exported = Column(Boolean, default=False)
    permission = Column(String(512), nullable=True)
    intent_filters = Column(JSON, default=list)
    deep_links = Column(JSON, default=list)
    metadata = Column(JSON, default=dict)

    scan = relationship("Scan", back_populates="components")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    plugin_name = Column(String(128), nullable=False)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    cvss_score = Column(Float, nullable=True)
    cwe_id = Column(String(32), nullable=True)
    mstg_id = Column(String(64), nullable=True)
    owasp_mobile = Column(String(64), nullable=True)

    component_name = Column(String(512), nullable=True)
    component_type = Column(String(64), nullable=True)

    validation_status = Column(Enum(ValidationStatus), default=ValidationStatus.PENDING)
    poc_command = Column(Text, nullable=True)
    poc_frida_script = Column(Text, nullable=True)
    request_data = Column(Text, nullable=True)
    response_data = Column(Text, nullable=True)
    evidence = Column(JSON, default=dict)
    logcat_snippet = Column(Text, nullable=True)
    screenshot_path = Column(String(1024), nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    validated_at = Column(DateTime, nullable=True)

    scan = relationship("Scan", back_populates="findings")
    chain_links = relationship("AttackChainLink", back_populates="finding")


class AttackChain(Base):
    __tablename__ = "attack_chains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    title = Column(String(512), nullable=False)
    description = Column(Text)
    severity = Column(Enum(Severity), nullable=False)
    cvss_score = Column(Float, nullable=True)

    links = relationship("AttackChainLink", back_populates="chain", order_by="AttackChainLink.step_order")


class AttackChainLink(Base):
    __tablename__ = "attack_chain_links"

    id = Column(Integer, primary_key=True, autoincrement=True)
    chain_id = Column(Integer, ForeignKey("attack_chains.id"), nullable=False)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False)
    step_order = Column(Integer, nullable=False)
    description = Column(Text)

    chain = relationship("AttackChain", back_populates="links")
    finding = relationship("Finding", back_populates="chain_links")


class StaticAnalysisResult(Base):
    __tablename__ = "static_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, unique=True)
    package_name = Column(String(512))
    min_sdk = Column(Integer, nullable=True)
    target_sdk = Column(Integer, nullable=True)
    permissions = Column(JSON, default=list)
    debuggable = Column(Boolean, default=False)
    allow_backup = Column(Boolean, default=False)
    network_security_config = Column(JSON, default=dict)
    shared_uid = Column(String(256), nullable=True)
    secret_codes = Column(JSON, default=list)
    hardcoded_secrets = Column(JSON, default=list)
    native_libs = Column(JSON, default=list)
    attack_surface_score = Column(Float, default=0.0)
    manifest_raw = Column(Text, nullable=True)
