from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from backend.models import ScanStatus, Severity, ValidationStatus, DeviceType


class ScanCreate(BaseModel):
    name: str = ""
    static_only: bool = False
    device_type: DeviceType | None = None
    device_id: str | None = None
    enabled_plugins: list[str] = []
    config_overrides: dict[str, Any] = {}


class ScanResponse(BaseModel):
    id: int
    name: str
    package_name: str | None
    app_version: str | None
    status: ScanStatus
    static_only: bool
    device_type: DeviceType | None
    progress_pct: float
    current_phase: str
    coverage_pct: float
    total_intents_sent: int
    total_crashes: int
    findings_count: int = 0
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    error_message: str | None

    class Config:
        from_attributes = True


class ScanDetail(ScanResponse):
    enabled_plugins: list[str]
    config_overrides: dict[str, Any]
    components: list[ComponentResponse] = []
    findings: list[FindingResponse] = []


class ComponentResponse(BaseModel):
    id: int
    component_type: str
    name: str
    exported: bool
    permission: str | None
    intent_filters: list[dict]
    deep_links: list[str]
    metadata: dict

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    id: int
    scan_id: int
    plugin_name: str
    title: str
    description: str
    severity: Severity
    cvss_score: float | None
    cwe_id: str | None
    mstg_id: str | None
    owasp_mobile: str | None
    component_name: str | None
    component_type: str | None
    validation_status: ValidationStatus
    poc_command: str | None
    evidence: dict
    logcat_snippet: str | None
    created_at: datetime
    validated_at: datetime | None

    class Config:
        from_attributes = True


class FindingDetail(FindingResponse):
    poc_frida_script: str | None
    request_data: str | None
    response_data: str | None
    screenshot_path: str | None


class AttackChainResponse(BaseModel):
    id: int
    scan_id: int
    title: str
    description: str | None
    severity: Severity
    cvss_score: float | None
    steps: list[ChainStepResponse] = []

    class Config:
        from_attributes = True


class ChainStepResponse(BaseModel):
    step_order: int
    finding_id: int
    finding_title: str = ""
    description: str | None

    class Config:
        from_attributes = True


class StaticResultResponse(BaseModel):
    package_name: str | None
    min_sdk: int | None
    target_sdk: int | None
    permissions: list[str]
    debuggable: bool
    allow_backup: bool
    shared_uid: str | None
    secret_codes: list[str]
    hardcoded_secrets: list[dict]
    native_libs: list[str]
    attack_surface_score: float
    network_security_config: dict

    class Config:
        from_attributes = True


class DeviceInfo(BaseModel):
    device_id: str
    device_type: DeviceType
    model: str = ""
    android_version: str = ""
    api_level: int = 0
    rooted: bool = False
    frida_running: bool = False
    status: str = "unknown"


class PluginInfo(BaseModel):
    name: str
    display_name: str
    description: str
    version: str
    requires_device: bool
    attack_vectors: list[str]
    enabled: bool = True


class ScanProgress(BaseModel):
    scan_id: int
    status: ScanStatus
    phase: str
    progress_pct: float
    coverage_pct: float
    intents_sent: int
    crashes: int
    findings_count: int
    current_plugin: str = ""
    message: str = ""


class ReportRequest(BaseModel):
    scan_id: int
    format: str = "html"
    include_evidence: bool = True
    include_poc: bool = True
    include_chain_graph: bool = True
