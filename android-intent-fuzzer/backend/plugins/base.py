from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from backend.core.device_manager import DeviceHandle
    from backend.core.apk_analyzer import APKAnalysis


class PluginCategory(str, Enum):
    FUZZER = "fuzzer"
    SCANNER = "scanner"
    ANALYZER = "analyzer"
    VALIDATOR = "validator"


@dataclass
class IntentSpec:
    action: str = ""
    component: str = ""
    category: str = ""
    data_uri: str = ""
    mime_type: str = ""
    extras: dict[str, Any] = field(default_factory=dict)
    flags: int = 0

    def to_adb_args(self) -> list[str]:
        args = []
        if self.action:
            args.extend(["-a", self.action])
        if self.component:
            args.extend(["-n", self.component])
        if self.category:
            args.extend(["-c", self.category])
        if self.data_uri:
            args.extend(["-d", self.data_uri])
        if self.mime_type:
            args.extend(["-t", self.mime_type])
        if self.flags:
            args.extend(["-f", str(self.flags)])
        for key, val in self.extras.items():
            if isinstance(val, str):
                args.extend(["--es", key, val])
            elif isinstance(val, int):
                args.extend(["--ei", key, str(val)])
            elif isinstance(val, bool):
                args.extend(["--ez", key, str(val).lower()])
            elif isinstance(val, float):
                args.extend(["--ef", key, str(val)])
        return args

    def to_adb_command(self, cmd: str = "start") -> str:
        parts = ["adb", "shell", "am", cmd] + self.to_adb_args()
        return " ".join(parts)


@dataclass
class PluginFinding:
    title: str
    description: str
    severity: str
    component_name: str = ""
    component_type: str = ""
    cvss_score: float | None = None
    cwe_id: str = ""
    mstg_id: str = ""
    owasp_mobile: str = ""
    poc_command: str = ""
    poc_frida_script: str = ""
    request_data: str = ""
    response_data: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    logcat_snippet: str = ""


@dataclass
class ValidationVerdict:
    status: str  # confirmed, false_positive, partial, needs_manual
    evidence: dict[str, Any] = field(default_factory=dict)
    poc_command: str = ""
    logcat_snippet: str = ""
    screenshot_path: str = ""
    notes: str = ""


@dataclass
class PoC:
    poc_type: str  # adb_command, frida_script, apk_install
    commands: list[str] = field(default_factory=list)
    frida_script: str = ""
    apk_path: str = ""
    expected_result: str = ""
    timeout_seconds: int = 30


class BasePlugin(abc.ABC):
    name: str = "base"
    display_name: str = "Base Plugin"
    description: str = ""
    version: str = "1.0.0"
    category: PluginCategory = PluginCategory.SCANNER
    requires_device: bool = True
    attack_vectors: list[str] = []

    def __init__(self):
        self.logger = logging.getLogger(f"plugin.{self.name}")
        self._cancelled = False

    @abc.abstractmethod
    async def run(
        self,
        analysis: APKAnalysis,
        device: DeviceHandle | None,
        progress_callback=None,
    ) -> list[PluginFinding]:
        pass

    async def generate_poc(self, finding: PluginFinding) -> PoC | None:
        return None

    async def validate_result(
        self,
        finding: PluginFinding,
        device: DeviceHandle,
        execution_result: dict,
    ) -> ValidationVerdict:
        return ValidationVerdict(status="needs_manual", notes="No auto-validation implemented")

    def cancel(self):
        self._cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled

    def info(self) -> dict:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "version": self.version,
            "category": self.category.value,
            "requires_device": self.requires_device,
            "attack_vectors": self.attack_vectors,
        }
