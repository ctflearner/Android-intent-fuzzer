"""ServiceBinderPlugin — test exported services, AIDL interfaces, and unprotected commands."""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING

from backend.plugins.base import (
    BasePlugin,
    PluginCategory,
    PluginFinding,
    IntentSpec,
    PoC,
    ValidationVerdict,
)

if TYPE_CHECKING:
    from backend.core.device_manager import DeviceHandle
    from backend.core.apk_analyzer import APKAnalysis


_CRASH_RE = re.compile(
    r"(FATAL EXCEPTION|java\.lang\.\w*Exception|NullPointerException|"
    r"SecurityException|DeadObjectException|TransactionTooLargeException|"
    r"RemoteException|SIGSEGV|ANR in)",
    re.IGNORECASE,
)

_AIDL_RE = re.compile(r"(\.aidl|Stub\.asInterface|IBinder|onTransact|Proxy)", re.IGNORECASE)

_SERVICE_COMMANDS = list(range(10))  # dumpsys-style command codes 0-9

_EXTRA_PAYLOADS = [
    {"command": "exec", "cmd": "id"},
    {"command": "dump", "path": "/data/data/{pkg}/databases/"},
    {"command": "config", "debug": True},
    {"command": "admin", "level": 9999},
    {"action": "start", "data": "A" * 10000},
    {"action": "stop"},
    {"action": "reset"},
    {"query": "' OR 1=1--"},
    {},
]


class ServiceBinderPlugin(BasePlugin):
    name = "service_binder"
    display_name = "Service Binder Tester"
    description = (
        "Tests exported services by sending start intents, checking AIDL interfaces, "
        "and fuzzing unprotected service commands."
    )
    version = "1.0.0"
    category = PluginCategory.FUZZER
    requires_device = True
    attack_vectors = [
        "service_hijack",
        "aidl_exploitation",
        "unprotected_command",
        "service_dos",
    ]

    async def run(self, analysis, device, progress_callback=None) -> list[PluginFinding]:
        findings: list[PluginFinding] = []

        services = [
            c for c in analysis.components
            if c.type == "service" and c.exported
        ]
        total = len(services)
        if not total:
            return findings

        pkg = analysis.package_name

        for idx, svc in enumerate(services):
            if self.is_cancelled:
                break

            fqn = f"{pkg}/{svc.name}" if not svc.name.startswith(pkg) else f"{pkg}/{svc.name}"

            # 1) Start service with crafted extras
            start_findings = await self._test_start_intents(device, fqn, svc, pkg)
            findings.extend(start_findings)

            # 2) Check AIDL / binder interface exposure
            aidl_f = await self._test_aidl_interface(device, svc, pkg)
            if aidl_f:
                findings.append(aidl_f)

            # 3) Service command fuzzing via dumpsys
            cmd_findings = await self._fuzz_service_commands(device, svc, pkg)
            findings.extend(cmd_findings)

            # 4) Permission check
            perm_f = self._check_missing_permission(svc, pkg)
            if perm_f:
                findings.append(perm_f)

            # 5) DoS via rapid start
            dos_f = await self._test_service_dos(device, fqn, svc)
            if dos_f:
                findings.append(dos_f)

            if progress_callback:
                await progress_callback(
                    plugin=self.name,
                    progress=(idx + 1) / total,
                    message=f"Tested service {svc.name}",
                )

        return findings

    # ------------------------------------------------------------------
    async def _test_start_intents(self, device, fqn, svc, pkg) -> list[PluginFinding]:
        results: list[PluginFinding] = []

        actions = []
        for filt in svc.intent_filters:
            actions.extend(filt.get("actions", []))
        if not actions:
            actions = [f"{pkg}.action.START_SERVICE"]

        for action in actions:
            for payload in _EXTRA_PAYLOADS:
                if self.is_cancelled:
                    return results
                extras = {
                    k: v.replace("{pkg}", pkg) if isinstance(v, str) else v
                    for k, v in payload.items()
                }
                await device.clear_logcat()
                spec = IntentSpec(action=action, component=fqn, extras=extras)
                out = await device.start_service(spec.to_adb_args())
                await asyncio.sleep(0.5)
                logcat = await device.logcat_snapshot(lines=200)

                if _CRASH_RE.search(logcat + out):
                    exc = _CRASH_RE.search(logcat + out).group(0)
                    results.append(PluginFinding(
                        title=f"Service crash: {exc} — {svc.name}",
                        description=(
                            f"Starting service {svc.name} with extras {extras} "
                            f"triggers {exc}."
                        ),
                        severity="high",
                        component_name=svc.name,
                        component_type="service",
                        cwe_id="CWE-20",
                        mstg_id="MSTG-PLATFORM-2",
                        owasp_mobile="M1",
                        poc_command=spec.to_adb_command("startservice"),
                        logcat_snippet=logcat[-1500:],
                        evidence={"extras": extras},
                    ))
                    break
        return results

    async def _test_aidl_interface(self, device, svc, pkg) -> PluginFinding | None:
        """Check if the service exposes an AIDL binder interface."""
        # Use dumpsys to inspect the service
        dumpsys = await device.shell(f"dumpsys activity services {pkg}/{svc.name}")

        if _AIDL_RE.search(dumpsys):
            # Try to get the interface descriptor
            service_check = await device.shell(
                f"service list | grep -i {pkg}"
            )
            has_binder = bool(service_check.strip())

            if has_binder:
                return PluginFinding(
                    title=f"AIDL interface exposed — {svc.name}",
                    description=(
                        f"Service {svc.name} exposes an AIDL binder interface that "
                        f"can be called by any app. Interface detected in dumpsys output. "
                        f"This may allow unauthorized method invocations."
                    ),
                    severity="high",
                    component_name=svc.name,
                    component_type="service",
                    cvss_score=7.5,
                    cwe_id="CWE-862",
                    mstg_id="MSTG-PLATFORM-2",
                    owasp_mobile="M1",
                    poc_command=f"adb shell dumpsys activity services {pkg}/{svc.name}",
                    response_data=dumpsys[:2000],
                    evidence={"service_list": service_check[:500]},
                )

        return None

    async def _fuzz_service_commands(self, device, svc, pkg) -> list[PluginFinding]:
        """Fuzz service transaction codes via 'service call'."""
        results: list[PluginFinding] = []
        service_name = svc.name.split(".")[-1] if "." in svc.name else svc.name

        # Check if service is registered in service manager
        svc_list = await device.shell(f"service list | grep -i {service_name}")
        if not svc_list.strip():
            return results

        # Extract registered service name
        for line in svc_list.splitlines():
            parts = line.split(":")
            if len(parts) < 2:
                continue
            registered_name = parts[0].strip().split()[-1]

            for code in _SERVICE_COMMANDS:
                if self.is_cancelled:
                    return results
                await device.clear_logcat()
                cmd = f"service call {registered_name} {code}"
                out = await device.shell(cmd)
                logcat = await device.logcat_snapshot(lines=100)

                # Non-error response means the command was accepted
                if out and "Exception" not in out and "Unknown" not in out and "error" not in out.lower():
                    results.append(PluginFinding(
                        title=f"Unprotected service command code {code} — {svc.name}",
                        description=(
                            f"Service {registered_name} accepts transaction code {code} "
                            f"without authorization. Response: {out[:200]}"
                        ),
                        severity="medium",
                        component_name=svc.name,
                        component_type="service",
                        cwe_id="CWE-862",
                        mstg_id="MSTG-PLATFORM-2",
                        owasp_mobile="M1",
                        poc_command=f"adb shell {cmd}",
                        response_data=out[:2000],
                    ))
            break  # just test the first matching service

        return results

    def _check_missing_permission(self, svc, pkg) -> PluginFinding | None:
        """Static check: exported service with no permission guard."""
        if svc.exported and not svc.permission:
            return PluginFinding(
                title=f"Exported service without permission — {svc.name}",
                description=(
                    f"Service {svc.name} is exported without any permission requirement. "
                    f"Any app can start or bind to this service."
                ),
                severity="medium",
                component_name=svc.name,
                component_type="service",
                cwe_id="CWE-862",
                mstg_id="MSTG-PLATFORM-2",
                owasp_mobile="M1",
                evidence={"exported": True, "permission": None},
            )
        return None

    async def _test_service_dos(self, device, fqn, svc) -> PluginFinding | None:
        """Rapid-fire service starts to test for resource exhaustion."""
        await device.clear_logcat()
        for _ in range(30):
            if self.is_cancelled:
                return None
            spec = IntentSpec(component=fqn, extras={"data": "X" * 5000})
            await device.start_service(spec.to_adb_args())

        await asyncio.sleep(3)
        logcat = await device.logcat_snapshot(lines=300)

        if any(kw in logcat for kw in ("ANR in", "OutOfMemoryError", "TransactionTooLarge")):
            return PluginFinding(
                title=f"Service DoS via rapid start — {svc.name}",
                description=(
                    f"Rapidly starting service {svc.name} 30 times with large extras "
                    f"causes resource exhaustion (ANR/OOM)."
                ),
                severity="medium",
                component_name=svc.name,
                component_type="service",
                cwe_id="CWE-400",
                mstg_id="MSTG-PLATFORM-2",
                owasp_mobile="M1",
                logcat_snippet=logcat[-1500:],
            )
        return None

    async def generate_poc(self, finding: PluginFinding) -> PoC | None:
        if finding.poc_command:
            return PoC(
                poc_type="adb_command",
                commands=[finding.poc_command],
                expected_result="Service crash, unauthorized command execution, or DoS",
            )
        return None
