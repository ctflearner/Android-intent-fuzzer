"""BroadcastPlugin — test exported broadcast receivers for injection and interception."""

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
    r"SecurityException|ClassCastException|SIGSEGV|ANR in|"
    r"BroadcastQueue.*timeout|DeadObjectException)",
    re.IGNORECASE,
)

_DATA_LEAK_RE = re.compile(
    r"(password|token|secret|api.?key|auth|session|cookie|credential|"
    r"private.?key|otp|pin_code|verification_code)",
    re.IGNORECASE,
)

_BROADCAST_PAYLOADS = [
    # String extras with common keys
    {"command": "malicious", "action": "execute", "data": "A" * 5000},
    {"url": "http://attacker.com", "callback": "http://evil.com"},
    {"query": "' OR 1=1--", "search": "<script>alert(1)</script>"},
    {"package": "com.attacker.evil", "component": "com.attacker/.Evil"},
    # Type confusion
    {"count": "not_a_number", "id": "AAAA"},
    # Empty / null-like
    {},
]

_BROADCAST_INT_EXTRAS = [
    {"command_code": 0},
    {"command_code": -1},
    {"command_code": 9999},
    {"admin_level": 999},
]

_SENSITIVE_ACTIONS = [
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.PACKAGE_REPLACED",
    "android.intent.action.MY_PACKAGE_REPLACED",
    "android.intent.action.USER_PRESENT",
    "android.intent.action.NEW_OUTGOING_CALL",
    "android.provider.Telephony.SMS_RECEIVED",
]


class BroadcastPlugin(BasePlugin):
    name = "broadcast_analyzer"
    display_name = "Broadcast Receiver Analyzer"
    description = (
        "Tests exported broadcast receivers with crafted data, ordered broadcast "
        "interception, and sticky broadcast injection."
    )
    version = "1.0.0"
    category = PluginCategory.FUZZER
    requires_device = True
    attack_vectors = [
        "broadcast_injection",
        "ordered_broadcast_intercept",
        "sticky_broadcast",
        "receiver_dos",
    ]

    async def run(self, analysis, device, progress_callback=None) -> list[PluginFinding]:
        findings: list[PluginFinding] = []

        receivers = [
            c for c in analysis.components
            if c.type == "receiver" and c.exported
        ]
        total = len(receivers)
        if not total:
            return findings

        for idx, recv in enumerate(receivers):
            if self.is_cancelled:
                break

            pkg = analysis.package_name
            fqn = f"{pkg}/{recv.name}" if not recv.name.startswith(pkg) else f"{pkg}/{recv.name}"

            # Get registered actions from intent filters
            actions = []
            for filt in recv.intent_filters:
                actions.extend(filt.get("actions", []))
            if not actions:
                actions = ["com.test.FUZZ_ACTION"]

            for action in actions:
                # 1) Malformed data injection
                inj_findings = await self._test_injection(device, fqn, action, recv)
                findings.extend(inj_findings)

                # 2) Check for data leaks after broadcast
                leak = await self._test_data_leak(device, fqn, action, recv)
                if leak:
                    findings.append(leak)

            # 3) Ordered broadcast interception
            ord_f = await self._test_ordered_broadcast(device, recv, actions, pkg)
            if ord_f:
                findings.append(ord_f)

            # 4) DoS via rapid broadcast
            dos_f = await self._test_dos(device, fqn, actions, recv)
            if dos_f:
                findings.append(dos_f)

            # 5) Check if receiver handles sensitive system broadcasts without protection
            sens_f = self._check_sensitive_actions(recv, actions, pkg)
            if sens_f:
                findings.append(sens_f)

            if progress_callback:
                await progress_callback(
                    plugin=self.name,
                    progress=(idx + 1) / total,
                    message=f"Tested receiver {recv.name}",
                )

        # 6) Sticky broadcast injection (global check)
        sticky_f = await self._test_sticky_broadcast(device, analysis.package_name)
        if sticky_f:
            findings.append(sticky_f)

        return findings

    # ------------------------------------------------------------------
    async def _test_injection(self, device, fqn, action, recv) -> list[PluginFinding]:
        results: list[PluginFinding] = []
        for payload_set in _BROADCAST_PAYLOADS:
            if self.is_cancelled:
                return results
            await device.clear_logcat()
            spec = IntentSpec(action=action, component=fqn, extras=payload_set)
            out = await device.send_broadcast(spec.to_adb_args())
            await asyncio.sleep(0.5)
            logcat = await device.logcat_snapshot(lines=200)

            if _CRASH_RE.search(logcat + out):
                exc = _CRASH_RE.search(logcat + out).group(0)
                results.append(PluginFinding(
                    title=f"Broadcast injection crash: {exc} — {recv.name}",
                    description=(
                        f"Sending crafted broadcast to {recv.name} with extras "
                        f"{payload_set} triggers {exc}."
                    ),
                    severity="high",
                    component_name=recv.name,
                    component_type="receiver",
                    cwe_id="CWE-20",
                    mstg_id="MSTG-PLATFORM-2",
                    owasp_mobile="M1",
                    poc_command=spec.to_adb_command("broadcast"),
                    logcat_snippet=logcat[-1500:],
                    evidence={"extras": payload_set},
                ))
                break

        # Int extras
        for int_extras in _BROADCAST_INT_EXTRAS:
            if self.is_cancelled:
                return results
            await device.clear_logcat()
            spec = IntentSpec(action=action, component=fqn, extras=int_extras)
            out = await device.send_broadcast(spec.to_adb_args())
            await asyncio.sleep(0.5)
            logcat = await device.logcat_snapshot(lines=200)

            if _CRASH_RE.search(logcat + out):
                exc = _CRASH_RE.search(logcat + out).group(0)
                results.append(PluginFinding(
                    title=f"Broadcast int-extra crash: {exc} — {recv.name}",
                    description=(
                        f"Sending integer extras {int_extras} to {recv.name} triggers {exc}."
                    ),
                    severity="high",
                    component_name=recv.name,
                    component_type="receiver",
                    cwe_id="CWE-20",
                    mstg_id="MSTG-PLATFORM-2",
                    owasp_mobile="M1",
                    poc_command=spec.to_adb_command("broadcast"),
                    logcat_snippet=logcat[-1500:],
                ))
                break

        return results

    async def _test_data_leak(self, device, fqn, action, recv) -> PluginFinding | None:
        await device.clear_logcat()
        spec = IntentSpec(action=action, component=fqn)
        await device.send_broadcast(spec.to_adb_args())
        await asyncio.sleep(1)
        logcat = await device.logcat_snapshot(lines=300)

        match = _DATA_LEAK_RE.search(logcat)
        if match:
            return PluginFinding(
                title=f"Data leak after broadcast to {recv.name}",
                description=(
                    f"After sending broadcast to {recv.name}, logcat exposes sensitive "
                    f"data matching pattern: {match.group(0)}."
                ),
                severity="medium",
                component_name=recv.name,
                component_type="receiver",
                cwe_id="CWE-532",
                mstg_id="MSTG-STORAGE-3",
                owasp_mobile="M2",
                poc_command=spec.to_adb_command("broadcast"),
                logcat_snippet=logcat[-1500:],
                evidence={"leaked_pattern": match.group(0)},
            )
        return None

    async def _test_ordered_broadcast(self, device, recv, actions, pkg) -> PluginFinding | None:
        """Check if app sends ordered broadcasts we can intercept."""
        # Register a high-priority receiver and trigger the app's broadcast
        for action in actions:
            if self.is_cancelled:
                return None
            await device.clear_logcat()
            # Start a shell receiver at max priority
            cmd = (
                f"am broadcast -a {action} "
                f"--receiver-permission null "
                f"-f 0x00000020"  # FLAG_RECEIVER_REPLACE_PENDING
            )
            out = await device.shell(cmd)
            await asyncio.sleep(1)
            logcat = await device.logcat_snapshot(tag="BroadcastQueue", lines=200)

            if "ordered=true" in logcat.lower() or "resultcode" in logcat.lower():
                return PluginFinding(
                    title=f"Ordered broadcast interception — {recv.name} ({action})",
                    description=(
                        f"Broadcast receiver {recv.name} handles ordered broadcasts "
                        f"for action {action}. A malicious app can register a "
                        f"higher-priority receiver to intercept or abort the broadcast."
                    ),
                    severity="medium",
                    component_name=recv.name,
                    component_type="receiver",
                    cwe_id="CWE-925",
                    mstg_id="MSTG-PLATFORM-4",
                    owasp_mobile="M1",
                    poc_command=f"adb shell {cmd}",
                    logcat_snippet=logcat[-1500:],
                    evidence={"action": action},
                )
        return None

    async def _test_dos(self, device, fqn, actions, recv) -> PluginFinding | None:
        """Rapid-fire broadcasts to test for ANR/DoS."""
        action = actions[0] if actions else "com.test.DOS"
        await device.clear_logcat()
        # send 50 rapid broadcasts
        for _ in range(50):
            if self.is_cancelled:
                return None
            spec = IntentSpec(action=action, component=fqn, extras={"data": "A" * 1000})
            await device.send_broadcast(spec.to_adb_args())

        await asyncio.sleep(3)
        logcat = await device.logcat_snapshot(lines=300)

        if "ANR in" in logcat or "BroadcastQueue" in logcat and "timeout" in logcat.lower():
            return PluginFinding(
                title=f"Broadcast DoS / ANR — {recv.name}",
                description=(
                    f"Sending 50 rapid broadcasts to {recv.name} triggers ANR or "
                    f"broadcast queue timeout, causing denial of service."
                ),
                severity="medium",
                component_name=recv.name,
                component_type="receiver",
                cwe_id="CWE-400",
                mstg_id="MSTG-PLATFORM-2",
                owasp_mobile="M1",
                poc_command=f'for i in $(seq 50); do adb shell am broadcast -a {action} -n {fqn} --es data "{"A"*1000}"; done',
                logcat_snippet=logcat[-1500:],
            )
        return None

    def _check_sensitive_actions(self, recv, actions, pkg) -> PluginFinding | None:
        """Static: exported receiver handles sensitive system actions without permission."""
        if recv.permission:
            return None
        for action in actions:
            if action in _SENSITIVE_ACTIONS:
                return PluginFinding(
                    title=f"Unprotected receiver for sensitive action — {recv.name}",
                    description=(
                        f"Exported receiver {recv.name} handles sensitive system action "
                        f"'{action}' without requiring a permission. Any app can trigger it."
                    ),
                    severity="medium",
                    component_name=recv.name,
                    component_type="receiver",
                    cwe_id="CWE-862",
                    mstg_id="MSTG-PLATFORM-4",
                    owasp_mobile="M1",
                    evidence={"action": action},
                )
        return None

    async def _test_sticky_broadcast(self, device, pkg) -> PluginFinding | None:
        """Try sending a sticky broadcast (requires BROADCAST_STICKY permission)."""
        await device.clear_logcat()
        out = await device.shell(
            f'am broadcast --sticky -a com.{pkg}.STICKY_TEST --es data "injected"'
        )
        logcat = await device.logcat_snapshot(lines=100)
        if "SecurityException" not in out and "Broadcast completed" in out:
            return PluginFinding(
                title="Sticky broadcast injection possible",
                description=(
                    f"Successfully sent a sticky broadcast to package {pkg}. "
                    f"Sticky broadcasts persist and can be read by future receivers."
                ),
                severity="low",
                component_type="receiver",
                cwe_id="CWE-925",
                mstg_id="MSTG-PLATFORM-4",
                owasp_mobile="M1",
                poc_command=f'adb shell am broadcast --sticky -a com.{pkg}.STICKY_TEST --es data "injected"',
                response_data=out[:1000],
            )
        return None

    async def generate_poc(self, finding: PluginFinding) -> PoC | None:
        if finding.poc_command:
            return PoC(
                poc_type="adb_command",
                commands=[finding.poc_command],
                expected_result="Crash, data leak, or successful injection",
            )
        return None
