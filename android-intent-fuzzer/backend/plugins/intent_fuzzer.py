"""IntentFuzzerPlugin — schema-aware intent fuzzing on exported Activities and Services."""

from __future__ import annotations

import asyncio
import random
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


# ---------------------------------------------------------------------------
# Fuzz payload banks
# ---------------------------------------------------------------------------
_STRING_PAYLOADS = [
    "",
    "A" * 5000,
    "A" * 100_000,
    "'OR 1=1--",
    "<script>alert(1)</script>",
    "file:///etc/passwd",
    "content://com.android.contacts/data",
    "../../../data/data/com.target/databases/secret.db",
    "javascript:alert(document.cookie)",
    "%n%n%n%n%n",
    "\x00\x01\x02\xff",
    "${7*7}",
    "{{7*7}}",
    "null",
    "-1",
    "2147483647",
    "-2147483648",
    "99999999999999999999",
    "com.attacker.evil/.EvilActivity",
]

_INT_PAYLOADS = [0, -1, 1, 2147483647, -2147483648, 99999]

_FLOAT_PAYLOADS = [0.0, -1.0, float("inf"), float("-inf"), float("nan"), 1e308]

_BOOL_PAYLOADS = [True, False]

_URI_PAYLOADS = [
    "file:///etc/passwd",
    "file:///data/data/{pkg}/shared_prefs/secret.xml",
    "content://com.android.contacts/contacts",
    "javascript:alert(1)",
    "http://attacker.com",
    "intent://evil#Intent;scheme=http;end",
    "",
    "://",
]

_ACTIONS = [
    "android.intent.action.VIEW",
    "android.intent.action.EDIT",
    "android.intent.action.SEND",
    "android.intent.action.RUN",
    "com.attacker.EVIL_ACTION",
]

_CRASH_PATTERNS = re.compile(
    r"(FATAL EXCEPTION|java\.lang\.\w*Exception|NullPointerException|"
    r"SecurityException|ClassCastException|ArrayIndexOutOfBoundsException|"
    r"android\.os\.DeadObjectException|SIGSEGV|SIGABRT|ANR in|"
    r"Process.*has died|Force finishing activity|IllegalArgumentException|"
    r"ClassNotFoundException|InflateException)",
    re.IGNORECASE,
)

_DATA_LEAK_PATTERNS = re.compile(
    r"(password|token|secret|api.?key|auth|session|cookie|credential|"
    r"private.?key|BEGIN RSA|jdbc:|mysql://|postgres://)",
    re.IGNORECASE,
)


class IntentFuzzerPlugin(BasePlugin):
    name = "intent_fuzzer"
    display_name = "Intent Fuzzer"
    description = (
        "Schema-aware intent fuzzing on all exported Activities/Services. "
        "Sends crafted intents with malformed extras, type confusion, overflow "
        "values. Monitors for crashes, exceptions, data leaks."
    )
    version = "1.0.0"
    category = PluginCategory.FUZZER
    requires_device = True
    attack_vectors = [
        "intent_injection",
        "type_confusion",
        "buffer_overflow",
        "null_extras",
        "data_leak",
    ]

    # ------------------------------------------------------------------
    async def run(self, analysis, device, progress_callback=None) -> list[PluginFinding]:
        findings: list[PluginFinding] = []

        targets = [
            c for c in analysis.components
            if c.exported and c.type in ("activity", "service")
        ]
        total = len(targets)
        if not total:
            return findings

        for idx, comp in enumerate(targets):
            if self.is_cancelled:
                break

            comp_findings = await self._fuzz_component(
                analysis, device, comp,
            )
            findings.extend(comp_findings)

            if progress_callback:
                await progress_callback(
                    plugin=self.name,
                    progress=(idx + 1) / total,
                    message=f"Fuzzed {comp.name}",
                )

        return findings

    # ------------------------------------------------------------------
    async def _fuzz_component(self, analysis, device, comp) -> list[PluginFinding]:
        results: list[PluginFinding] = []
        pkg = analysis.package_name
        fqn = f"{pkg}/{comp.name}" if not comp.name.startswith(pkg) else f"{pkg}/{comp.name}"

        am_cmd = "start" if comp.type == "activity" else "startservice"

        # ---- 1) null / empty intent -----------------------------------
        await device.clear_logcat()
        spec = IntentSpec(component=fqn)
        out = await device.am(am_cmd, spec.to_adb_args())
        logcat = await device.logcat_snapshot(lines=300)
        finding = self._check_crash(logcat, comp, spec, "Null/empty intent", out)
        if finding:
            results.append(finding)

        # ---- 2) fuzz each intent-filter action with payloads ----------
        for filt in comp.intent_filters:
            actions = filt.get("actions", [])
            for action in (actions or _ACTIONS[:2]):
                for payload_name, extras in self._generate_extra_combos(pkg):
                    if self.is_cancelled:
                        return results
                    await device.clear_logcat()
                    spec = IntentSpec(
                        action=action,
                        component=fqn,
                        extras=extras,
                    )
                    out = await device.am(am_cmd, spec.to_adb_args())
                    logcat = await device.logcat_snapshot(lines=300)

                    finding = self._check_crash(
                        logcat, comp, spec, f"Fuzz extras ({payload_name})", out,
                    )
                    if finding:
                        results.append(finding)

                    leak = self._check_data_leak(logcat, comp, spec, payload_name)
                    if leak:
                        results.append(leak)

        # ---- 3) URI data fuzzing --------------------------------------
        for uri_template in _URI_PAYLOADS:
            if self.is_cancelled:
                return results
            uri = uri_template.replace("{pkg}", pkg)
            await device.clear_logcat()
            spec = IntentSpec(component=fqn, data_uri=uri)
            out = await device.am(am_cmd, spec.to_adb_args())
            logcat = await device.logcat_snapshot(lines=300)
            finding = self._check_crash(logcat, comp, spec, f"URI fuzz: {uri[:60]}", out)
            if finding:
                results.append(finding)

        # ---- 4) type-confusion: send int where string expected --------
        await device.clear_logcat()
        spec = IntentSpec(
            component=fqn,
            extras={"url": 12345, "data": -1, "id": "not_an_int"},
        )
        out = await device.am(am_cmd, spec.to_adb_args())
        logcat = await device.logcat_snapshot(lines=300)
        finding = self._check_crash(logcat, comp, spec, "Type confusion extras", out)
        if finding:
            results.append(finding)

        return results

    # ------------------------------------------------------------------
    def _generate_extra_combos(self, pkg: str):
        """Yield (name, extras_dict) tuples — bounded set of fuzz combos."""
        common_keys = [
            "url", "data", "uri", "path", "file", "id", "user_id",
            "token", "query", "redirect", "callback", "next", "action",
            "package", "component", "class", "fragment",
        ]
        # String payloads
        for key in common_keys:
            for sp in _STRING_PAYLOADS[:8]:  # cap to avoid combinatorial explosion
                yield (f"str-{key}", {key: sp})
        # Int payloads
        for key in ("id", "user_id", "count", "index", "position"):
            for ip in _INT_PAYLOADS:
                yield (f"int-{key}={ip}", {key: ip})
        # Multi-key combo
        yield (
            "multi-key-overflow",
            {k: "A" * 5000 for k in common_keys[:6]},
        )

    # ------------------------------------------------------------------
    def _check_crash(self, logcat, comp, spec, test_name, am_output) -> PluginFinding | None:
        combined = logcat + "\n" + am_output
        match = _CRASH_PATTERNS.search(combined)
        if not match:
            return None

        exc_type = match.group(0)
        severity = "high"
        if "SecurityException" in exc_type:
            severity = "medium"

        return PluginFinding(
            title=f"Crash via intent fuzzing: {exc_type} in {comp.name}",
            description=(
                f"Sending a crafted intent to {comp.name} ({comp.type}) triggered "
                f"{exc_type}. Test: {test_name}."
            ),
            severity=severity,
            component_name=comp.name,
            component_type=comp.type,
            cwe_id="CWE-20",
            mstg_id="MSTG-PLATFORM-2",
            owasp_mobile="M1",
            poc_command=spec.to_adb_command("start" if comp.type == "activity" else "startservice"),
            logcat_snippet=self._trim_logcat(logcat, exc_type),
            evidence={"am_output": am_output, "test": test_name},
        )

    def _check_data_leak(self, logcat, comp, spec, test_name) -> PluginFinding | None:
        match = _DATA_LEAK_PATTERNS.search(logcat)
        if not match:
            return None
        return PluginFinding(
            title=f"Data leak in logcat from {comp.name}",
            description=(
                f"After sending fuzzed intent ({test_name}), logcat contains "
                f"sensitive data pattern: {match.group(0)}"
            ),
            severity="medium",
            component_name=comp.name,
            component_type=comp.type,
            cwe_id="CWE-532",
            mstg_id="MSTG-STORAGE-3",
            owasp_mobile="M2",
            poc_command=spec.to_adb_command("start" if comp.type == "activity" else "startservice"),
            logcat_snippet=self._trim_logcat(logcat, match.group(0)),
            evidence={"leaked_pattern": match.group(0)},
        )

    @staticmethod
    def _trim_logcat(logcat: str, keyword: str, context: int = 15) -> str:
        lines = logcat.splitlines()
        for i, line in enumerate(lines):
            if keyword in line:
                start = max(0, i - context)
                end = min(len(lines), i + context + 1)
                return "\n".join(lines[start:end])
        return logcat[-2000:] if len(logcat) > 2000 else logcat

    # ------------------------------------------------------------------
    async def generate_poc(self, finding: PluginFinding) -> PoC | None:
        if finding.poc_command:
            return PoC(
                poc_type="adb_command",
                commands=[finding.poc_command],
                expected_result="Application crash or exception in logcat",
            )
        return None

    async def validate_result(self, finding, device, execution_result) -> ValidationVerdict:
        if not finding.poc_command:
            return ValidationVerdict(status="needs_manual")
        await device.clear_logcat()
        # replay the poc
        parts = finding.poc_command.split()
        # strip leading "adb shell am"
        am_args = parts[3:]  # after "am"
        sub = am_args[0] if am_args else "start"
        await device.am(sub, am_args[1:])
        await asyncio.sleep(2)
        logcat = await device.logcat_snapshot(lines=300)
        if _CRASH_PATTERNS.search(logcat):
            return ValidationVerdict(
                status="confirmed",
                poc_command=finding.poc_command,
                logcat_snippet=logcat[-2000:],
            )
        return ValidationVerdict(status="false_positive", notes="Crash not reproducible on replay")
