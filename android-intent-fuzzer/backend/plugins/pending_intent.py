"""PendingIntentPlugin — scan for mutable PendingIntents with implicit base intents."""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING

from backend.plugins.base import (
    BasePlugin,
    PluginCategory,
    PluginFinding,
    PoC,
)

if TYPE_CHECKING:
    from backend.core.device_manager import DeviceHandle
    from backend.core.apk_analyzer import APKAnalysis


# Patterns for PendingIntent creation in decompiled source / manifest
_PI_GET_ACTIVITY = re.compile(
    r"PendingIntent\s*\.\s*getActivity\s*\(\s*[^,]+,\s*(\d+)\s*,\s*([^,]+),\s*(\d+|[A-Z_|]+)\s*\)",
    re.MULTILINE,
)
_PI_GET_BROADCAST = re.compile(
    r"PendingIntent\s*\.\s*getBroadcast\s*\(\s*[^,]+,\s*(\d+)\s*,\s*([^,]+),\s*(\d+|[A-Z_|]+)\s*\)",
    re.MULTILINE,
)
_PI_GET_SERVICE = re.compile(
    r"PendingIntent\s*\.\s*getService\s*\(\s*[^,]+,\s*(\d+)\s*,\s*([^,]+),\s*(\d+|[A-Z_|]+)\s*\)",
    re.MULTILINE,
)

_IMPLICIT_INTENT_RE = re.compile(
    r"new\s+Intent\s*\(\s*\)|Intent\s*\(\s*\)|new\s+Intent\s*\(\s*\"[^\"]+\"\s*\)",
)

_MUTABLE_FLAGS = re.compile(
    r"FLAG_MUTABLE|0x02000000",
    re.IGNORECASE,
)

# FLAG_IMMUTABLE = 0x04000000; if present, not vulnerable
_IMMUTABLE_FLAGS = re.compile(
    r"FLAG_IMMUTABLE|0x04000000|67108864",
    re.IGNORECASE,
)


class PendingIntentPlugin(BasePlugin):
    name = "pending_intent"
    display_name = "PendingIntent Analyzer"
    description = (
        "Scans for mutable PendingIntents with implicit base intents. "
        "Reports exploitation scenarios and attempts fill-in intent hijack."
    )
    version = "1.0.0"
    category = PluginCategory.SCANNER
    requires_device = False  # primarily static, device optional
    attack_vectors = [
        "pending_intent_hijack",
        "implicit_intent_interception",
        "mutable_pending_intent",
    ]

    async def run(self, analysis, device, progress_callback=None) -> list[PluginFinding]:
        findings: list[PluginFinding] = []

        # Scan manifest raw for PendingIntent patterns
        source = analysis.manifest_raw or ""

        # Also scan hardcoded_secrets list for code snippets if available
        # (some analyzers stash decompiled snippets there)
        for secret in analysis.hardcoded_secrets:
            source += "\n" + str(secret.get("context", ""))

        # Scan for PendingIntent.getActivity/getBroadcast/getService
        all_matches = []
        for pattern, pi_type in [
            (_PI_GET_ACTIVITY, "getActivity"),
            (_PI_GET_BROADCAST, "getBroadcast"),
            (_PI_GET_SERVICE, "getService"),
        ]:
            for m in pattern.finditer(source):
                all_matches.append((pi_type, m))

        total = len(all_matches)
        for idx, (pi_type, match) in enumerate(all_matches):
            if self.is_cancelled:
                break

            request_code = match.group(1)
            intent_var = match.group(2).strip()
            flags_raw = match.group(3).strip()

            # Check if immutable
            if _IMMUTABLE_FLAGS.search(flags_raw):
                continue

            is_mutable = bool(_MUTABLE_FLAGS.search(flags_raw))
            # Flags=0 is mutable by default on API < 31
            is_zero_flags = flags_raw in ("0", "0x0", "0x00000000")

            if not is_mutable and not is_zero_flags:
                continue

            # Check if the base intent is implicit (no component set)
            # Look backwards for the intent construction
            context_start = max(0, match.start() - 500)
            context_block = source[context_start:match.end()]

            is_implicit = self._check_implicit_intent(context_block, intent_var)

            severity = "high" if is_implicit else "medium"
            vuln_type = "mutable + implicit" if is_implicit else "mutable"

            finding = PluginFinding(
                title=f"Mutable PendingIntent ({pi_type}) — {vuln_type}",
                description=(
                    f"PendingIntent.{pi_type}() created with "
                    f"{'FLAG_MUTABLE' if is_mutable else 'flags=0 (mutable by default)'}. "
                    f"{'Base intent is IMPLICIT (no component set), allowing any app ' if is_implicit else 'Base intent may be explicit, but mutable flag allows '}"
                    f"to intercept and fill in the PendingIntent with arbitrary data. "
                    f"This can lead to launching arbitrary components, broadcasting "
                    f"to arbitrary receivers, or starting arbitrary services with the "
                    f"app's identity and permissions."
                ),
                severity=severity,
                component_type="code",
                cvss_score=7.7 if is_implicit else 5.5,
                cwe_id="CWE-927",
                mstg_id="MSTG-PLATFORM-4",
                owasp_mobile="M1",
                evidence={
                    "pi_type": pi_type,
                    "flags": flags_raw,
                    "is_mutable": is_mutable or is_zero_flags,
                    "is_implicit": is_implicit,
                    "intent_variable": intent_var,
                    "code_context": context_block[-300:],
                },
            )
            findings.append(finding)

            if progress_callback:
                await progress_callback(
                    plugin=self.name,
                    progress=(idx + 1) / total if total else 1.0,
                    message=f"Analyzed PendingIntent {idx + 1}/{total}",
                )

        # If device available, attempt fill-in hijack for confirmed mutable+implicit
        if device:
            for f in findings:
                if f.evidence.get("is_implicit") and f.severity == "high":
                    hijack_result = await self._attempt_fill_in_hijack(
                        device, f, analysis.package_name,
                    )
                    if hijack_result:
                        f.evidence["hijack_attempt"] = hijack_result
                        if hijack_result.get("success"):
                            f.severity = "critical"
                            f.cvss_score = 9.0
                            f.description += (
                                f"\n\nFill-in hijack confirmed on device: "
                                f"{hijack_result.get('detail', '')}"
                            )

        return findings

    # ------------------------------------------------------------------
    def _check_implicit_intent(self, code_block: str, intent_var: str) -> bool:
        """Heuristic: check if the intent variable was created without a component."""
        # Look for "new Intent()" or "new Intent(action)" without .setComponent/.setClass
        if _IMPLICIT_INTENT_RE.search(code_block):
            # Check no .setComponent or .setClass on the same variable
            component_set = re.search(
                rf"{re.escape(intent_var)}\s*\.\s*(setComponent|setClass|setClassName|setPackage)",
                code_block,
            )
            if not component_set:
                return True
        return False

    async def _attempt_fill_in_hijack(self, device, finding, pkg) -> dict:
        """Try to exploit a mutable PendingIntent by registering a receiver."""
        pi_type = finding.evidence.get("pi_type", "")
        result = {"success": False, "detail": ""}

        if pi_type == "getBroadcast":
            # Register a broadcast receiver to catch the PendingIntent
            await device.clear_logcat()
            # Trigger the component that creates the PendingIntent
            # We look for activities that might trigger it
            out = await device.shell(
                f"am broadcast -a android.intent.action.SEND "
                f"-p {pkg} --es data test"
            )
            await asyncio.sleep(2)
            logcat = await device.logcat_snapshot(lines=200)

            if "BroadcastReceiver" in logcat or "onReceive" in logcat:
                result["success"] = True
                result["detail"] = "Broadcast PendingIntent intercepted"
                result["logcat"] = logcat[-1000:]

        elif pi_type == "getActivity":
            await device.clear_logcat()
            # Try to send an intent that triggers the PendingIntent
            out = await device.shell(
                f"am start -a android.intent.action.VIEW "
                f"-p {pkg} --es redirect test"
            )
            await asyncio.sleep(2)
            logcat = await device.logcat_snapshot(lines=200)

            if "startActivity" in logcat or "ActivityNotFound" in logcat:
                result["success"] = True
                result["detail"] = "Activity PendingIntent fill-in attempt triggered"
                result["logcat"] = logcat[-1000:]

        return result

    async def generate_poc(self, finding: PluginFinding) -> PoC | None:
        pi_type = finding.evidence.get("pi_type", "getActivity")
        is_implicit = finding.evidence.get("is_implicit", False)

        if is_implicit:
            frida_script = f"""\
Java.perform(function() {{
    var PendingIntent = Java.use('android.app.PendingIntent');

    PendingIntent.{pi_type}.overload(
        'android.content.Context', 'int', 'android.content.Intent', 'int'
    ).implementation = function(ctx, reqCode, intent, flags) {{
        console.log('[PendingIntent] {pi_type} called');
        console.log('  Intent: ' + intent.toString());
        console.log('  Flags: ' + flags);
        console.log('  Component: ' + intent.getComponent());
        console.log('  Action: ' + intent.getAction());

        // Demonstrate fill-in attack
        var Intent = Java.use('android.content.Intent');
        var fillIn = Intent.$new();
        fillIn.setClassName('com.attacker', 'com.attacker.StealerActivity');
        console.log('[EXPLOIT] Fill-in intent: ' + fillIn.toString());

        return this.{pi_type}(ctx, reqCode, intent, flags);
    }};
}});
"""
            return PoC(
                poc_type="frida_script",
                frida_script=frida_script,
                expected_result="PendingIntent intercepted with attacker fill-in",
            )
        return None
