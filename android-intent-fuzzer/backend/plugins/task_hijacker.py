"""TaskHijackPlugin — static check for StrandHogg 1 & 2 conditions."""

from __future__ import annotations

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


_TASK_AFFINITY_RE = re.compile(
    r'android:taskAffinity\s*=\s*"([^"]*)"',
)
_LAUNCH_MODE_RE = re.compile(
    r'android:launchMode\s*=\s*"(singleTask|singleInstance|singleTop)"',
    re.IGNORECASE,
)
_ALLOW_REPARENT_RE = re.compile(
    r'android:allowTaskReparenting\s*=\s*"true"',
    re.IGNORECASE,
)
_EXPORTED_RE = re.compile(
    r'android:exported\s*=\s*"true"',
    re.IGNORECASE,
)

_LAUNCHER_ACTION = "android.intent.action.MAIN"
_LAUNCHER_CATEGORY = "android.intent.category.LAUNCHER"


class TaskHijackPlugin(BasePlugin):
    name = "task_hijacker"
    display_name = "Task Hijack Detector"
    description = (
        "Static check for StrandHogg 1 & 2 conditions: taskAffinity on "
        "launchable Activities, allowTaskReparenting, singleTask with "
        "exported Activity. Reports exploitability."
    )
    version = "1.0.0"
    category = PluginCategory.SCANNER
    requires_device = False
    attack_vectors = [
        "strandhogg_v1",
        "strandhogg_v2",
        "task_affinity_hijack",
    ]

    async def run(self, analysis, device, progress_callback=None) -> list[PluginFinding]:
        findings: list[PluginFinding] = []
        manifest = analysis.manifest_raw

        activities = [c for c in analysis.components if c.type == "activity"]
        total = len(activities)
        if not total:
            return findings

        # Parse per-activity blocks from manifest
        activity_blocks = self._extract_activity_blocks(manifest)

        for idx, comp in enumerate(activities):
            if self.is_cancelled:
                break

            block = activity_blocks.get(comp.name, "")
            is_launcher = self._is_launcher(comp)

            # ---- StrandHogg v1: taskAffinity + singleTask/exported ----
            affinity_match = _TASK_AFFINITY_RE.search(block)
            launch_mode_match = _LAUNCH_MODE_RE.search(block)
            reparent_match = _ALLOW_REPARENT_RE.search(block)

            has_custom_affinity = bool(
                affinity_match and affinity_match.group(1) != ""
            )
            has_single_task = bool(
                launch_mode_match
                and launch_mode_match.group(1).lower() in ("singletask", "singleinstance")
            )
            has_reparenting = bool(reparent_match)

            # StrandHogg v1: any activity with non-empty taskAffinity
            if has_custom_affinity:
                affinity_val = affinity_match.group(1)
                severity = "high" if is_launcher or comp.exported else "medium"
                findings.append(PluginFinding(
                    title=f"StrandHogg v1: custom taskAffinity — {comp.name}",
                    description=(
                        f"Activity {comp.name} has taskAffinity='{affinity_val}'. "
                        f"A malicious app can set the same taskAffinity and place itself "
                        f"on top of this activity's task, hijacking the UI. "
                        f"{'Launcher activity — high impact.' if is_launcher else ''} "
                        f"{'Exported.' if comp.exported else 'Not exported but may be started internally.'}"
                    ),
                    severity=severity,
                    component_name=comp.name,
                    component_type="activity",
                    cvss_score=7.5 if severity == "high" else 5.0,
                    cwe_id="CWE-1021",
                    mstg_id="MSTG-PLATFORM-1",
                    owasp_mobile="M1",
                    evidence={
                        "taskAffinity": affinity_val,
                        "exported": comp.exported,
                        "is_launcher": is_launcher,
                    },
                ))

            # allowTaskReparenting
            if has_reparenting:
                findings.append(PluginFinding(
                    title=f"allowTaskReparenting enabled — {comp.name}",
                    description=(
                        f"Activity {comp.name} has allowTaskReparenting=true. "
                        f"This allows the activity to move between tasks, enabling "
                        f"task hijacking when combined with taskAffinity manipulation."
                    ),
                    severity="medium",
                    component_name=comp.name,
                    component_type="activity",
                    cwe_id="CWE-1021",
                    mstg_id="MSTG-PLATFORM-1",
                    owasp_mobile="M1",
                    evidence={"allowTaskReparenting": True},
                ))

            # singleTask/singleInstance + exported
            if has_single_task and comp.exported:
                mode = launch_mode_match.group(1) if launch_mode_match else "singleTask"
                findings.append(PluginFinding(
                    title=f"Exported {mode} activity — {comp.name}",
                    description=(
                        f"Activity {comp.name} uses launchMode='{mode}' and is exported. "
                        f"An attacker can send an intent to bring this activity to the "
                        f"foreground and inject extras, potentially reading result data."
                    ),
                    severity="medium",
                    component_name=comp.name,
                    component_type="activity",
                    cwe_id="CWE-1021",
                    mstg_id="MSTG-PLATFORM-1",
                    owasp_mobile="M1",
                    evidence={"launchMode": mode, "exported": True},
                ))

            # ---- StrandHogg v2: empty taskAffinity on non-launcher ----
            if affinity_match and affinity_match.group(1) == "" and not is_launcher:
                findings.append(PluginFinding(
                    title=f"StrandHogg v2: empty taskAffinity — {comp.name}",
                    description=(
                        f"Activity {comp.name} has an empty taskAffinity (\"\"), making "
                        f"it susceptible to StrandHogg v2 where a malicious app running "
                        f"in the same task can overlay this activity."
                    ),
                    severity="medium",
                    component_name=comp.name,
                    component_type="activity",
                    cwe_id="CWE-1021",
                    mstg_id="MSTG-PLATFORM-1",
                    owasp_mobile="M1",
                    evidence={"taskAffinity": "", "is_launcher": False},
                ))

            if progress_callback and (idx + 1) % 10 == 0:
                await progress_callback(
                    plugin=self.name,
                    progress=(idx + 1) / total,
                    message=f"Checked {comp.name}",
                )

        # ---- Global: no explicit taskAffinity on launcher = default (pkg name) ----
        launcher = next((c for c in activities if self._is_launcher(c)), None)
        if launcher:
            block = activity_blocks.get(launcher.name, "")
            if not _TASK_AFFINITY_RE.search(block):
                # Default taskAffinity = package name. Any app can set matching affinity.
                findings.append(PluginFinding(
                    title=f"Default taskAffinity on launcher — {launcher.name}",
                    description=(
                        f"Launcher activity {launcher.name} uses the default taskAffinity "
                        f"(package name). While this is common, a malicious app with "
                        f"matching taskAffinity can still perform StrandHogg v1. "
                        f"Consider setting taskAffinity=\"\" on launcher."
                    ),
                    severity="low",
                    component_name=launcher.name,
                    component_type="activity",
                    cwe_id="CWE-1021",
                    mstg_id="MSTG-PLATFORM-1",
                    owasp_mobile="M1",
                    evidence={"taskAffinity": "default (package name)"},
                ))

        return findings

    # ------------------------------------------------------------------
    @staticmethod
    def _extract_activity_blocks(manifest: str) -> dict[str, str]:
        """Parse <activity> blocks from manifest XML keyed by class name."""
        blocks: dict[str, str] = {}
        pattern = re.compile(
            r'<activity\s+[^>]*android:name\s*=\s*"([^"]+)"[^>]*>(.*?)</activity>',
            re.DOTALL,
        )
        for m in pattern.finditer(manifest):
            blocks[m.group(1)] = m.group(0)
        # Also self-closing activities
        pattern_sc = re.compile(
            r'<activity\s+[^>]*android:name\s*=\s*"([^"]+)"[^>]*/\s*>',
        )
        for m in pattern_sc.finditer(manifest):
            if m.group(1) not in blocks:
                blocks[m.group(1)] = m.group(0)
        return blocks

    @staticmethod
    def _is_launcher(comp) -> bool:
        for filt in comp.intent_filters:
            actions = filt.get("actions", [])
            categories = filt.get("categories", [])
            if _LAUNCHER_ACTION in actions and _LAUNCHER_CATEGORY in categories:
                return True
        return False

    async def generate_poc(self, finding: PluginFinding) -> PoC | None:
        affinity = finding.evidence.get("taskAffinity", "")
        if affinity:
            # Generate a PoC manifest snippet
            poc_manifest = (
                f'<activity android:name=".StrandHoggPoC"\n'
                f'    android:taskAffinity="{affinity}"\n'
                f'    android:allowTaskReparenting="true"\n'
                f'    android:exported="true">\n'
                f'    <intent-filter>\n'
                f'        <action android:name="android.intent.action.MAIN"/>\n'
                f'        <category android:name="android.intent.category.LAUNCHER"/>\n'
                f'    </intent-filter>\n'
                f'</activity>'
            )
            return PoC(
                poc_type="adb_command",
                commands=[
                    f"# Install a PoC APK with the following manifest:\n{poc_manifest}",
                    "adb install poc-strandhogg.apk",
                    "adb shell am start -n com.poc.app/.StrandHoggPoC",
                ],
                expected_result="PoC activity overlays the target app's task",
            )
        return None
