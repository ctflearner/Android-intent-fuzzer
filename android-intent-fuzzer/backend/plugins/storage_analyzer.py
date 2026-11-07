"""StorageAnalyzerPlugin — check world-readable files, clipboard leakage, external storage exposure."""

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
)

if TYPE_CHECKING:
    from backend.core.device_manager import DeviceHandle
    from backend.core.apk_analyzer import APKAnalysis


_SECRET_RE = re.compile(
    r"(password|passwd|secret|api[_-]?key|auth[_-]?token|"
    r"session[_-]?id|private[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|jwt|bearer|pin|otp|"
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+)",
    re.IGNORECASE,
)

_WORLD_READABLE = re.compile(r"^.{7}r..", re.MULTILINE)  # others-read bit
_WORLD_WRITABLE = re.compile(r"^.{8}w.", re.MULTILINE)  # others-write bit
_SETUID_RE = re.compile(r"^...s", re.MULTILINE)


class StorageAnalyzerPlugin(BasePlugin):
    name = "storage_analyzer"
    display_name = "Storage Analyzer"
    description = (
        "Checks for world-readable/writable files, clipboard data leakage, "
        "setuid binaries in app dirs, and external storage exposure."
    )
    version = "1.0.0"
    category = PluginCategory.SCANNER
    requires_device = True
    attack_vectors = [
        "world_readable_files",
        "world_writable_files",
        "clipboard_leak",
        "external_storage_exposure",
        "setuid_binary",
    ]

    async def run(self, analysis, device, progress_callback=None) -> list[PluginFinding]:
        findings: list[PluginFinding] = []
        pkg = analysis.package_name

        # 1) Check world-readable/writable files in app data dir
        perm_findings = await self._check_file_permissions(device, pkg)
        findings.extend(perm_findings)

        if progress_callback:
            await progress_callback(plugin=self.name, progress=0.2, message="File permissions checked")

        # 2) Clipboard leakage after interacting with exported components
        clip_findings = await self._check_clipboard_leak(device, analysis)
        findings.extend(clip_findings)

        if progress_callback:
            await progress_callback(plugin=self.name, progress=0.4, message="Clipboard checked")

        # 3) External storage exposure
        ext_findings = await self._check_external_storage(device, pkg)
        findings.extend(ext_findings)

        if progress_callback:
            await progress_callback(plugin=self.name, progress=0.6, message="External storage checked")

        # 4) Setuid binaries in app directories
        suid_findings = await self._check_setuid(device, pkg)
        findings.extend(suid_findings)

        if progress_callback:
            await progress_callback(plugin=self.name, progress=0.8, message="Setuid check done")

        # 5) Shared preferences security
        prefs_findings = await self._check_shared_prefs(device, pkg)
        findings.extend(prefs_findings)

        if progress_callback:
            await progress_callback(plugin=self.name, progress=1.0, message="Storage analysis complete")

        return findings

    # ------------------------------------------------------------------
    async def _check_file_permissions(self, device, pkg) -> list[PluginFinding]:
        results: list[PluginFinding] = []
        data_dir = f"/data/data/{pkg}"

        # List files with permissions (needs root or run-as)
        ls_output = await device.shell(f"run-as {pkg} ls -laR {data_dir} 2>/dev/null")
        if not ls_output or "Permission denied" in ls_output:
            # Try with root
            ls_output = await device.shell(f"ls -laR {data_dir} 2>/dev/null")
        if not ls_output:
            return results

        current_dir = data_dir
        for line in ls_output.splitlines():
            if line.endswith(":"):
                current_dir = line.rstrip(":")
                continue
            if not line or line.startswith("total"):
                continue

            # Check world-readable
            if _WORLD_READABLE.match(line):
                filename = line.split()[-1] if line.split() else "unknown"
                filepath = f"{current_dir}/{filename}"
                results.append(PluginFinding(
                    title=f"World-readable file: {filepath}",
                    description=(
                        f"File {filepath} has world-readable permissions. Any app "
                        f"on the device can read this file."
                    ),
                    severity="medium",
                    component_type="storage",
                    cwe_id="CWE-732",
                    mstg_id="MSTG-STORAGE-2",
                    owasp_mobile="M2",
                    poc_command=f"adb shell ls -la {filepath}",
                    evidence={"permissions": line[:10], "path": filepath},
                ))

            # Check world-writable
            if _WORLD_WRITABLE.match(line):
                filename = line.split()[-1] if line.split() else "unknown"
                filepath = f"{current_dir}/{filename}"
                results.append(PluginFinding(
                    title=f"World-writable file: {filepath}",
                    description=(
                        f"File {filepath} has world-writable permissions. Any app "
                        f"can modify this file, enabling data injection or corruption."
                    ),
                    severity="high",
                    component_type="storage",
                    cvss_score=7.5,
                    cwe_id="CWE-732",
                    mstg_id="MSTG-STORAGE-2",
                    owasp_mobile="M2",
                    poc_command=f"adb shell ls -la {filepath}",
                    evidence={"permissions": line[:10], "path": filepath},
                ))

            if len(results) > 50:
                break  # cap findings for memory

        return results

    async def _check_clipboard_leak(self, device, analysis) -> list[PluginFinding]:
        results: list[PluginFinding] = []
        pkg = analysis.package_name

        # Get baseline clipboard
        baseline_clip = await device.get_clipboard()

        # Interact with exported activities that might copy to clipboard
        activities = [
            c for c in analysis.components
            if c.type == "activity" and c.exported
        ]

        for comp in activities[:10]:  # cap to avoid excessive testing
            if self.is_cancelled:
                return results
            fqn = f"{pkg}/{comp.name}"
            spec = IntentSpec(component=fqn)
            await device.start_activity(spec.to_adb_args())
            await asyncio.sleep(2)

            new_clip = await device.get_clipboard()
            if new_clip != baseline_clip and new_clip:
                # Check if sensitive data was copied
                if _SECRET_RE.search(new_clip):
                    results.append(PluginFinding(
                        title=f"Sensitive data leaked to clipboard — {comp.name}",
                        description=(
                            f"After launching {comp.name}, sensitive data was found "
                            f"in the device clipboard. Pattern: "
                            f"{_SECRET_RE.search(new_clip).group(0)[:30]}. "
                            f"Any app with READ_CLIPBOARD can access this data."
                        ),
                        severity="medium",
                        component_name=comp.name,
                        component_type="activity",
                        cwe_id="CWE-200",
                        mstg_id="MSTG-STORAGE-10",
                        owasp_mobile="M2",
                        poc_command=spec.to_adb_command("start"),
                        evidence={"clipboard_content": new_clip[:200]},
                    ))

            # Stop the activity before testing next
            await device.shell(f"am force-stop {pkg}")
            await asyncio.sleep(0.5)

        return results

    async def _check_external_storage(self, device, pkg) -> list[PluginFinding]:
        results: list[PluginFinding] = []

        ext_dirs = [
            f"/sdcard/Android/data/{pkg}",
            f"/storage/emulated/0/Android/data/{pkg}",
            f"/sdcard/{pkg}",
        ]

        for ext_dir in ext_dirs:
            ls_out = await device.shell(f"ls -laR {ext_dir} 2>/dev/null")
            if not ls_out or "No such file" in ls_out:
                continue

            files = [
                line.split()[-1]
                for line in ls_out.splitlines()
                if line and not line.startswith("total") and not line.endswith(":")
                and len(line.split()) > 5
            ]

            if not files:
                continue

            # Check for sensitive file types
            sensitive_files = [
                f for f in files
                if any(ext in f.lower() for ext in
                       (".db", ".sqlite", ".json", ".xml", ".key", ".pem",
                        ".token", ".log", ".txt", ".cfg", ".conf"))
            ]

            if sensitive_files:
                results.append(PluginFinding(
                    title=f"Sensitive files on external storage — {pkg}",
                    description=(
                        f"App stores potentially sensitive files on external storage "
                        f"at {ext_dir}. External storage is world-readable. "
                        f"Files: {', '.join(sensitive_files[:10])}"
                    ),
                    severity="medium",
                    component_type="storage",
                    cwe_id="CWE-312",
                    mstg_id="MSTG-STORAGE-2",
                    owasp_mobile="M2",
                    poc_command=f"adb shell ls -laR {ext_dir}",
                    evidence={
                        "directory": ext_dir,
                        "sensitive_files": sensitive_files[:20],
                    },
                ))

            # Try to read contents of small config/json files for secrets
            for sf in sensitive_files[:5]:
                if self.is_cancelled:
                    return results
                content = await device.shell(
                    f"cat {ext_dir}/{sf} 2>/dev/null | head -c 5000"
                )
                if content and _SECRET_RE.search(content):
                    match = _SECRET_RE.search(content)
                    results.append(PluginFinding(
                        title=f"Secret on external storage: {sf}",
                        description=(
                            f"File {ext_dir}/{sf} on external storage contains "
                            f"sensitive data: {match.group(0)[:40]}"
                        ),
                        severity="high",
                        component_type="storage",
                        cvss_score=7.5,
                        cwe_id="CWE-312",
                        mstg_id="MSTG-STORAGE-1",
                        owasp_mobile="M2",
                        poc_command=f"adb shell cat {ext_dir}/{sf}",
                        evidence={"pattern": match.group(0)[:60]},
                    ))

        return results

    async def _check_setuid(self, device, pkg) -> list[PluginFinding]:
        results: list[PluginFinding] = []
        data_dir = f"/data/data/{pkg}"

        find_out = await device.shell(
            f"find {data_dir} -perm -4000 -o -perm -2000 2>/dev/null"
        )
        if not find_out:
            return results

        for line in find_out.splitlines():
            line = line.strip()
            if line:
                results.append(PluginFinding(
                    title=f"Setuid/setgid binary in app dir: {line}",
                    description=(
                        f"Binary {line} has setuid/setgid permissions in the app's "
                        f"data directory. This can be exploited for privilege escalation."
                    ),
                    severity="critical",
                    component_type="storage",
                    cvss_score=8.8,
                    cwe_id="CWE-250",
                    mstg_id="MSTG-STORAGE-12",
                    owasp_mobile="M1",
                    poc_command=f"adb shell ls -la {line}",
                    evidence={"path": line},
                ))

        return results

    async def _check_shared_prefs(self, device, pkg) -> list[PluginFinding]:
        """Check if shared preferences files are world-readable."""
        results: list[PluginFinding] = []
        prefs_dir = f"/data/data/{pkg}/shared_prefs"

        ls_out = await device.shell(f"run-as {pkg} ls -la {prefs_dir} 2>/dev/null")
        if not ls_out:
            ls_out = await device.shell(f"ls -la {prefs_dir} 2>/dev/null")
        if not ls_out:
            return results

        for line in ls_out.splitlines():
            if not line.strip() or line.startswith("total"):
                continue
            if _WORLD_READABLE.match(line):
                filename = line.split()[-1]
                results.append(PluginFinding(
                    title=f"World-readable shared preferences: {filename}",
                    description=(
                        f"Shared preferences file {prefs_dir}/{filename} is "
                        f"world-readable (MODE_WORLD_READABLE). Any app can read it."
                    ),
                    severity="high",
                    component_type="storage",
                    cvss_score=7.0,
                    cwe_id="CWE-732",
                    mstg_id="MSTG-STORAGE-2",
                    owasp_mobile="M2",
                    poc_command=f"adb shell cat {prefs_dir}/{filename}",
                    evidence={"permissions": line[:10]},
                ))

        return results

    async def generate_poc(self, finding: PluginFinding) -> PoC | None:
        if finding.poc_command:
            return PoC(
                poc_type="adb_command",
                commands=[finding.poc_command],
                expected_result="File contents or directory listing showing exposure",
            )
        return None
