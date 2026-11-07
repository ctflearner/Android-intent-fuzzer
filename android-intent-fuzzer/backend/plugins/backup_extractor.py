"""BackupExtractorPlugin — check allowBackup and analyze extracted backup data."""

from __future__ import annotations

import asyncio
import os
import re
import tempfile
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


_ALLOW_BACKUP_RE = re.compile(
    r'android:allowBackup\s*=\s*"(true|false)"',
    re.IGNORECASE,
)

_FULL_BACKUP_ONLY_RE = re.compile(
    r'android:fullBackupOnly\s*=\s*"true"',
    re.IGNORECASE,
)

_BACKUP_AGENT_RE = re.compile(
    r'android:backupAgent\s*=\s*"([^"]*)"',
    re.IGNORECASE,
)

_SECRET_PATTERNS = re.compile(
    r"(password|passwd|secret|api[_-]?key|auth[_-]?token|"
    r"session[_-]?id|private[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|jwt|bearer|Basic [A-Za-z0-9+/=]{10,}|"
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+|"  # JWT
    r"AKIA[0-9A-Z]{16}|"  # AWS key
    r"-----BEGIN (RSA |EC )?PRIVATE KEY|"
    r"jdbc:|mysql://|postgres://|mongodb://)",
    re.IGNORECASE,
)

_DB_FILE_RE = re.compile(r"\.(db|sqlite|sqlite3)$", re.IGNORECASE)
_PREFS_FILE_RE = re.compile(r"\.xml$", re.IGNORECASE)


class BackupExtractorPlugin(BasePlugin):
    name = "backup_extractor"
    display_name = "Backup Extractor"
    description = (
        "Checks android:allowBackup flag. If device available, runs adb backup "
        "and analyzes extracted data for secrets, databases, shared preferences."
    )
    version = "1.0.0"
    category = PluginCategory.SCANNER
    requires_device = False  # static check works without device
    attack_vectors = [
        "backup_data_extraction",
        "credential_theft",
        "sensitive_data_exposure",
    ]

    async def run(self, analysis, device, progress_callback=None) -> list[PluginFinding]:
        findings: list[PluginFinding] = []
        manifest = analysis.manifest_raw
        pkg = analysis.package_name

        # 1) Static: check allowBackup flag
        backup_match = _ALLOW_BACKUP_RE.search(manifest)
        allow_backup = True  # default is true if not specified
        if backup_match:
            allow_backup = backup_match.group(1).lower() == "true"

        if allow_backup:
            has_agent = bool(_BACKUP_AGENT_RE.search(manifest))
            full_only = bool(_FULL_BACKUP_ONLY_RE.search(manifest))

            severity = "medium"
            desc_extra = ""
            if not has_agent:
                severity = "high"
                desc_extra = (
                    "No custom BackupAgent is defined, so the default backup includes "
                    "all app data: databases, shared preferences, and files."
                )
            elif full_only:
                desc_extra = (
                    "fullBackupOnly=true with custom BackupAgent. Full data backup "
                    "is performed on supported devices."
                )

            findings.append(PluginFinding(
                title=f"Application allows backup — {pkg}",
                description=(
                    f"android:allowBackup is {'explicitly set to true' if backup_match else 'not set (defaults to true)'}. "
                    f"An attacker with physical access or ADB can extract the app's data "
                    f"using 'adb backup'. {desc_extra}"
                ),
                severity=severity,
                component_type="application",
                cvss_score=5.5 if severity == "medium" else 7.0,
                cwe_id="CWE-312",
                mstg_id="MSTG-STORAGE-8",
                owasp_mobile="M2",
                poc_command=f"adb backup -apk -shared {pkg}",
                evidence={
                    "allowBackup": allow_backup,
                    "hasBackupAgent": has_agent,
                    "fullBackupOnly": full_only,
                },
            ))
        else:
            # allowBackup=false — check if there are exceptions
            if progress_callback:
                await progress_callback(
                    plugin=self.name,
                    progress=0.5,
                    message="allowBackup=false, checking edge cases",
                )

        # 2) If device available and backup enabled, attempt extraction
        if device and allow_backup:
            extract_findings = await self._extract_and_analyze(device, pkg)
            findings.extend(extract_findings)

        # 3) Check for debuggable + backup combination
        if "android:debuggable=\"true\"" in manifest.lower() and allow_backup:
            findings.append(PluginFinding(
                title=f"Debuggable app with backup enabled — {pkg}",
                description=(
                    f"App is both debuggable and allows backup. An attacker can use "
                    f"'run-as {pkg}' to access app data directly, and also extract "
                    f"full backup via ADB. Double exposure path."
                ),
                severity="critical",
                component_type="application",
                cvss_score=9.0,
                cwe_id="CWE-489",
                mstg_id="MSTG-STORAGE-8",
                owasp_mobile="M2",
                poc_command=f"adb shell run-as {pkg} ls /data/data/{pkg}/",
                evidence={"debuggable": True, "allowBackup": True},
            ))

        if progress_callback:
            await progress_callback(
                plugin=self.name,
                progress=1.0,
                message="Backup analysis complete",
            )

        return findings

    # ------------------------------------------------------------------
    async def _extract_and_analyze(self, device, pkg) -> list[PluginFinding]:
        """Run adb backup and analyze the extracted data."""
        results: list[PluginFinding] = []

        with tempfile.TemporaryDirectory(prefix="ih_backup_") as tmpdir:
            backup_path = os.path.join(tmpdir, f"{pkg}.ab")
            tar_path = os.path.join(tmpdir, f"{pkg}.tar")
            extract_dir = os.path.join(tmpdir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)

            # Run adb backup (non-interactive with auto-confirm via key event)
            proc = await asyncio.create_subprocess_exec(
                "adb", "backup", "-noapk", "-noshared", pkg,
                "-f", backup_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Auto-confirm the backup dialog on device
            await asyncio.sleep(2)
            await device.shell("input keyevent 61 && input keyevent 66")  # tab + enter
            try:
                await asyncio.wait_for(proc.communicate(), timeout=30)
            except asyncio.TimeoutError:
                proc.kill()
                return results

            if not os.path.exists(backup_path) or os.path.getsize(backup_path) < 100:
                return results

            # Convert .ab to .tar using dd + openssl (strip 24-byte header)
            conv_proc = await asyncio.create_subprocess_shell(
                f"dd if={backup_path} bs=1 skip=24 2>/dev/null | "
                f"python3 -c \"import sys,zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))\" "
                f"> {tar_path}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(conv_proc.communicate(), timeout=30)

            if not os.path.exists(tar_path) or os.path.getsize(tar_path) < 100:
                return results

            # Extract tar
            ext_proc = await asyncio.create_subprocess_shell(
                f"tar xf {tar_path} -C {extract_dir} 2>/dev/null",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(ext_proc.communicate(), timeout=30)

            # Analyze extracted files
            results.extend(await self._analyze_extracted(extract_dir, pkg))

        return results

    async def _analyze_extracted(self, extract_dir: str, pkg: str) -> list[PluginFinding]:
        results: list[PluginFinding] = []
        files_scanned = 0
        max_files = 500  # bound to avoid memory issues

        for root, _dirs, files in os.walk(extract_dir):
            for filename in files:
                if files_scanned >= max_files:
                    break
                files_scanned += 1

                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, extract_dir)

                # Check database files
                if _DB_FILE_RE.search(filename):
                    results.append(PluginFinding(
                        title=f"Database extracted from backup: {filename}",
                        description=(
                            f"Database file '{rel_path}' was extracted from the app's "
                            f"backup. It may contain user data, credentials, or tokens."
                        ),
                        severity="medium",
                        component_type="application",
                        cwe_id="CWE-312",
                        mstg_id="MSTG-STORAGE-8",
                        owasp_mobile="M2",
                        evidence={"file": rel_path, "type": "database"},
                    ))

                # Scan text-based files for secrets
                if self._is_text_file(filename):
                    try:
                        with open(filepath, "r", errors="replace") as f:
                            content = f.read(50_000)  # cap at 50KB
                    except OSError:
                        continue

                    for m in _SECRET_PATTERNS.finditer(content):
                        # Get surrounding context
                        start = max(0, m.start() - 50)
                        end = min(len(content), m.end() + 100)
                        context = content[start:end]

                        results.append(PluginFinding(
                            title=f"Secret in backup file: {filename}",
                            description=(
                                f"Sensitive data pattern '{m.group(0)[:40]}' found in "
                                f"backup file '{rel_path}'."
                            ),
                            severity="high",
                            component_type="application",
                            cvss_score=7.5,
                            cwe_id="CWE-312",
                            mstg_id="MSTG-STORAGE-1",
                            owasp_mobile="M2",
                            evidence={
                                "file": rel_path,
                                "pattern": m.group(0)[:60],
                                "context": context[:200],
                            },
                        ))
                        break  # one finding per file is enough

        return results

    @staticmethod
    def _is_text_file(filename: str) -> bool:
        text_exts = (".xml", ".json", ".txt", ".properties", ".cfg", ".conf",
                     ".ini", ".yaml", ".yml", ".plist", ".csv", ".log")
        return any(filename.lower().endswith(ext) for ext in text_exts)

    async def generate_poc(self, finding: PluginFinding) -> PoC | None:
        if finding.poc_command:
            return PoC(
                poc_type="adb_command",
                commands=[
                    finding.poc_command,
                    "# Then extract: dd if=backup.ab bs=1 skip=24 | python3 -c 'import sys,zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))' > backup.tar",
                    "# Extract: tar xf backup.tar",
                ],
                expected_result="App data extracted including databases and preferences",
            )
        return None
