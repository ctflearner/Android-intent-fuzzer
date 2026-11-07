"""AttackChainPlugin — post-processing: chain findings into multi-step attack paths."""

from __future__ import annotations

import itertools
from typing import TYPE_CHECKING

from backend.plugins.base import (
    BasePlugin,
    PluginCategory,
    PluginFinding,
)

if TYPE_CHECKING:
    from backend.core.device_manager import DeviceHandle
    from backend.core.apk_analyzer import APKAnalysis


# ---------------------------------------------------------------------------
# Chain rule definitions
# ---------------------------------------------------------------------------
# Each rule: (name, description, required_cwe_set, severity_boost, cvss)
# If a findings set matches all CWEs in required_cwe_set, a chain is created.
_CHAIN_RULES: list[tuple[str, str, set[str], str, float]] = [
    (
        "Intent Redirect → Internal Activity Access",
        "Deep link or broadcast injection redirects to an internal (unexported) "
        "activity via a confused deputy pattern. Attacker chains deep link abuse "
        "with intent redirect to access protected functionality.",
        {"CWE-926", "CWE-20"},
        "critical",
        9.0,
    ),
    (
        "Fragment Injection → Privilege Escalation",
        "Exported PreferenceActivity + fragment injection allows loading privileged "
        "fragments (e.g., DevelopmentSettings). Chained with task hijacking for "
        "seamless exploitation.",
        {"CWE-470", "CWE-1021"},
        "critical",
        9.0,
    ),
    (
        "Content Provider SQLi → Data Exfiltration",
        "SQL injection in an exported content provider combined with world-readable "
        "storage allows full database extraction and offline analysis.",
        {"CWE-89", "CWE-732"},
        "critical",
        9.5,
    ),
    (
        "WebView JS Injection → Token Theft",
        "JavaScript injection in a WebView combined with sensitive data logged "
        "or stored insecurely enables stealing authentication tokens.",
        {"CWE-79", "CWE-312"},
        "critical",
        9.0,
    ),
    (
        "WebView JS Injection → Local File Read",
        "JavaScript injection in a WebView combined with file:// access enables "
        "reading the app's private files (databases, shared preferences).",
        {"CWE-79", "CWE-200"},
        "critical",
        9.0,
    ),
    (
        "Mutable PendingIntent → Confused Deputy → RCE",
        "Mutable PendingIntent with implicit base intent allows fill-in attack. "
        "Chained with an exported service that executes commands, this achieves "
        "RCE with the victim app's permissions.",
        {"CWE-927", "CWE-862"},
        "critical",
        9.8,
    ),
    (
        "Backup Extraction → Credential Theft",
        "App allows backup + stores secrets in plain text. Attacker extracts "
        "backup via ADB and recovers credentials.",
        {"CWE-312", "CWE-312"},  # same CWE different contexts
        "high",
        8.0,
    ),
    (
        "Broadcast Injection → DoS + Data Leak",
        "Exported broadcast receiver crashes on malformed input while leaking "
        "sensitive data in logcat during the exception handling.",
        {"CWE-20", "CWE-532"},
        "high",
        7.5,
    ),
    (
        "FileProvider Traversal → Full Data Access",
        "Path traversal through FileProvider combined with content provider "
        "access grants arbitrary file read within the app's data directory.",
        {"CWE-22", "CWE-200"},
        "critical",
        9.0,
    ),
    (
        "Task Hijacking → Phishing",
        "StrandHogg task affinity abuse overlays a phishing activity on top of "
        "the target app. Combined with exported activity, the attack requires "
        "no special permissions.",
        {"CWE-1021"},
        "high",
        7.5,
    ),
    (
        "External Storage + Clipboard → Session Hijack",
        "Sensitive tokens on external storage or clipboard enable session "
        "hijacking from a malicious app.",
        {"CWE-200", "CWE-312"},
        "high",
        8.0,
    ),
]

# Confused deputy patterns: component A (exported) calls component B (unexported)
_CONFUSED_DEPUTY_INTENTS = {
    "activity": ["startActivity", "startActivityForResult"],
    "service": ["startService", "bindService"],
    "receiver": ["sendBroadcast", "sendOrderedBroadcast"],
}


class AttackChainPlugin(BasePlugin):
    name = "attack_chain"
    display_name = "Attack Chain Builder"
    description = (
        "Post-processing plugin: maps inter-component flows, detects confused "
        "deputy patterns, chains findings into multi-step attack paths."
    )
    version = "1.0.0"
    category = PluginCategory.ANALYZER
    requires_device = False
    attack_vectors = [
        "attack_chain",
        "confused_deputy",
        "multi_step_exploitation",
    ]

    async def run(self, analysis, device, progress_callback=None) -> list[PluginFinding]:
        # This plugin expects other findings passed in analysis.
        # We look for them in the evidence dict or a custom attribute.
        return []

    async def run_post_process(
        self,
        analysis,
        all_findings: list[PluginFinding],
        device=None,
        progress_callback=None,
    ) -> list[PluginFinding]:
        """Main entry for post-processing — called by the scan engine after all plugins."""
        chain_findings: list[PluginFinding] = []

        if not all_findings:
            return chain_findings

        # Index findings by CWE
        cwe_index: dict[str, list[PluginFinding]] = {}
        for f in all_findings:
            if f.cwe_id:
                cwe_index.setdefault(f.cwe_id, []).append(f)

        # Index by component
        comp_index: dict[str, list[PluginFinding]] = {}
        for f in all_findings:
            if f.component_name:
                comp_index.setdefault(f.component_name, []).append(f)

        total_rules = len(_CHAIN_RULES)

        # 1) Rule-based chain detection
        for idx, (name, desc, required_cwes, severity, cvss) in enumerate(_CHAIN_RULES):
            if self.is_cancelled:
                break

            # Check if we have findings matching all required CWEs
            matched_findings: list[PluginFinding] = []
            all_cwes_present = True
            for cwe in required_cwes:
                if cwe in cwe_index:
                    matched_findings.extend(cwe_index[cwe][:2])  # max 2 per CWE
                else:
                    all_cwes_present = False
                    break

            if not all_cwes_present or not matched_findings:
                continue

            # Deduplicate
            seen_titles = set()
            unique_findings = []
            for mf in matched_findings:
                if mf.title not in seen_titles:
                    seen_titles.add(mf.title)
                    unique_findings.append(mf)

            steps = "\n".join(
                f"  Step {i+1}: [{f.severity.upper()}] {f.title}"
                for i, f in enumerate(unique_findings)
            )

            chain_findings.append(PluginFinding(
                title=f"Attack Chain: {name}",
                description=(
                    f"{desc}\n\n"
                    f"Chain steps:\n{steps}\n\n"
                    f"Combined impact exceeds individual findings."
                ),
                severity=severity,
                cvss_score=cvss,
                cwe_id=",".join(required_cwes),
                mstg_id="MSTG-ARCH-2",
                owasp_mobile="M1",
                evidence={
                    "chain_name": name,
                    "steps": [
                        {
                            "title": f.title,
                            "severity": f.severity,
                            "component": f.component_name,
                            "cwe": f.cwe_id,
                        }
                        for f in unique_findings
                    ],
                },
            ))

            if progress_callback:
                await progress_callback(
                    plugin=self.name,
                    progress=(idx + 1) / total_rules,
                    message=f"Evaluated chain rule: {name}",
                )

        # 2) Confused deputy detection
        deputy_findings = self._detect_confused_deputy(analysis, all_findings, comp_index)
        chain_findings.extend(deputy_findings)

        # 3) Same-component multi-vuln escalation
        escalation_findings = self._detect_escalation(comp_index)
        chain_findings.extend(escalation_findings)

        return chain_findings

    # ------------------------------------------------------------------
    def _detect_confused_deputy(
        self, analysis, all_findings, comp_index,
    ) -> list[PluginFinding]:
        """Detect when an exported component can be used to reach unexported ones."""
        results: list[PluginFinding] = []

        exported = {c.name for c in analysis.components if c.exported}
        unexported = {c.name for c in analysis.components if not c.exported}

        # If we have findings on exported components that involve intent creation
        # (e.g., intent redirect, fragment injection), they may reach unexported components
        for f in all_findings:
            if f.component_name not in exported:
                continue
            # Check for indicators of confused deputy
            desc_lower = f.description.lower()
            if any(kw in desc_lower for kw in (
                "redirect", "forward", "reparent", "inject",
                "load", "startactivity", "startservice", "intent",
            )):
                # This exported component handles intents in a way that could
                # reach unexported components
                for unexported_name in unexported:
                    # Check if the exported component's finding mentions patterns
                    # that could target the unexported component
                    short_name = unexported_name.split(".")[-1].lower()
                    if short_name in desc_lower or short_name in str(f.evidence).lower():
                        results.append(PluginFinding(
                            title=(
                                f"Confused Deputy: {f.component_name} → {unexported_name}"
                            ),
                            description=(
                                f"Exported component {f.component_name} can be abused "
                                f"to reach unexported component {unexported_name}. "
                                f"Finding: {f.title}. An attacker sends a crafted intent "
                                f"to the exported component, which internally delegates "
                                f"to the unexported component with the attacker's data."
                            ),
                            severity="high",
                            component_name=f.component_name,
                            component_type=f.component_type,
                            cvss_score=8.0,
                            cwe_id="CWE-441",
                            mstg_id="MSTG-PLATFORM-2",
                            owasp_mobile="M1",
                            evidence={
                                "exported_component": f.component_name,
                                "unexported_target": unexported_name,
                                "via_finding": f.title,
                            },
                        ))
                        break  # one confused deputy per exported component

        return results

    def _detect_escalation(self, comp_index) -> list[PluginFinding]:
        """When a single component has multiple vulns, the combined impact may escalate."""
        results: list[PluginFinding] = []

        for comp_name, findings in comp_index.items():
            if len(findings) < 2:
                continue

            severities = {f.severity for f in findings}
            cwes = {f.cwe_id for f in findings if f.cwe_id}

            # If a component has both injection AND data leak, escalate
            has_injection = cwes & {"CWE-89", "CWE-79", "CWE-20", "CWE-470"}
            has_data_issue = cwes & {"CWE-200", "CWE-312", "CWE-532", "CWE-732"}

            if has_injection and has_data_issue:
                results.append(PluginFinding(
                    title=f"Multi-vuln escalation on {comp_name}",
                    description=(
                        f"Component {comp_name} has {len(findings)} findings including "
                        f"both injection ({', '.join(has_injection)}) and data exposure "
                        f"({', '.join(has_data_issue)}). Combined exploitation achieves "
                        f"higher impact than individual findings."
                    ),
                    severity="high",
                    component_name=comp_name,
                    cvss_score=8.5,
                    cwe_id=",".join(cwes),
                    mstg_id="MSTG-ARCH-2",
                    owasp_mobile="M1",
                    evidence={
                        "finding_count": len(findings),
                        "cwes": list(cwes),
                        "finding_titles": [f.title for f in findings[:5]],
                    },
                ))

        return results
