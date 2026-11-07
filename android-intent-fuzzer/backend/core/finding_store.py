"""Finding management and CVSS scoring for IntentHunter.

Wraps SQLAlchemy operations for findings persistence, querying,
validation updates, stats aggregation, and CVSS 3.1 base score
calculation.
"""
from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from typing import Any

from backend.database import SessionLocal
from backend.models import Finding, Scan, Severity, ValidationStatus
from backend.plugins.base import PluginFinding, ValidationVerdict

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CVSS 3.1 constants and lookup tables
# ---------------------------------------------------------------------------

# Attack Vector (AV)
AV_SCORES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
# Attack Complexity (AC)
AC_SCORES = {"L": 0.77, "H": 0.44}
# Privileges Required (PR) — Scope Unchanged / Changed
PR_SCORES_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_SCORES_C = {"N": 0.85, "L": 0.68, "H": 0.50}
# User Interaction (UI)
UI_SCORES = {"N": 0.85, "R": 0.62}
# Scope (S)
# Impact subscores: Confidentiality, Integrity, Availability
IMPACT_SCORES = {"H": 0.56, "L": 0.22, "N": 0.0}

# CWE -> default CVSS vector mappings for auto-calculation
CWE_CVSS_DEFAULTS: dict[str, dict[str, str]] = {
    # Injection
    "CWE-89": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "CWE-78": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    # XSS
    "CWE-79": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
    # Path Traversal
    "CWE-22": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    # IDOR
    "CWE-639": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"},
    # Exported component (Android)
    "CWE-926": {"AV": "L", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
    # Intent redirection
    "CWE-940": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "H", "A": "N"},
    # Hardcoded credentials
    "CWE-798": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    # Insecure storage
    "CWE-922": {"AV": "L", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    # Debug enabled
    "CWE-489": {"AV": "L", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
    # Backup enabled
    "CWE-530": {"AV": "P", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    # Cleartext traffic
    "CWE-319": {"AV": "A", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    # DoS / crash
    "CWE-400": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "H"},
}

# Severity string -> default CVSS vectors when no CWE is available
SEVERITY_CVSS_DEFAULTS: dict[str, dict[str, str]] = {
    "critical": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "high":     {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "medium":   {"AV": "N", "AC": "L", "PR": "L", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"},
    "low":      {"AV": "L", "AC": "H", "PR": "L", "UI": "R", "S": "U", "C": "L", "I": "N", "A": "N"},
    "info":     {"AV": "N", "AC": "H", "PR": "H", "UI": "R", "S": "U", "C": "N", "I": "N", "A": "N"},
}


def _compute_cvss31_base(vector: dict[str, str]) -> float:
    """Compute CVSS 3.1 base score from a vector dict.

    Keys: AV, AC, PR, UI, S, C, I, A
    Returns score 0.0 - 10.0.
    """
    av = AV_SCORES.get(vector.get("AV", "N"), 0.85)
    ac = AC_SCORES.get(vector.get("AC", "L"), 0.77)
    scope_changed = vector.get("S", "U") == "C"
    pr_table = PR_SCORES_C if scope_changed else PR_SCORES_U
    pr = pr_table.get(vector.get("PR", "N"), 0.85)
    ui = UI_SCORES.get(vector.get("UI", "N"), 0.85)

    conf = IMPACT_SCORES.get(vector.get("C", "N"), 0.0)
    integ = IMPACT_SCORES.get(vector.get("I", "N"), 0.0)
    avail = IMPACT_SCORES.get(vector.get("A", "N"), 0.0)

    # ISS (Impact Sub-Score)
    iss = 1.0 - ((1.0 - conf) * (1.0 - integ) * (1.0 - avail))

    if iss <= 0:
        return 0.0

    # Impact
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    # Base score
    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)

    # Round up to nearest 0.1
    return math.ceil(base * 10) / 10


# ---------------------------------------------------------------------------
# FindingStore
# ---------------------------------------------------------------------------

class FindingStore:
    """Manages finding persistence, queries, validation, and scoring."""

    def add_finding(
        self,
        scan_id: int,
        plugin_finding: PluginFinding,
        plugin_name: str = "",
    ) -> int:
        """Save a plugin finding to the database.

        Args:
            scan_id: The scan this finding belongs to.
            plugin_finding: Finding data from a plugin.
            plugin_name: Override plugin name (if not set on finding).

        Returns:
            The database ID of the created Finding.
        """
        db = SessionLocal()
        try:
            # Auto-calculate CVSS if not provided
            cvss = plugin_finding.cvss_score
            if cvss is None:
                cvss = self.calculate_cvss(plugin_finding)

            # Map severity string to enum
            try:
                severity = Severity(plugin_finding.severity.lower())
            except ValueError:
                severity = Severity.INFO

            finding = Finding(
                scan_id=scan_id,
                plugin_name=plugin_name or "unknown",
                title=plugin_finding.title,
                description=plugin_finding.description,
                severity=severity,
                cvss_score=cvss,
                cwe_id=plugin_finding.cwe_id or None,
                mstg_id=plugin_finding.mstg_id or None,
                owasp_mobile=plugin_finding.owasp_mobile or None,
                component_name=plugin_finding.component_name or None,
                component_type=plugin_finding.component_type or None,
                validation_status=ValidationStatus.PENDING,
                poc_command=plugin_finding.poc_command or None,
                poc_frida_script=plugin_finding.poc_frida_script or None,
                request_data=plugin_finding.request_data or None,
                response_data=plugin_finding.response_data or None,
                evidence=plugin_finding.evidence or {},
                logcat_snippet=plugin_finding.logcat_snippet or None,
            )

            db.add(finding)
            db.commit()
            db.refresh(finding)

            logger.info(
                "Finding saved: [%s] %s (CVSS %.1f) for scan %d",
                severity.value, finding.title, cvss or 0.0, scan_id,
            )
            return finding.id
        finally:
            db.close()

    def get_findings(
        self,
        scan_id: int,
        severity: str | None = None,
        plugin_name: str | None = None,
        validation_status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Finding]:
        """Query findings with optional filters.

        Args:
            scan_id: Scan to query.
            severity: Filter by severity (critical, high, medium, low, info).
            plugin_name: Filter by plugin name.
            validation_status: Filter by validation status.
            limit: Max results.
            offset: Pagination offset.

        Returns:
            List of Finding ORM objects.
        """
        db = SessionLocal()
        try:
            query = db.query(Finding).filter(Finding.scan_id == scan_id)

            if severity:
                try:
                    query = query.filter(Finding.severity == Severity(severity.lower()))
                except ValueError:
                    pass

            if plugin_name:
                query = query.filter(Finding.plugin_name == plugin_name)

            if validation_status:
                try:
                    query = query.filter(
                        Finding.validation_status == ValidationStatus(validation_status.lower())
                    )
                except ValueError:
                    pass

            query = query.order_by(Finding.cvss_score.desc().nullslast())
            findings = query.offset(offset).limit(limit).all()

            # Expunge from session so they can be used after close
            for f in findings:
                db.expunge(f)

            return findings
        finally:
            db.close()

    def update_validation(
        self,
        finding_id: int,
        verdict: str,
        evidence: dict[str, Any] | None = None,
    ) -> bool:
        """Update a finding's validation status.

        Args:
            finding_id: ID of the finding to update.
            verdict: One of: confirmed, false_positive, partial, needs_manual.
            evidence: Additional validation evidence to merge.

        Returns:
            True if updated, False if finding not found.
        """
        db = SessionLocal()
        try:
            finding = db.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                return False

            try:
                finding.validation_status = ValidationStatus(verdict.lower())
            except ValueError:
                finding.validation_status = ValidationStatus.NEEDS_MANUAL

            if evidence:
                existing = finding.evidence or {}
                existing["validation"] = evidence
                finding.evidence = existing

            finding.validated_at = datetime.now(timezone.utc)
            db.commit()

            logger.info("Finding %d validated: %s", finding_id, verdict)
            return True
        finally:
            db.close()

    def get_scan_stats(self, scan_id: int) -> dict[str, Any]:
        """Get finding counts by severity for a scan.

        Returns dict with keys: total, critical, high, medium, low, info,
        confirmed, false_positive, pending.
        """
        db = SessionLocal()
        try:
            findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

            stats: dict[str, int] = {
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "confirmed": 0,
                "false_positive": 0,
                "pending": 0,
            }

            for f in findings:
                stats["total"] += 1
                sev_key = f.severity.value if f.severity else "info"
                if sev_key in stats:
                    stats[sev_key] += 1

                val_key = f.validation_status.value if f.validation_status else "pending"
                if val_key in stats:
                    stats[val_key] += 1

            return stats
        finally:
            db.close()

    @staticmethod
    def calculate_cvss(finding: PluginFinding) -> float:
        """Auto-calculate CVSS 3.1 base score from finding attributes.

        Uses CWE-based default vectors when available, falls back to
        severity-based defaults.

        Args:
            finding: The PluginFinding to score.

        Returns:
            CVSS 3.1 base score (0.0 - 10.0).
        """
        # If finding already has a score, use it
        if finding.cvss_score is not None and finding.cvss_score > 0:
            return finding.cvss_score

        # Try CWE-based vector
        if finding.cwe_id:
            cwe_upper = finding.cwe_id.upper()
            if not cwe_upper.startswith("CWE-"):
                cwe_upper = f"CWE-{cwe_upper}"
            vector = CWE_CVSS_DEFAULTS.get(cwe_upper)
            if vector:
                return _compute_cvss31_base(vector)

        # Fall back to severity-based vector
        severity_key = finding.severity.lower() if finding.severity else "info"
        vector = SEVERITY_CVSS_DEFAULTS.get(severity_key, SEVERITY_CVSS_DEFAULTS["info"])
        return _compute_cvss31_base(vector)
