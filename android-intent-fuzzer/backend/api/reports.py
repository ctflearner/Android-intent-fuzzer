"""Report generation API routes."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.models import AttackChain, Finding, Scan, Severity, StaticAnalysisResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans/{scan_id}/report", tags=["reports"])

# Jinja2 setup -- template in backend/templates/
_template_dir = Path(__file__).resolve().parent.parent / "templates"
_jinja_env = Environment(
    loader=FileSystemLoader(str(_template_dir)),
    autoescape=True,
)


def _severity_order(sev: Severity) -> int:
    return {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }.get(sev, 5)


def _build_report_data(scan: Scan, db: Session) -> dict:
    """Assemble all data needed for the report template."""
    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id)
        .all()
    )
    findings_sorted = sorted(findings, key=lambda f: _severity_order(f.severity))

    severity_stats = {s.value: 0 for s in Severity}
    for f in findings:
        severity_stats[f.severity.value] += 1

    static = (
        db.query(StaticAnalysisResult)
        .filter(StaticAnalysisResult.scan_id == scan.id)
        .first()
    )

    chains = db.query(AttackChain).filter(AttackChain.scan_id == scan.id).all()

    return {
        "scan": scan,
        "findings": findings_sorted,
        "severity_stats": severity_stats,
        "static_analysis": static,
        "attack_chains": chains,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "total_findings": len(findings),
    }


@router.get("")
async def generate_report(
    scan_id: int,
    format: str = Query("html", pattern="^(html|json)$"),
    db: Session = Depends(get_db),
):
    """Generate a scan report in HTML or JSON format."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    report_data = _build_report_data(scan, db)

    if format == "json":
        findings_json = []
        for f in report_data["findings"]:
            findings_json.append({
                "id": f.id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "cvss_score": f.cvss_score,
                "cwe_id": f.cwe_id,
                "mstg_id": f.mstg_id,
                "owasp_mobile": f.owasp_mobile,
                "plugin_name": f.plugin_name,
                "component_name": f.component_name,
                "component_type": f.component_type,
                "validation_status": f.validation_status.value,
                "poc_command": f.poc_command,
                "evidence": f.evidence,
                "logcat_snippet": f.logcat_snippet,
            })

        chains_json = []
        for c in report_data["attack_chains"]:
            chains_json.append({
                "id": c.id,
                "title": c.title,
                "description": c.description,
                "severity": c.severity.value,
                "cvss_score": c.cvss_score,
                "steps": [
                    {
                        "step_order": link.step_order,
                        "finding_id": link.finding_id,
                        "description": link.description,
                    }
                    for link in c.links
                ],
            })

        return JSONResponse({
            "scan_id": scan.id,
            "scan_name": scan.name,
            "package_name": scan.package_name,
            "status": scan.status.value,
            "generated_at": report_data["generated_at"],
            "severity_stats": report_data["severity_stats"],
            "total_findings": report_data["total_findings"],
            "findings": findings_json,
            "attack_chains": chains_json,
        })

    # HTML report
    try:
        template = _jinja_env.get_template("report.html")
    except Exception:
        # Inline fallback if template file is missing
        return HTMLResponse(_generate_inline_html(report_data))

    html = template.render(**report_data)
    return HTMLResponse(html)


def _generate_inline_html(data: dict) -> str:
    """Fallback HTML report when Jinja2 template is unavailable."""
    scan = data["scan"]
    findings = data["findings"]
    stats = data["severity_stats"]

    severity_colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#2563eb",
        "info": "#6b7280",
    }

    findings_rows = ""
    for f in findings:
        color = severity_colors.get(f.severity.value, "#6b7280")
        poc_html = ""
        if f.poc_command:
            poc_html = f'<pre style="background:#1e1e2e;color:#cdd6f4;padding:8px;border-radius:4px;overflow-x:auto;font-size:12px">{_esc(f.poc_command)}</pre>'

        findings_rows += f"""
        <div style="border:1px solid #333;border-left:4px solid {color};border-radius:6px;padding:16px;margin-bottom:12px;background:#181825">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
                <h3 style="margin:0;color:#cdd6f4">{_esc(f.title)}</h3>
                <span style="background:{color};color:#fff;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600;text-transform:uppercase">{f.severity.value}</span>
            </div>
            <p style="color:#a6adc8;margin:4px 0">{_esc(f.description)}</p>
            <div style="font-size:12px;color:#7f849c;margin-top:6px">
                Plugin: {_esc(f.plugin_name)} | Component: {_esc(f.component_name or 'N/A')} |
                CWE: {_esc(f.cwe_id or 'N/A')} | CVSS: {f.cvss_score or 'N/A'} |
                Validation: {f.validation_status.value}
            </div>
            {poc_html}
        </div>"""

    stats_html = ""
    for sev, count in stats.items():
        color = severity_colors.get(sev, "#6b7280")
        stats_html += f'<div style="text-align:center;padding:12px 20px"><div style="font-size:28px;font-weight:700;color:{color}">{count}</div><div style="font-size:12px;color:#a6adc8;text-transform:uppercase">{sev}</div></div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IntentHunter Report - {_esc(scan.name)}</title>
<style>
    *{{margin:0;padding:0;box-sizing:border-box}}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#11111b;color:#cdd6f4;padding:24px;max-width:960px;margin:0 auto}}
    h1{{font-size:24px;margin-bottom:4px}}
    h2{{font-size:18px;margin:24px 0 12px;color:#89b4fa}}
</style>
</head>
<body>
    <h1>IntentHunter Security Assessment</h1>
    <p style="color:#a6adc8;margin-bottom:24px">Scan: {_esc(scan.name)} | Package: {_esc(scan.package_name or 'N/A')} | Generated: {data['generated_at']}</p>

    <h2>Severity Summary</h2>
    <div style="display:flex;gap:8px;background:#181825;border-radius:8px;padding:12px;margin-bottom:24px">{stats_html}</div>

    <h2>Findings ({data['total_findings']})</h2>
    {findings_rows if findings_rows else '<p style="color:#a6adc8">No findings recorded.</p>'}

    <div style="margin-top:32px;padding-top:16px;border-top:1px solid #333;font-size:12px;color:#585b70">
        Generated by IntentHunter v{settings.version}
    </div>
</body>
</html>"""


def _esc(text: str) -> str:
    """Minimal HTML escaping."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
