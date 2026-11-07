"""Findings API routes."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import Finding, Scan, Severity, ValidationStatus
from backend.schemas import FindingDetail, FindingResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans/{scan_id}/findings", tags=["findings"])


@router.get("", response_model=list[FindingResponse])
async def list_findings(
    scan_id: int,
    severity: str | None = Query(None, description="Filter by severity"),
    plugin: str | None = Query(None, description="Filter by plugin name"),
    validation_status: str | None = Query(None, description="Filter by validation status"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """List findings for a scan with optional filters."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    query = db.query(Finding).filter(Finding.scan_id == scan_id)

    if severity:
        try:
            sev = Severity(severity.lower())
            query = query.filter(Finding.severity == sev)
        except ValueError:
            raise HTTPException(400, f"Invalid severity: {severity}")

    if plugin:
        query = query.filter(Finding.plugin_name == plugin)

    if validation_status:
        try:
            vs = ValidationStatus(validation_status.lower())
            query = query.filter(Finding.validation_status == vs)
        except ValueError:
            raise HTTPException(400, f"Invalid validation_status: {validation_status}")

    query = query.order_by(
        Finding.severity.asc(),  # critical first (alphabetical sort works for enum)
        Finding.created_at.desc(),
    )
    findings = query.offset(offset).limit(limit).all()
    return [FindingResponse.model_validate(f) for f in findings]


@router.get("/{finding_id}", response_model=FindingDetail)
async def get_finding(scan_id: int, finding_id: int, db: Session = Depends(get_db)):
    """Get full finding detail with evidence."""
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id, Finding.scan_id == scan_id)
        .first()
    )
    if not finding:
        raise HTTPException(404, "Finding not found")

    return FindingDetail.model_validate(finding)


async def _revalidate_finding(scan_id: int, finding_id: int) -> None:
    """Background task: re-validate a single finding on-device."""
    from backend.database import SessionLocal

    db = SessionLocal()
    try:
        finding = (
            db.query(Finding)
            .filter(Finding.id == finding_id, Finding.scan_id == scan_id)
            .first()
        )
        if not finding:
            return

        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or not scan.device_id:
            finding.validation_status = ValidationStatus.NEEDS_MANUAL
            finding.validated_at = datetime.now(timezone.utc)
            db.commit()
            return

        try:
            from backend.core.device_manager import DeviceManager

            dm = DeviceManager()
            device = await dm.get_device(scan.device_id)
            if not device:
                finding.validation_status = ValidationStatus.NEEDS_MANUAL
                finding.validated_at = datetime.now(timezone.utc)
                db.commit()
                return

            # Attempt PoC replay if poc_command is available
            if finding.poc_command:
                await device.clear_logcat()

                # Execute the PoC via adb shell am
                result = await device.shell(finding.poc_command, timeout=30)

                logcat = await device.logcat_snapshot(lines=100)
                finding.logcat_snippet = logcat
                finding.response_data = result

                # Check for crash indicators in logcat
                crash_indicators = [
                    "FATAL EXCEPTION",
                    "java.lang.SecurityException",
                    "AndroidRuntime",
                    "Process crashed",
                ]
                crashed = any(ind in logcat for ind in crash_indicators)

                if crashed:
                    finding.validation_status = ValidationStatus.CONFIRMED
                else:
                    finding.validation_status = ValidationStatus.PARTIAL

                finding.validated_at = datetime.now(timezone.utc)
            else:
                finding.validation_status = ValidationStatus.NEEDS_MANUAL
                finding.validated_at = datetime.now(timezone.utc)

            db.commit()

        except Exception as exc:
            logger.exception("Revalidation failed for finding %d", finding_id)
            finding.validation_status = ValidationStatus.NEEDS_MANUAL
            finding.validated_at = datetime.now(timezone.utc)
            finding.evidence = {**(finding.evidence or {}), "revalidation_error": str(exc)}
            db.commit()
    finally:
        db.close()


@router.post("/{finding_id}/validate", response_model=FindingResponse)
async def validate_finding(
    scan_id: int,
    finding_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Trigger re-validation of a finding."""
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id, Finding.scan_id == scan_id)
        .first()
    )
    if not finding:
        raise HTTPException(404, "Finding not found")

    finding.validation_status = ValidationStatus.PENDING
    db.commit()
    db.refresh(finding)

    background_tasks.add_task(_revalidate_finding, scan_id, finding_id)
    logger.info("Queued revalidation for finding %d (scan %d)", finding_id, scan_id)

    return FindingResponse.model_validate(finding)
