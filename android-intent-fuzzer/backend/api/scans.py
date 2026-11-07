"""Scan management API routes."""
from __future__ import annotations

import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile, File, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.models import (
    AttackChain,
    AttackChainLink,
    Component,
    Finding,
    Scan,
    ScanStatus,
    StaticAnalysisResult,
)
from backend.schemas import (
    AttackChainResponse,
    ChainStepResponse,
    ComponentResponse,
    FindingResponse,
    ScanCreate,
    ScanDetail,
    ScanResponse,
    StaticResultResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["scans"])


async def _run_scan(scan_id: int) -> None:
    """Background task: launch the ScanEngine for a scan."""
    from backend.database import SessionLocal

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        scan.status = ScanStatus.STATIC
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        try:
            from backend.core.engine import ScanEngine
            from backend.core.device_manager import DeviceManager
            from backend.plugins import ALL_PLUGINS, POST_PROCESS_PLUGINS

            engine = ScanEngine()

            device = None
            if not scan.static_only:
                dm = DeviceManager()
                if scan.device_id:
                    device = await dm.get_device(scan.device_id)
                elif scan.device_type == "docker":
                    device = await dm.get_or_create_emulator()
                else:
                    devices = await dm.discover_devices()
                    device = devices[0] if devices else None

            enabled = scan.enabled_plugins or list(ALL_PLUGINS.keys())
            plugins = []
            for name in enabled:
                if name not in POST_PROCESS_PLUGINS and name in ALL_PLUGINS:
                    plugins.append(ALL_PLUGINS[name]())
            for name in POST_PROCESS_PLUGINS:
                if name in ALL_PLUGINS:
                    plugins.append(ALL_PLUGINS[name]())

            async def _progress(data: dict):
                try:
                    from backend.api.ws import broadcast_scan_progress
                    await broadcast_scan_progress(scan.id, data)
                except Exception:
                    pass

            await engine.run_scan(
                scan_id=scan.id,
                apk_path=scan.apk_path,
                device=device,
                plugins=plugins,
                progress_callback=_progress,
                static_only=scan.static_only,
            )
        except Exception as import_or_run_exc:
            raise import_or_run_exc
        except Exception as exc:
            logger.exception("Scan %d failed", scan_id)
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = str(exc)[:2000]
                scan.completed_at = datetime.now(timezone.utc)
                db.commit()
    finally:
        db.close()


def _scan_to_response(scan: Scan) -> dict:
    """Convert a Scan ORM object to a dict suitable for ScanResponse."""
    return {
        "id": scan.id,
        "name": scan.name,
        "package_name": scan.package_name,
        "app_version": scan.app_version,
        "status": scan.status,
        "static_only": scan.static_only,
        "device_type": scan.device_type,
        "progress_pct": scan.progress_pct,
        "current_phase": scan.current_phase,
        "coverage_pct": scan.coverage_pct,
        "total_intents_sent": scan.total_intents_sent,
        "total_crashes": scan.total_crashes,
        "findings_count": len(scan.findings),
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "created_at": scan.created_at,
        "error_message": scan.error_message,
    }


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(
    apk: UploadFile = File(...),
    name: str = Query("", description="Scan name, defaults to APK filename"),
    static_only: bool = Query(False),
    device_type: str | None = Query(None),
    device_id: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """Upload an APK and create a new scan record."""
    if apk.content_type not in (
        "application/vnd.android.package-archive",
        "application/octet-stream",
        "application/java-archive",
    ):
        # Lenient: also accept by extension
        if apk.filename and not apk.filename.endswith(".apk"):
            raise HTTPException(400, "File must be an APK")

    if not apk.filename:
        raise HTTPException(400, "Filename required")

    # Save uploaded APK
    upload_dir = Path(settings.uploads_dir)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_name = apk.filename.replace(" ", "_").replace("/", "_")
    dest = upload_dir / f"{timestamp}_{safe_name}"

    total_size = 0
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    with open(dest, "wb") as f:
        while chunk := await apk.read(1024 * 1024):
            total_size += len(chunk)
            if total_size > max_bytes:
                dest.unlink(missing_ok=True)
                raise HTTPException(413, f"APK exceeds max upload size ({settings.max_upload_size_mb} MB)")
            f.write(chunk)

    scan = Scan(
        name=name or safe_name.replace(".apk", ""),
        apk_path=str(dest),
        status=ScanStatus.PENDING,
        static_only=static_only,
        device_type=device_type,
        device_id=device_id,
        enabled_plugins=[],
        config_overrides={},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    logger.info("Created scan %d for APK %s", scan.id, safe_name)
    return ScanResponse(**_scan_to_response(scan))


@router.get("", response_model=list[ScanResponse])
async def list_scans(
    offset: int = Query(0, ge=0),
    limit: int = Query(25, ge=1, le=100),
    status: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """List all scans with pagination."""
    query = db.query(Scan)
    if status:
        query = query.filter(Scan.status == status)
    query = query.order_by(Scan.created_at.desc())
    scans = query.offset(offset).limit(limit).all()
    return [ScanResponse(**_scan_to_response(s)) for s in scans]


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Get scan details with component and finding counts."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    data = _scan_to_response(scan)
    data["enabled_plugins"] = scan.enabled_plugins or []
    data["config_overrides"] = scan.config_overrides or {}
    data["components"] = [ComponentResponse.model_validate(c) for c in scan.components]
    data["findings"] = [FindingResponse.model_validate(f) for f in scan.findings]
    return ScanDetail(**data)


@router.post("/{scan_id}/start", response_model=ScanResponse)
async def start_scan(
    scan_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Start a scan (launches ScanEngine in a background task)."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    if scan.status not in (ScanStatus.PENDING, ScanStatus.FAILED):
        raise HTTPException(
            409, f"Scan is {scan.status.value}; only PENDING or FAILED scans can be started"
        )

    scan.status = ScanStatus.PENDING
    scan.error_message = None
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(_run_scan, scan.id)
    logger.info("Queued scan %d for execution", scan.id)

    return ScanResponse(**_scan_to_response(scan))


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(scan_id: int, db: Session = Depends(get_db)):
    """Cancel a running scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    active_states = (
        ScanStatus.STATIC,
        ScanStatus.INSTALLING,
        ScanStatus.FUZZING,
        ScanStatus.VALIDATING,
    )
    if scan.status not in active_states:
        raise HTTPException(409, f"Scan is {scan.status.value}; only active scans can be cancelled")

    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(scan)

    logger.info("Cancelled scan %d", scan.id)
    return ScanResponse(**_scan_to_response(scan))


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Delete a scan and all associated data."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    active_states = (
        ScanStatus.STATIC,
        ScanStatus.INSTALLING,
        ScanStatus.FUZZING,
        ScanStatus.VALIDATING,
    )
    if scan.status in active_states:
        raise HTTPException(409, "Cannot delete an active scan; cancel it first")

    # Clean up APK file
    apk_path = Path(scan.apk_path)
    if apk_path.exists():
        apk_path.unlink(missing_ok=True)

    # Clean up decompiled directory
    decompiled = Path(settings.decompiled_dir) / str(scan.id)
    if decompiled.exists():
        shutil.rmtree(decompiled, ignore_errors=True)

    # Delete related attack chains (not cascade from scan directly)
    chain_ids = [c.id for c in db.query(AttackChain).filter(AttackChain.scan_id == scan_id).all()]
    if chain_ids:
        db.query(AttackChainLink).filter(AttackChainLink.chain_id.in_(chain_ids)).delete(
            synchronize_session=False
        )
        db.query(AttackChain).filter(AttackChain.scan_id == scan_id).delete(
            synchronize_session=False
        )

    # Delete static results
    db.query(StaticAnalysisResult).filter(StaticAnalysisResult.scan_id == scan_id).delete(
        synchronize_session=False
    )

    db.delete(scan)  # cascade deletes findings and components
    db.commit()

    logger.info("Deleted scan %d", scan_id)


@router.get("/{scan_id}/static", response_model=StaticResultResponse)
async def get_static_results(scan_id: int, db: Session = Depends(get_db)):
    """Get static analysis results for a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    result = (
        db.query(StaticAnalysisResult)
        .filter(StaticAnalysisResult.scan_id == scan_id)
        .first()
    )
    if not result:
        raise HTTPException(404, "Static analysis not yet run for this scan")

    return StaticResultResponse.model_validate(result)


@router.get("/{scan_id}/chains", response_model=list[AttackChainResponse])
async def get_attack_chains(scan_id: int, db: Session = Depends(get_db)):
    """Get attack chains discovered during a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    chains = db.query(AttackChain).filter(AttackChain.scan_id == scan_id).all()
    result = []
    for chain in chains:
        steps = []
        for link in chain.links:
            finding_title = link.finding.title if link.finding else ""
            steps.append(
                ChainStepResponse(
                    step_order=link.step_order,
                    finding_id=link.finding_id,
                    finding_title=finding_title,
                    description=link.description,
                )
            )
        result.append(
            AttackChainResponse(
                id=chain.id,
                scan_id=chain.scan_id,
                title=chain.title,
                description=chain.description,
                severity=chain.severity,
                cvss_score=chain.cvss_score,
                steps=steps,
            )
        )
    return result
