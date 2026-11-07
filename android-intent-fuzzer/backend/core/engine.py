"""Main scan orchestrator for IntentHunter.

Manages the full scan lifecycle: static analysis, app installation,
Frida instrumentation, plugin execution, crash detection, validation,
and result persistence. Memory-efficient: processes one plugin at a time,
streams results to DB, supports cancellation.
"""
from __future__ import annotations

import asyncio
import logging
import time
import traceback
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine

from backend.config import settings
from backend.database import SessionLocal
from backend.models import (
    Component,
    Finding,
    Scan,
    ScanStatus,
    Severity,
    StaticAnalysisResult,
)
from backend.plugins.base import BasePlugin, PluginFinding

from backend.core.apk_analyzer import APKAnalysis, APKAnalyzer
from backend.core.coverage import CoverageManager
from backend.core.crash_detector import CrashDetector
from backend.core.finding_store import FindingStore

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[dict[str, Any]], Coroutine[Any, Any, None]] | Callable[[dict[str, Any]], None] | None


class ScanEngine:
    """Orchestrates a complete IntentHunter scan.

    Lifecycle:
      1. Static analysis (APK decompile + manifest parse)
      2. Install APK on device
      3. Attach Frida coverage instrumentation
      4. Run plugins in order
      5. Validate findings
      6. Persist results and generate report data
    """

    def __init__(self):
        self._cancelled = False
        self._finding_store = FindingStore()

    def cancel(self) -> None:
        """Request scan cancellation. Checked between phases and plugins."""
        self._cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled

    async def run_scan(
        self,
        scan_id: int,
        apk_path: str,
        device: Any | None,
        plugins: list[BasePlugin],
        progress_callback: ProgressCallback = None,
        static_only: bool = False,
    ) -> None:
        """Execute a full scan.

        Args:
            scan_id: Database ID of the Scan row.
            apk_path: Path to the APK file.
            device: DeviceHandle instance (None if static_only).
            plugins: Ordered list of plugin instances to run.
            progress_callback: Async or sync callable for WebSocket progress updates.
            static_only: If True, skip device-dependent phases.
        """
        self._cancelled = False
        coverage: CoverageManager | None = None
        crash_detector: CrashDetector | None = None

        try:
            # ---- Phase 1: Static Analysis ----
            await self._emit_progress(progress_callback, scan_id, "static_analysis", 0.0)
            self._update_scan_status(scan_id, ScanStatus.STATIC, phase="static_analysis")

            analyzer = APKAnalyzer(apk_path)
            analysis = await analyzer.analyze()

            # Persist static analysis results
            self._persist_static_results(scan_id, analysis)
            self._persist_components(scan_id, analysis)
            self._update_scan_field(scan_id, package_name=analysis.package_name, app_version=analysis.app_version)

            await self._emit_progress(progress_callback, scan_id, "static_analysis", 15.0,
                                      message=f"Static analysis complete: {len(analysis.exported_components)} exported components")

            if self._cancelled:
                self._update_scan_status(scan_id, ScanStatus.CANCELLED)
                return

            if static_only:
                # Run static-only plugins
                static_plugins = [p for p in plugins if not p.requires_device]
                await self._run_plugins(
                    scan_id, static_plugins, analysis, None, None, None,
                    progress_callback, start_pct=15.0, end_pct=90.0,
                )
                self._finalize_scan(scan_id)
                await self._emit_progress(progress_callback, scan_id, "completed", 100.0,
                                          message="Static-only scan complete")
                return

            # ---- Phase 2: Install APK ----
            if device is None:
                raise RuntimeError("Device required for dynamic scan but none provided")

            await self._emit_progress(progress_callback, scan_id, "installing", 18.0)
            self._update_scan_status(scan_id, ScanStatus.INSTALLING, phase="installing")

            install_ok = await device.install_apk(apk_path)
            if not install_ok:
                raise RuntimeError(f"Failed to install APK on {device.device_id}")

            await self._emit_progress(progress_callback, scan_id, "installing", 22.0,
                                      message="APK installed successfully")

            if self._cancelled:
                self._update_scan_status(scan_id, ScanStatus.CANCELLED)
                return

            # ---- Phase 3: Instrument (Frida + crash detector) ----
            await self._emit_progress(progress_callback, scan_id, "instrumenting", 25.0)

            # Launch the app
            await device.shell(f"monkey -p {analysis.package_name} -c android.intent.category.LAUNCHER 1")
            await asyncio.sleep(2)

            # Attach coverage
            try:
                coverage = CoverageManager(
                    package_name=analysis.package_name,
                    device_id=device.device_id if device.device_type != "docker" else None,
                )
                await coverage.attach()
            except Exception as e:
                logger.warning("Coverage attach failed (continuing without): %s", e)
                coverage = None

            # Start crash monitoring
            crash_detector = CrashDetector()
            await crash_detector.start_monitoring(device.device_id, analysis.package_name)

            # Wire Frida detach to crash detector
            if coverage and coverage._session and crash_detector:
                coverage._session.on("detached", crash_detector.on_frida_detach)

            await self._emit_progress(progress_callback, scan_id, "instrumenting", 30.0,
                                      message="Instrumentation attached")

            if self._cancelled:
                self._update_scan_status(scan_id, ScanStatus.CANCELLED)
                return

            # ---- Phase 4: Run Plugins ----
            self._update_scan_status(scan_id, ScanStatus.FUZZING, phase="fuzzing")

            await self._run_plugins(
                scan_id, plugins, analysis, device, coverage, crash_detector,
                progress_callback, start_pct=30.0, end_pct=85.0,
            )

            if self._cancelled:
                self._update_scan_status(scan_id, ScanStatus.CANCELLED)
                return

            # ---- Phase 5: Validate findings ----
            self._update_scan_status(scan_id, ScanStatus.VALIDATING, phase="validating")
            await self._emit_progress(progress_callback, scan_id, "validating", 85.0)

            await self._validate_findings(scan_id, plugins, device, analysis)

            await self._emit_progress(progress_callback, scan_id, "validating", 95.0,
                                      message="Validation complete")

            # ---- Phase 6: Finalize ----
            # Record crash count and coverage
            crash_count = crash_detector.crash_count if crash_detector else 0
            coverage_pct = 0.0
            if coverage:
                snap = await coverage.get_coverage()
                coverage_pct = snap.percentage

            self._update_scan_field(
                scan_id,
                total_crashes=crash_count,
                coverage_pct=coverage_pct,
            )

            self._finalize_scan(scan_id)
            await self._emit_progress(progress_callback, scan_id, "completed", 100.0,
                                      message="Scan complete")

        except asyncio.CancelledError:
            self._update_scan_status(scan_id, ScanStatus.CANCELLED)
            raise
        except Exception as e:
            tb = traceback.format_exc()
            logger.error("Scan %d failed: %s\n%s", scan_id, e, tb)
            self._update_scan_status(
                scan_id, ScanStatus.FAILED,
                error_message=f"{type(e).__name__}: {e}"
            )
            await self._emit_progress(progress_callback, scan_id, "failed", 0.0,
                                      message=str(e))
        finally:
            # Cleanup
            if coverage:
                try:
                    await coverage.detach()
                except Exception:
                    pass
            if crash_detector and crash_detector.is_monitoring:
                try:
                    await crash_detector.stop_monitoring()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Plugin execution
    # ------------------------------------------------------------------

    async def _run_plugins(
        self,
        scan_id: int,
        plugins: list[BasePlugin],
        analysis: APKAnalysis,
        device: Any | None,
        coverage: CoverageManager | None,
        crash_detector: CrashDetector | None,
        progress_callback: ProgressCallback,
        start_pct: float,
        end_pct: float,
    ) -> None:
        """Run plugins one at a time for memory efficiency."""
        if not plugins:
            return

        pct_per_plugin = (end_pct - start_pct) / len(plugins)

        for i, plugin in enumerate(plugins):
            if self._cancelled:
                return

            # Skip device-requiring plugins in static-only mode
            if plugin.requires_device and device is None:
                logger.info("Skipping %s (requires device)", plugin.name)
                continue

            current_pct = start_pct + (i * pct_per_plugin)
            await self._emit_progress(
                progress_callback, scan_id, "fuzzing", current_pct,
                current_plugin=plugin.name,
                message=f"Running {plugin.display_name}",
            )

            logger.info("Running plugin: %s", plugin.name)
            plugin_start = time.time()

            try:
                # Plugin progress sub-callback
                async def plugin_progress(data: dict) -> None:
                    sub_pct = current_pct + (data.get("progress", 0) / 100.0) * pct_per_plugin
                    await self._emit_progress(
                        progress_callback, scan_id, "fuzzing", sub_pct,
                        current_plugin=plugin.name,
                        message=data.get("message", ""),
                    )

                findings: list[PluginFinding] = await plugin.run(
                    analysis=analysis,
                    device=device,
                    progress_callback=plugin_progress,
                )

                # Persist findings one at a time (memory efficient)
                for finding in findings:
                    self._finding_store.add_finding(scan_id, finding, plugin.name)

                # Update intent count from crash detector
                if crash_detector:
                    self._update_scan_field(scan_id, total_crashes=crash_detector.crash_count)

                elapsed = time.time() - plugin_start
                logger.info(
                    "Plugin %s complete: %d findings in %.1fs",
                    plugin.name, len(findings), elapsed,
                )

                # Let the findings list be GC'd
                del findings

            except Exception as e:
                logger.error("Plugin %s failed: %s", plugin.name, e, exc_info=True)
                # Don't abort entire scan for one plugin failure
                continue

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    async def _validate_findings(
        self,
        scan_id: int,
        plugins: list[BasePlugin],
        device: Any | None,
        analysis: APKAnalysis,
    ) -> None:
        """Auto-validate findings using plugin validators."""
        if device is None:
            return

        db = SessionLocal()
        try:
            findings = (
                db.query(Finding)
                .filter(Finding.scan_id == scan_id)
                .all()
            )

            plugin_map = {p.name: p for p in plugins}

            for finding in findings:
                if self._cancelled:
                    return

                plugin = plugin_map.get(finding.plugin_name)
                if not plugin:
                    continue

                try:
                    pf = PluginFinding(
                        title=finding.title,
                        description=finding.description,
                        severity=finding.severity.value,
                        component_name=finding.component_name or "",
                        component_type=finding.component_type or "",
                        poc_command=finding.poc_command or "",
                        evidence=finding.evidence or {},
                    )

                    verdict = await plugin.validate_result(
                        finding=pf,
                        device=device,
                        execution_result=finding.evidence or {},
                    )

                    self._finding_store.update_validation(
                        finding.id, verdict.status, verdict.evidence
                    )
                except Exception as e:
                    logger.debug("Validation failed for finding %d: %s", finding.id, e)
                    continue
        finally:
            db.close()

    # ------------------------------------------------------------------
    # Progress emission
    # ------------------------------------------------------------------

    async def _emit_progress(
        self,
        callback: ProgressCallback,
        scan_id: int,
        phase: str,
        progress_pct: float,
        current_plugin: str = "",
        message: str = "",
    ) -> None:
        """Send progress update via callback (for WebSocket)."""
        if callback is None:
            return

        # Update DB progress
        self._update_scan_field(scan_id, progress_pct=progress_pct, current_phase=phase)

        # Get live stats
        stats = self._finding_store.get_scan_stats(scan_id)

        payload = {
            "scan_id": scan_id,
            "status": phase,
            "phase": phase,
            "progress_pct": round(progress_pct, 1),
            "current_plugin": current_plugin,
            "message": message,
            "findings_count": stats.get("total", 0),
        }

        try:
            result = callback(payload)
            if asyncio.iscoroutine(result):
                await result
        except Exception as e:
            logger.debug("Progress callback error: %s", e)

    # ------------------------------------------------------------------
    # Database helpers
    # ------------------------------------------------------------------

    def _update_scan_status(
        self,
        scan_id: int,
        status: ScanStatus,
        phase: str = "",
        error_message: str = "",
    ) -> None:
        """Update scan status in DB."""
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = status
                if phase:
                    scan.current_phase = phase
                if error_message:
                    scan.error_message = error_message
                if status == ScanStatus.STATIC and scan.started_at is None:
                    scan.started_at = datetime.now(timezone.utc)
                db.commit()
        finally:
            db.close()

    def _update_scan_field(self, scan_id: int, **kwargs: Any) -> None:
        """Update arbitrary scan fields."""
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                for key, value in kwargs.items():
                    if hasattr(scan, key):
                        setattr(scan, key, value)
                db.commit()
        finally:
            db.close()

    def _persist_static_results(self, scan_id: int, analysis: APKAnalysis) -> None:
        """Save static analysis results to DB."""
        db = SessionLocal()
        try:
            # Check if already exists
            existing = db.query(StaticAnalysisResult).filter(
                StaticAnalysisResult.scan_id == scan_id
            ).first()
            if existing:
                db.delete(existing)
                db.flush()

            result = StaticAnalysisResult(
                scan_id=scan_id,
                package_name=analysis.package_name,
                min_sdk=analysis.min_sdk,
                target_sdk=analysis.target_sdk,
                permissions=analysis.permissions,
                debuggable=analysis.debuggable,
                allow_backup=analysis.allow_backup,
                network_security_config=(
                    {
                        "cleartext_permitted": analysis.network_security.cleartextTrafficPermitted,
                        "trust_user_certs": analysis.network_security.trust_user_certs,
                        "pin_sets": analysis.network_security.pin_sets,
                        "domain_configs": analysis.network_security.domain_configs,
                    }
                    if analysis.network_security else {}
                ),
                shared_uid=analysis.shared_uid,
                secret_codes=analysis.secret_codes,
                hardcoded_secrets=[
                    {
                        "pattern": s.pattern_name,
                        "file": s.file_path,
                        "line": s.line_number,
                        "match": s.matched_text[:100],
                    }
                    for s in analysis.hardcoded_secrets
                ],
                native_libs=analysis.native_libs,
                attack_surface_score=analysis.attack_surface_score,
                manifest_raw=analysis.manifest_raw,
            )
            db.add(result)
            db.commit()
        finally:
            db.close()

    def _persist_components(self, scan_id: int, analysis: APKAnalysis) -> None:
        """Save extracted components to DB."""
        db = SessionLocal()
        try:
            for comp in analysis.components:
                db_comp = Component(
                    scan_id=scan_id,
                    component_type=comp.component_type,
                    name=comp.name,
                    exported=comp.exported,
                    permission=comp.permission,
                    intent_filters=[
                        {
                            "actions": f.actions,
                            "categories": f.categories,
                            "data_schemes": f.data_schemes,
                            "data_hosts": f.data_hosts,
                            "data_paths": f.data_paths,
                            "data_mime_types": f.data_mime_types,
                        }
                        for f in comp.intent_filters
                    ],
                    deep_links=comp.deep_links,
                    metadata=comp.metadata,
                )
                db.add(db_comp)
            db.commit()
        finally:
            db.close()

    def _finalize_scan(self, scan_id: int) -> None:
        """Mark scan as completed with final timestamp."""
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.now(timezone.utc)
                scan.progress_pct = 100.0
                scan.current_phase = "completed"

                # Update total findings count
                stats = self._finding_store.get_scan_stats(scan_id)
                scan.total_intents_sent = scan.total_intents_sent or 0

                db.commit()
        finally:
            db.close()
