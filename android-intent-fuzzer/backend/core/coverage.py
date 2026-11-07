"""Frida-based code coverage engine for IntentHunter.

Attaches to a running app, injects method-level instrumentation,
tracks hit methods, and reports coverage metrics. Memory-efficient:
batches coverage data, uses sets for dedup, doesn't store every hit.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from backend.config import settings

logger = logging.getLogger(__name__)

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    logger.warning("frida-python not installed — coverage collection disabled")


# ---------------------------------------------------------------------------
# Frida JS instrumentation script
# ---------------------------------------------------------------------------
COVERAGE_SCRIPT = """
'use strict';

const PKG = '%TARGET_PACKAGE%';
const BATCH_SIZE = %BATCH_SIZE%;

// Track hit methods: set of "class.method" strings
const hitMethods = new Set();
const pendingBatch = [];
let totalMethods = 0;
let enumerated = false;

function enumerateMethods() {
    if (enumerated) return;
    enumerated = true;

    Java.perform(function() {
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                if (!className.startsWith(PKG)) return;

                try {
                    const klass = Java.use(className);
                    const methods = klass.class.getDeclaredMethods();
                    totalMethods += methods.length;

                    methods.forEach(function(method) {
                        const methodName = method.getName();
                        const key = className + '.' + methodName;

                        // Skip synthetic/bridge methods
                        const mods = method.getModifiers();
                        if ((mods & 0x1000) !== 0 || (mods & 0x0040) !== 0) return;

                        try {
                            const overloads = klass[methodName].overloads;
                            overloads.forEach(function(overload) {
                                overload.implementation = function() {
                                    if (!hitMethods.has(key)) {
                                        hitMethods.add(key);
                                        pendingBatch.push(key);

                                        if (pendingBatch.length >= BATCH_SIZE) {
                                            send({
                                                type: 'coverage_batch',
                                                methods: pendingBatch.splice(0),
                                                total: totalMethods,
                                                hit: hitMethods.size
                                            });
                                        }
                                    }
                                    return this[methodName].apply(this, arguments);
                                };
                            });
                        } catch(e) {
                            // Some methods can't be hooked; skip
                        }
                    });
                } catch(e) {
                    // Class load failure; skip
                }
            },
            onComplete: function() {
                send({
                    type: 'enumeration_complete',
                    total: totalMethods,
                    message: 'Method enumeration complete'
                });
            }
        });
    });
}

// Flush pending batch on demand
function flushBatch() {
    if (pendingBatch.length > 0) {
        send({
            type: 'coverage_batch',
            methods: pendingBatch.splice(0),
            total: totalMethods,
            hit: hitMethods.size
        });
    }
}

// Get current snapshot
function getSnapshot() {
    flushBatch();
    send({
        type: 'coverage_snapshot',
        total: totalMethods,
        hit: hitMethods.size,
        percentage: totalMethods > 0 ? (hitMethods.size / totalMethods * 100) : 0
    });
}

// RPC exports
rpc.exports = {
    start: function() { enumerateMethods(); },
    flush: function() { flushBatch(); },
    snapshot: function() { getSnapshot(); },
    getHitCount: function() { return hitMethods.size; },
    getTotalCount: function() { return totalMethods; },
    getHitMethods: function() { return Array.from(hitMethods); },
    reset: function() {
        hitMethods.clear();
        pendingBatch.length = 0;
    }
};
"""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CoverageSnapshot:
    total_methods: int = 0
    hit_methods: int = 0
    percentage: float = 0.0
    timestamp: float = field(default_factory=time.time)
    new_methods: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# CoverageManager
# ---------------------------------------------------------------------------

class CoverageManager:
    """Frida-based coverage collection for a target Android app.

    Hooks method entries in the target package's classes, tracks which
    methods have been reached, and reports coverage metrics. Batches
    coverage reports for memory efficiency.
    """

    def __init__(
        self,
        package_name: str,
        device_id: str | None = None,
        batch_size: int = 50,
    ):
        if not FRIDA_AVAILABLE:
            raise RuntimeError("frida-python is required for coverage collection")

        self.package_name = package_name
        self.device_id = device_id
        self.batch_size = batch_size

        self._device: Any = None
        self._session: Any = None
        self._script: Any = None
        self._attached = False

        # Coverage state
        self._hit_methods: set[str] = set()
        self._total_methods: int = 0
        self._enumeration_complete = False

        # Snapshot tracking for coverage-guided fuzzing
        self._snapshot_before: int = 0

    async def attach(self, pid: int | None = None) -> None:
        """Attach Frida to the target app.

        Args:
            pid: Specific PID to attach to. If None, spawns/attaches by package name.
        """
        loop = asyncio.get_event_loop()

        # Get device
        if self.device_id:
            self._device = await loop.run_in_executor(
                None, frida.get_device, self.device_id
            )
        else:
            self._device = await loop.run_in_executor(
                None, frida.get_usb_device
            )

        # Attach to process
        if pid is not None:
            self._session = await loop.run_in_executor(
                None, self._device.attach, pid
            )
        else:
            self._session = await loop.run_in_executor(
                None, self._device.attach, self.package_name
            )

        self._session.on("detached", self._on_detached)

        # Inject script
        script_src = (
            COVERAGE_SCRIPT
            .replace("%TARGET_PACKAGE%", self.package_name)
            .replace("%BATCH_SIZE%", str(self.batch_size))
        )
        self._script = await loop.run_in_executor(
            None, self._session.create_script, script_src
        )
        self._script.on("message", self._on_message)
        await loop.run_in_executor(None, self._script.load)

        # Start enumeration
        await loop.run_in_executor(None, self._script.exports_sync.start)
        self._attached = True
        logger.info("Coverage attached to %s", self.package_name)

    async def detach(self) -> None:
        """Detach Frida from the target app."""
        if self._script:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self._script.unload)
            except Exception:
                pass
            self._script = None

        if self._session:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self._session.detach)
            except Exception:
                pass
            self._session = None

        self._attached = False
        logger.info("Coverage detached from %s", self.package_name)

    def _on_message(self, message: dict, data: Any) -> None:
        """Handle messages from the Frida script."""
        if message.get("type") != "send":
            if message.get("type") == "error":
                logger.error("Frida script error: %s", message.get("description", ""))
            return

        payload = message.get("payload", {})
        msg_type = payload.get("type", "")

        if msg_type == "coverage_batch":
            new_methods = payload.get("methods", [])
            self._hit_methods.update(new_methods)
            self._total_methods = payload.get("total", self._total_methods)

        elif msg_type == "enumeration_complete":
            self._total_methods = payload.get("total", 0)
            self._enumeration_complete = True
            logger.info(
                "Coverage enumeration complete: %d methods in %s",
                self._total_methods, self.package_name,
            )

        elif msg_type == "coverage_snapshot":
            self._total_methods = payload.get("total", self._total_methods)

    def _on_detached(self, reason: str, crash: Any) -> None:
        """Handle Frida session detachment."""
        self._attached = False
        logger.warning(
            "Frida detached from %s: reason=%s crash=%s",
            self.package_name, reason, crash,
        )

    @property
    def is_attached(self) -> bool:
        return self._attached

    async def get_coverage(self) -> CoverageSnapshot:
        """Get current coverage snapshot."""
        if self._script and self._attached:
            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(None, self._script.exports_sync.flush)
            except Exception:
                pass

        total = self._total_methods
        hit = len(self._hit_methods)
        pct = (hit / total * 100.0) if total > 0 else 0.0

        return CoverageSnapshot(
            total_methods=total,
            hit_methods=hit,
            percentage=round(pct, 2),
        )

    def mark_snapshot(self) -> None:
        """Mark current coverage state before sending an intent.

        Call this before sending an intent, then call get_new_coverage()
        after to see if the intent triggered new code paths.
        """
        self._snapshot_before = len(self._hit_methods)

    async def get_new_coverage(self) -> tuple[bool, list[str]]:
        """Check if new code paths were hit since last mark_snapshot().

        Returns:
            Tuple of (has_new_coverage, list_of_new_methods).
        """
        if self._script and self._attached:
            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(None, self._script.exports_sync.flush)
            except Exception:
                pass

        current_count = len(self._hit_methods)
        has_new = current_count > self._snapshot_before

        # Get the new methods (difference since snapshot)
        # We track this by count since we can't diff sets without storing old state
        new_methods: list[str] = []
        if has_new and self._script and self._attached:
            loop = asyncio.get_event_loop()
            try:
                all_hit = await loop.run_in_executor(
                    None, self._script.exports_sync.get_hit_methods
                )
                # Only return what was added since snapshot
                new_methods = all_hit[self._snapshot_before:]
            except Exception:
                pass

        return has_new, new_methods

    async def get_hit_method_names(self) -> set[str]:
        """Return the full set of hit method names."""
        if self._script and self._attached:
            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(None, self._script.exports_sync.flush)
            except Exception:
                pass
        return set(self._hit_methods)

    async def reset(self) -> None:
        """Reset all coverage data."""
        self._hit_methods.clear()
        self._snapshot_before = 0
        if self._script and self._attached:
            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(None, self._script.exports_sync.reset)
            except Exception:
                pass
        logger.info("Coverage reset for %s", self.package_name)
