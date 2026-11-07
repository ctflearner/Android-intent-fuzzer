"""Crash and anomaly detection engine for IntentHunter.

Monitors logcat asynchronously for Java exceptions, native crashes,
ANRs, SecurityExceptions, and permission denials. Also detects Frida
process crashes. Rate-limited crash collection via configurable cooldown.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from backend.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

class CrashType(str, Enum):
    JAVA_EXCEPTION = "java_exception"
    NATIVE_CRASH = "native_crash"
    ANR = "anr"
    SECURITY_EXCEPTION = "security_exception"
    PERMISSION_DENIAL = "permission_denial"
    FRIDA_CRASH = "frida_crash"


@dataclass
class CrashEvent:
    timestamp: float
    crash_type: CrashType
    stacktrace: str
    triggering_intent: str = ""
    process_name: str = ""
    signal: str = ""
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "crash_type": self.crash_type.value,
            "stacktrace": self.stacktrace[:5000],
            "triggering_intent": self.triggering_intent,
            "process_name": self.process_name,
            "signal": self.signal,
            "summary": self.summary,
        }


# ---------------------------------------------------------------------------
# Logcat patterns
# ---------------------------------------------------------------------------

# Java crash: "FATAL EXCEPTION:" followed by stacktrace
RE_FATAL_EXCEPTION = re.compile(
    r"FATAL EXCEPTION:.*?$", re.MULTILINE
)
# Native crash: "Fatal signal" or tombstone markers
RE_NATIVE_CRASH = re.compile(
    r"(?:Fatal signal \d+|DEBUG\s*:\s*\*\*\*\s*\*\*\*)", re.MULTILINE
)
# ANR detection
RE_ANR = re.compile(
    r"ANR in (\S+)", re.MULTILINE
)
# SecurityException
RE_SECURITY_EXCEPTION = re.compile(
    r"java\.lang\.SecurityException:(.+?)$", re.MULTILINE
)
# Permission denial
RE_PERMISSION_DENIAL = re.compile(
    r"Permission Denial:(.+?)$", re.MULTILINE
)
# Process crash indicator
RE_PROCESS_CRASH = re.compile(
    r"Process:\s*(\S+),\s*PID:\s*\d+", re.MULTILINE
)


# ---------------------------------------------------------------------------
# CrashDetector
# ---------------------------------------------------------------------------

class CrashDetector:
    """Asynchronous crash and anomaly detector.

    Monitors logcat output and Frida session for crashes, exceptions,
    ANRs, and permission denials. Rate-limits collection to avoid
    flooding on crash loops.
    """

    def __init__(self, cooldown: float | None = None):
        self._cooldown = cooldown if cooldown is not None else settings.crash_cooldown_seconds
        self._crashes: list[CrashEvent] = []
        self._monitoring = False
        self._logcat_task: asyncio.Task | None = None
        self._package: str = ""
        self._device_id: str = ""
        self._last_crash_time: float = 0.0
        self._current_intent: str = ""
        self._max_crashes = 1000  # Memory cap

        # Buffer for multi-line stacktrace assembly
        self._line_buffer: list[str] = []
        self._buffer_crash_type: CrashType | None = None
        self._buffer_start_time: float = 0.0

    async def start_monitoring(self, device_id: str, package: str) -> None:
        """Start async logcat monitoring for the target package.

        Args:
            device_id: ADB device serial (e.g., "emulator-5554").
            package: Target app package name to filter.
        """
        if self._monitoring:
            logger.warning("Crash monitoring already active for %s", self._package)
            return

        self._device_id = device_id
        self._package = package
        self._monitoring = True
        self._crashes.clear()
        self._line_buffer.clear()
        self._buffer_crash_type = None

        # Clear existing logcat
        clear_proc = await asyncio.create_subprocess_exec(
            settings.adb_path, "-s", device_id, "logcat", "-c",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await clear_proc.communicate()

        self._logcat_task = asyncio.create_task(self._logcat_reader())
        logger.info("Crash monitoring started for %s on %s", package, device_id)

    async def stop_monitoring(self) -> None:
        """Stop logcat monitoring."""
        self._monitoring = False
        if self._logcat_task:
            self._logcat_task.cancel()
            try:
                await self._logcat_task
            except asyncio.CancelledError:
                pass
            self._logcat_task = None

        # Flush any remaining buffer
        self._flush_buffer()
        logger.info("Crash monitoring stopped for %s", self._package)

    def set_current_intent(self, intent_desc: str) -> None:
        """Set the intent currently being tested, for crash correlation."""
        self._current_intent = intent_desc

    def get_crashes(self) -> list[CrashEvent]:
        """Return all collected crash events."""
        return list(self._crashes)

    def get_crashes_since(self, timestamp: float) -> list[CrashEvent]:
        """Return crashes after a given timestamp."""
        return [c for c in self._crashes if c.timestamp > timestamp]

    @property
    def crash_count(self) -> int:
        return len(self._crashes)

    @property
    def is_monitoring(self) -> bool:
        return self._monitoring

    # ------------------------------------------------------------------
    # Frida crash detection
    # ------------------------------------------------------------------

    def on_frida_detach(self, reason: str, crash: Any) -> None:
        """Called when Frida detects the target process crashed.

        Wire this into the Frida session's 'detached' event.
        """
        if reason == "process-terminated" or crash is not None:
            now = time.time()
            if not self._check_cooldown(now):
                return

            summary = f"Process terminated: {reason}"
            stacktrace = ""
            if crash is not None:
                summary = str(getattr(crash, "summary", crash))
                stacktrace = str(getattr(crash, "report", ""))

            event = CrashEvent(
                timestamp=now,
                crash_type=CrashType.FRIDA_CRASH,
                stacktrace=stacktrace[:5000],
                triggering_intent=self._current_intent,
                process_name=self._package,
                summary=summary,
            )
            self._add_crash(event)
            logger.warning("Frida detected process crash: %s", summary)

    # ------------------------------------------------------------------
    # Internal: logcat reader
    # ------------------------------------------------------------------

    async def _logcat_reader(self) -> None:
        """Continuously read logcat output and parse for crashes."""
        cmd = [
            settings.adb_path, "-s", self._device_id,
            "logcat",
            "-v", "threadtime",
            "--pid=" if False else "*:W",  # Warning level and above
        ]
        # Filter by package if possible (logcat --pid requires PID)
        # We filter in post-processing instead for reliability
        cmd = [
            settings.adb_path, "-s", self._device_id,
            "logcat", "-v", "threadtime", "*:W",
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )

        try:
            while self._monitoring and proc.stdout:
                try:
                    line_bytes = await asyncio.wait_for(
                        proc.stdout.readline(), timeout=5.0
                    )
                except asyncio.TimeoutError:
                    continue

                if not line_bytes:
                    break

                line = line_bytes.decode("utf-8", errors="replace").rstrip()
                if not line:
                    continue

                self._process_logcat_line(line)

        except asyncio.CancelledError:
            pass
        finally:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()

    def _process_logcat_line(self, line: str) -> None:
        """Process a single logcat line for crash indicators."""
        now = time.time()

        # Check if we're in a multi-line stacktrace collection
        if self._buffer_crash_type is not None:
            # Stacktrace continuation: lines starting with whitespace + "at " or "Caused by:"
            if (line.lstrip().startswith("at ") or
                line.lstrip().startswith("Caused by:") or
                line.lstrip().startswith("... ") or
                (self._line_buffer and time.time() - self._buffer_start_time < 2.0 and
                 "\t" in line)):
                self._line_buffer.append(line)
                if len(self._line_buffer) > 200:
                    self._flush_buffer()
                return
            else:
                self._flush_buffer()

        # Detect FATAL EXCEPTION
        if "FATAL EXCEPTION:" in line:
            if self._check_cooldown(now) and self._is_relevant(line):
                self._buffer_crash_type = CrashType.JAVA_EXCEPTION
                self._buffer_start_time = now
                self._line_buffer = [line]
                return

        # Detect native crash
        if RE_NATIVE_CRASH.search(line):
            if self._check_cooldown(now) and self._is_relevant(line):
                signal_match = re.search(r"Fatal signal (\d+)", line)
                signal = signal_match.group(1) if signal_match else ""
                event = CrashEvent(
                    timestamp=now,
                    crash_type=CrashType.NATIVE_CRASH,
                    stacktrace=line[:5000],
                    triggering_intent=self._current_intent,
                    process_name=self._package,
                    signal=signal,
                    summary=f"Native crash: signal {signal}",
                )
                self._add_crash(event)
                return

        # Detect ANR
        anr_match = RE_ANR.search(line)
        if anr_match:
            process = anr_match.group(1)
            if self._package in process and self._check_cooldown(now):
                event = CrashEvent(
                    timestamp=now,
                    crash_type=CrashType.ANR,
                    stacktrace=line[:5000],
                    triggering_intent=self._current_intent,
                    process_name=process,
                    summary=f"ANR in {process}",
                )
                self._add_crash(event)
                return

        # Detect SecurityException
        sec_match = RE_SECURITY_EXCEPTION.search(line)
        if sec_match:
            if self._check_cooldown(now) and self._is_relevant(line):
                event = CrashEvent(
                    timestamp=now,
                    crash_type=CrashType.SECURITY_EXCEPTION,
                    stacktrace=line[:5000],
                    triggering_intent=self._current_intent,
                    process_name=self._package,
                    summary=f"SecurityException: {sec_match.group(1).strip()[:200]}",
                )
                self._add_crash(event)
                return

        # Detect Permission Denial
        perm_match = RE_PERMISSION_DENIAL.search(line)
        if perm_match:
            if self._check_cooldown(now) and self._is_relevant(line):
                event = CrashEvent(
                    timestamp=now,
                    crash_type=CrashType.PERMISSION_DENIAL,
                    stacktrace=line[:5000],
                    triggering_intent=self._current_intent,
                    process_name=self._package,
                    summary=f"Permission Denial: {perm_match.group(1).strip()[:200]}",
                )
                self._add_crash(event)
                return

    def _flush_buffer(self) -> None:
        """Flush the multi-line stacktrace buffer into a CrashEvent."""
        if not self._line_buffer or self._buffer_crash_type is None:
            self._line_buffer.clear()
            self._buffer_crash_type = None
            return

        stacktrace = "\n".join(self._line_buffer)
        summary_line = self._line_buffer[0] if self._line_buffer else ""

        # Extract process name from stacktrace
        process = self._package
        proc_match = RE_PROCESS_CRASH.search(stacktrace)
        if proc_match:
            process = proc_match.group(1)

        event = CrashEvent(
            timestamp=self._buffer_start_time,
            crash_type=self._buffer_crash_type,
            stacktrace=stacktrace[:5000],
            triggering_intent=self._current_intent,
            process_name=process,
            summary=summary_line[:300],
        )
        self._add_crash(event)

        self._line_buffer.clear()
        self._buffer_crash_type = None

    def _add_crash(self, event: CrashEvent) -> None:
        """Add a crash event, respecting memory cap."""
        if len(self._crashes) >= self._max_crashes:
            # Keep the last half + new
            self._crashes = self._crashes[-(self._max_crashes // 2):]
        self._crashes.append(event)
        self._last_crash_time = event.timestamp
        logger.info(
            "Crash detected [%s]: %s",
            event.crash_type.value, event.summary[:100],
        )

    def _check_cooldown(self, now: float) -> bool:
        """Return True if enough time has passed since last crash."""
        return (now - self._last_crash_time) >= self._cooldown

    def _is_relevant(self, line: str) -> bool:
        """Check if a logcat line is relevant to our target package."""
        # If no package filter, accept everything
        if not self._package:
            return True
        return self._package in line
