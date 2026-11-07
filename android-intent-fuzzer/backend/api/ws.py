"""WebSocket endpoints for real-time scan progress and logcat streaming."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.models import ScanStatus

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])


class ConnectionManager:
    """Manages WebSocket connections grouped by topic (scan_id or device_id)."""

    def __init__(self):
        self._connections: dict[str, list[WebSocket]] = {}

    async def connect(self, topic: str, ws: WebSocket):
        await ws.accept()
        self._connections.setdefault(topic, []).append(ws)
        logger.debug("WS connected: topic=%s (total=%d)", topic, len(self._connections[topic]))

    def disconnect(self, topic: str, ws: WebSocket):
        conns = self._connections.get(topic, [])
        if ws in conns:
            conns.remove(ws)
        if not conns:
            self._connections.pop(topic, None)
        logger.debug("WS disconnected: topic=%s", topic)

    async def broadcast(self, topic: str, data: dict[str, Any]):
        """Send a JSON message to all connections on a topic."""
        conns = self._connections.get(topic, [])
        dead = []
        message = json.dumps(data)
        for ws in conns:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(topic, ws)

    async def send_personal(self, ws: WebSocket, data: dict[str, Any]):
        try:
            await ws.send_text(json.dumps(data))
        except Exception:
            pass

    @property
    def active_topics(self) -> list[str]:
        return list(self._connections.keys())


# Global connection manager shared across the app
scan_manager = ConnectionManager()
logcat_manager = ConnectionManager()


@router.websocket("/ws/scan/{scan_id}")
async def ws_scan_progress(ws: WebSocket, scan_id: int):
    """
    Stream ScanProgress JSON messages for an active scan.

    Messages follow the ScanProgress schema:
    {
        "scan_id": int,
        "status": str,
        "phase": str,
        "progress_pct": float,
        "coverage_pct": float,
        "intents_sent": int,
        "crashes": int,
        "findings_count": int,
        "current_plugin": str,
        "message": str
    }
    """
    topic = f"scan:{scan_id}"
    await scan_manager.connect(topic, ws)
    try:
        # Send initial ack
        await scan_manager.send_personal(ws, {
            "type": "connected",
            "scan_id": scan_id,
            "message": "Subscribed to scan progress",
        })

        # Keep connection alive; ScanEngine pushes messages via broadcast
        while True:
            # Wait for client pings or close
            try:
                data = await asyncio.wait_for(ws.receive_text(), timeout=30.0)
                # Client can send {"type": "ping"}
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await scan_manager.send_personal(ws, {"type": "pong"})
            except asyncio.TimeoutError:
                # Send keepalive
                await scan_manager.send_personal(ws, {"type": "keepalive"})
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("WS scan connection error: %s", exc)
    finally:
        scan_manager.disconnect(topic, ws)


@router.websocket("/ws/logcat/{device_id}")
async def ws_logcat_stream(ws: WebSocket, device_id: str):
    """
    Stream logcat output from a device in real-time.

    Messages:
    {"type": "logcat", "line": "...", "timestamp": "..."}
    """
    topic = f"logcat:{device_id}"
    await logcat_manager.connect(topic, ws)

    process = None
    try:
        await logcat_manager.send_personal(ws, {
            "type": "connected",
            "device_id": device_id,
            "message": "Subscribed to logcat stream",
        })

        from backend.config import settings

        # Start adb logcat as a subprocess
        process = await asyncio.create_subprocess_exec(
            settings.adb_path, "-s", device_id, "logcat", "-v", "threadtime",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async def _read_logcat():
            while process and process.stdout:
                line_bytes = await process.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace").rstrip()
                if line:
                    await logcat_manager.send_personal(ws, {
                        "type": "logcat",
                        "line": line,
                        "device_id": device_id,
                    })

        async def _read_client():
            while True:
                try:
                    data = await ws.receive_text()
                    msg = json.loads(data)
                    if msg.get("type") == "ping":
                        await logcat_manager.send_personal(ws, {"type": "pong"})
                    elif msg.get("type") == "filter":
                        # Client can request a tag filter -- restart logcat
                        pass
                except WebSocketDisconnect:
                    raise
                except Exception:
                    break

        # Run both tasks concurrently
        done, pending = await asyncio.wait(
            [
                asyncio.create_task(_read_logcat()),
                asyncio.create_task(_read_client()),
            ],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("WS logcat connection error: %s", exc)
    finally:
        if process:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        logcat_manager.disconnect(topic, ws)


async def broadcast_scan_progress(
    scan_id: int,
    status: str,
    phase: str,
    progress_pct: float,
    coverage_pct: float = 0.0,
    intents_sent: int = 0,
    crashes: int = 0,
    findings_count: int = 0,
    current_plugin: str = "",
    message: str = "",
):
    """Helper for ScanEngine to push progress updates to connected clients."""
    topic = f"scan:{scan_id}"
    await scan_manager.broadcast(topic, {
        "type": "scan_progress",
        "scan_id": scan_id,
        "status": status,
        "phase": phase,
        "progress_pct": progress_pct,
        "coverage_pct": coverage_pct,
        "intents_sent": intents_sent,
        "crashes": crashes,
        "findings_count": findings_count,
        "current_plugin": current_plugin,
        "message": message,
    })
