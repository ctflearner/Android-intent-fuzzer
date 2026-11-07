"""Device management API routes."""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from backend.core.device_manager import DeviceManager
from backend.core.emulator_manager import EmulatorManager
from backend.plugins import ALL_PLUGINS
from backend.schemas import DeviceInfo, PluginInfo

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["devices"])

# Shared singleton instances
_device_manager = DeviceManager()
_emulator_manager = EmulatorManager()


@router.get("/plugins", response_model=list[PluginInfo], tags=["plugins"])
async def list_plugins():
    """List all available plugins."""
    result = []
    for name, cls in ALL_PLUGINS.items():
        instance = cls()
        info = instance.info()
        result.append(PluginInfo(
            name=info["name"],
            display_name=info["display_name"],
            description=info["description"],
            version=info["version"],
            requires_device=info["requires_device"],
            attack_vectors=info["attack_vectors"],
            enabled=True,
        ))
    return result


@router.get("/devices", response_model=list[DeviceInfo])
async def list_devices():
    """List all connected ADB devices."""
    devices = await _device_manager.discover_devices()
    return [
        DeviceInfo(
            device_id=d.device_id,
            device_type=d.device_type,
            model=d.model,
            android_version=d.android_version,
            api_level=d.api_level,
            rooted=d.rooted,
            frida_running=d.frida_running,
            status="online",
        )
        for d in devices
    ]


@router.post("/devices/emulator", response_model=DeviceInfo, status_code=201)
async def create_emulator():
    """Create and start a Docker Android emulator."""
    try:
        handle = await _emulator_manager.get_or_create()
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))

    if not handle:
        raise HTTPException(503, "Failed to start emulator; check Docker and image availability")

    return DeviceInfo(
        device_id=handle.device_id,
        device_type=handle.device_type,
        model=handle.model,
        android_version=handle.android_version,
        api_level=handle.api_level,
        rooted=handle.rooted,
        frida_running=handle.frida_running,
        status="online",
    )


@router.delete("/devices/emulator", status_code=204)
async def destroy_emulator():
    """Stop and remove the Docker Android emulator."""
    try:
        await _emulator_manager.destroy()
    except Exception as exc:
        logger.exception("Failed to destroy emulator")
        raise HTTPException(500, f"Failed to destroy emulator: {exc}")

    logger.info("Emulator destroyed")


@router.get("/devices/{device_id}", response_model=DeviceInfo)
async def get_device_info(device_id: str):
    """Get detailed info for a specific device."""
    handle = await _device_manager.get_device(device_id)
    if not handle:
        raise HTTPException(404, f"Device {device_id} not found or offline")

    # Refresh live status
    handle.frida_running = await handle.check_frida()
    handle.rooted = await handle.check_root()

    return DeviceInfo(
        device_id=handle.device_id,
        device_type=handle.device_type,
        model=handle.model,
        android_version=handle.android_version,
        api_level=handle.api_level,
        rooted=handle.rooted,
        frida_running=handle.frida_running,
        status="online",
    )
