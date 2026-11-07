from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
from dataclasses import dataclass, field
from typing import Any

from backend.config import settings

logger = logging.getLogger(__name__)


@dataclass
class DeviceHandle:
    device_id: str
    device_type: str  # docker, local_adb, remote_adb
    model: str = ""
    android_version: str = ""
    api_level: int = 0
    rooted: bool = False
    frida_running: bool = False
    _adb_prefix: list[str] = field(default_factory=list)

    def __post_init__(self):
        self._adb_prefix = [settings.adb_path, "-s", self.device_id]

    async def shell(self, cmd: str, timeout: int = 30) -> str:
        proc = await asyncio.create_subprocess_exec(
            *self._adb_prefix, "shell", cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return ""
        return stdout.decode("utf-8", errors="replace").strip()

    async def push(self, local: str, remote: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            *self._adb_prefix, "push", local, remote,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return proc.returncode == 0

    async def pull(self, remote: str, local: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            *self._adb_prefix, "pull", remote, local,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return proc.returncode == 0

    async def install_apk(self, apk_path: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            *self._adb_prefix, "install", "-r", "-g", apk_path,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), 120)
        return b"Success" in stdout

    async def uninstall(self, package: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            *self._adb_prefix, "uninstall", package,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return proc.returncode == 0

    async def am(self, subcommand: str, args: list[str]) -> str:
        cmd = f"am {subcommand} {' '.join(args)}"
        return await self.shell(cmd)

    async def start_activity(self, args: list[str]) -> str:
        return await self.am("start", args)

    async def send_broadcast(self, args: list[str]) -> str:
        return await self.am("broadcast", args)

    async def start_service(self, args: list[str]) -> str:
        return await self.am("startservice", args)

    async def content_query(self, uri: str, projection: str = "", selection: str = "") -> str:
        cmd = f"content query --uri {uri}"
        if projection:
            cmd += f" --projection {projection}"
        if selection:
            cmd += f" --where \"{selection}\""
        return await self.shell(cmd)

    async def logcat_snapshot(self, tag: str = "", lines: int = 200) -> str:
        cmd = f"logcat -d -t {lines}"
        if tag:
            cmd += f" -s {tag}"
        return await self.shell(cmd)

    async def clear_logcat(self):
        await self.shell("logcat -c")

    async def list_packages(self) -> list[str]:
        output = await self.shell("pm list packages")
        return [line.replace("package:", "") for line in output.splitlines() if line.startswith("package:")]

    async def get_package_info(self, package: str) -> dict[str, Any]:
        output = await self.shell(f"dumpsys package {package}")
        info = {"raw": output}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("versionName="):
                info["version_name"] = line.split("=", 1)[1]
            elif line.startswith("versionCode="):
                info["version_code"] = line.split("=", 1)[1].split()[0]
            elif line.startswith("targetSdk="):
                info["target_sdk"] = int(line.split("=", 1)[1])
        return info

    async def check_root(self) -> bool:
        result = await self.shell("id")
        return "uid=0" in result or "root" in result

    async def check_frida(self) -> bool:
        result = await self.shell("ps -A | grep frida")
        return "frida" in result.lower()

    async def start_frida_server(self) -> bool:
        await self.shell("nohup /data/local/tmp/frida-server &")
        await asyncio.sleep(1)
        return await self.check_frida()

    async def screenshot(self, local_path: str) -> bool:
        remote = "/data/local/tmp/ih_screen.png"
        await self.shell(f"screencap -p {remote}")
        return await self.pull(remote, local_path)

    async def get_clipboard(self) -> str:
        return await self.shell("service call clipboard 2 s16 com.android.shell")


class DeviceManager:
    def __init__(self):
        self._devices: dict[str, DeviceHandle] = {}

    async def discover_devices(self) -> list[DeviceHandle]:
        devices = []
        adb = settings.adb_path
        if not shutil.which(adb):
            logger.warning("adb not found at %s", adb)
            return devices

        proc = await asyncio.create_subprocess_exec(
            adb, "devices", "-l",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        for line in stdout.decode().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                dev_id = parts[0]
                model = ""
                for p in parts[2:]:
                    if p.startswith("model:"):
                        model = p.split(":", 1)[1]
                handle = DeviceHandle(
                    device_id=dev_id,
                    device_type="local_adb",
                    model=model,
                )
                version = await handle.shell("getprop ro.build.version.release")
                api = await handle.shell("getprop ro.build.version.sdk")
                handle.android_version = version
                handle.api_level = int(api) if api.isdigit() else 0
                handle.rooted = await handle.check_root()
                handle.frida_running = await handle.check_frida()
                devices.append(handle)
                self._devices[dev_id] = handle

        return devices

    async def get_device(self, device_id: str) -> DeviceHandle | None:
        if device_id in self._devices:
            return self._devices[device_id]
        await self.discover_devices()
        return self._devices.get(device_id)

    async def get_or_create_emulator(self) -> DeviceHandle | None:
        from backend.core.emulator_manager import EmulatorManager
        emu = EmulatorManager()
        return await emu.get_or_create()
