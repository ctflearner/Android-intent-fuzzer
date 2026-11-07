from __future__ import annotations

import asyncio
import logging

from backend.config import settings
from backend.core.device_manager import DeviceHandle

logger = logging.getLogger(__name__)

try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False


class EmulatorManager:
    def __init__(self):
        self._client = None
        self._container = None

    def _get_client(self):
        if not DOCKER_AVAILABLE:
            raise RuntimeError("Docker SDK not installed: pip install docker")
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    async def get_or_create(self) -> DeviceHandle | None:
        if not settings.docker_enabled or not DOCKER_AVAILABLE:
            logger.info("Docker emulator disabled or unavailable")
            return None

        loop = asyncio.get_event_loop()
        client = self._get_client()

        try:
            container = await loop.run_in_executor(
                None, lambda: client.containers.get(settings.emulator_container_name)
            )
            if container.status != "running":
                await loop.run_in_executor(None, container.start)
                await asyncio.sleep(5)
        except docker.errors.NotFound:
            container = await self._create_container(client, loop)

        self._container = container
        device_id = await self._wait_for_adb(container)
        if not device_id:
            return None

        handle = DeviceHandle(
            device_id=device_id,
            device_type="docker",
            model="Docker Emulator",
        )
        version = await handle.shell("getprop ro.build.version.release")
        api = await handle.shell("getprop ro.build.version.sdk")
        handle.android_version = version
        handle.api_level = int(api) if api.isdigit() else 0
        handle.rooted = True
        handle.frida_running = await handle.check_frida()
        if not handle.frida_running:
            await handle.start_frida_server()
            handle.frida_running = await handle.check_frida()

        return handle

    async def _create_container(self, client, loop):
        logger.info("Creating Android emulator container...")
        container = await loop.run_in_executor(
            None,
            lambda: client.containers.run(
                settings.emulator_image,
                name=settings.emulator_container_name,
                detach=True,
                privileged=True,
                ports={"5555/tcp": 5555, "6080/tcp": 6080, "27042/tcp": 27042},
                environment={
                    "EMULATOR_PARAMS": f"-memory {settings.emulator_memory_mb} -cores {settings.emulator_cpus} -no-window -no-audio -gpu swiftshader_indirect",
                },
                mem_limit=f"{settings.emulator_memory_mb + 512}m",
                cpuset_cpus=f"0-{settings.emulator_cpus - 1}",
            ),
        )
        logger.info("Emulator container created, waiting for boot...")
        await asyncio.sleep(15)
        return container

    async def _wait_for_adb(self, container, timeout: int = 60) -> str | None:
        adb = settings.adb_path
        device_id = f"localhost:5555"

        proc = await asyncio.create_subprocess_exec(
            adb, "connect", device_id,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

        for _ in range(timeout // 2):
            proc = await asyncio.create_subprocess_exec(
                adb, "-s", device_id, "shell", "getprop", "sys.boot_completed",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if stdout.decode().strip() == "1":
                logger.info("Emulator booted successfully")
                return device_id
            await asyncio.sleep(2)

        logger.error("Emulator failed to boot within %ds", timeout)
        return None

    async def snapshot_save(self, name: str = "clean"):
        if self._container:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: self._container.exec_run(
                f"adb emu avd snapshot save {name}"
            ))

    async def snapshot_restore(self, name: str = "clean"):
        if self._container:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: self._container.exec_run(
                f"adb emu avd snapshot load {name}"
            ))

    async def destroy(self):
        if self._container:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._container.stop)
            await loop.run_in_executor(None, self._container.remove)
            self._container = None

    async def get_stream_url(self) -> str:
        return "http://localhost:6080"
