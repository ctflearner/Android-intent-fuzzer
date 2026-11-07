import os
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "IntentHunter"
    version: str = "1.0.0"
    debug: bool = False

    base_dir: Path = Path(__file__).resolve().parent.parent
    data_dir: Path = base_dir / "data"
    uploads_dir: Path = data_dir / "uploads"
    decompiled_dir: Path = data_dir / "decompiled"
    reports_dir: Path = data_dir / "reports"
    db_path: Path = data_dir / "intethunter.db"

    host: str = "0.0.0.0"
    port: int = 8745
    workers: int = 1

    adb_path: str = os.getenv("ADB_PATH", "adb")
    jadx_path: str = os.getenv("JADX_PATH", "jadx")
    apktool_path: str = os.getenv("APKTOOL_PATH", "apktool")

    frida_host: str = "127.0.0.1"
    frida_port: int = 27042

    docker_enabled: bool = True
    emulator_image: str = "intethunter/android-emu:api34"
    emulator_memory_mb: int = 2048
    emulator_cpus: int = 2
    emulator_api_level: int = 34
    emulator_container_name: str = "intethunter-emu"

    max_fuzz_iterations: int = 10000
    fuzz_timeout_seconds: int = 300
    coverage_sample_interval_ms: int = 100
    crash_cooldown_seconds: int = 2

    max_concurrent_scans: int = 2
    max_upload_size_mb: int = 500

    class Config:
        env_prefix = "IH_"
        env_file = ".env"


settings = Settings()

for d in [settings.data_dir, settings.uploads_dir, settings.decompiled_dir, settings.reports_dir]:
    d.mkdir(parents=True, exist_ok=True)
