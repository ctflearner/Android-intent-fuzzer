@echo off
setlocal enabledelayedexpansion

echo ========================================
echo  IntentHunter - Setup
echo ========================================
echo.

:: Check Python version
echo [1/6] Checking Python...
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python not found. Install Python 3.11+ from https://python.org
    pause
    exit /b 1
)
for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
for /f "tokens=1,2 delims=." %%a in ("%PYVER%") do (
    set PYMAJOR=%%a
    set PYMINOR=%%b
)
if %PYMAJOR% LSS 3 (
    echo ERROR: Python 3.11+ required, found %PYVER%
    pause
    exit /b 1
)
if %PYMAJOR%==3 if %PYMINOR% LSS 11 (
    echo ERROR: Python 3.11+ required, found %PYVER%
    pause
    exit /b 1
)
echo   Python %PYVER% OK

:: Create venv
echo.
echo [2/6] Creating virtual environment...
if not exist "venv" (
    python -m venv venv
    echo   venv created
) else (
    echo   venv already exists
)

:: Install requirements
echo.
echo [3/6] Installing Python dependencies...
call venv\Scripts\activate.bat
pip install --upgrade pip >nul 2>&1
pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: pip install failed
    pause
    exit /b 1
)
echo   Dependencies installed

:: Check Docker
echo.
echo [4/6] Checking Docker...
docker --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo   WARNING: Docker not found. Emulator container will not be available.
    echo   Install Docker Desktop from https://docker.com if you need the emulator.
) else (
    for /f "tokens=*" %%v in ('docker --version') do echo   %%v

    set /p BUILD_EMU="   Build Docker emulator image? (y/N): "
    if /i "!BUILD_EMU!"=="y" (
        echo   Building emulator image... this will take a while
        docker build -t intethunter/android-emu:api34 ./emulator
        if %ERRORLEVEL% NEQ 0 (
            echo   WARNING: Emulator image build failed. You can retry later.
        ) else (
            echo   Emulator image built successfully
        )
    )
)

:: Check adb and jadx
echo.
echo [5/6] Checking tools...
adb version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo   WARNING: adb not found in PATH.
    echo   Install Android SDK Platform-Tools or set ADB_PATH in .env
) else (
    echo   adb OK
)

jadx --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo   WARNING: jadx not found in PATH.
    echo   Install from https://github.com/skylot/jadx/releases or set JADX_PATH in .env
) else (
    echo   jadx OK
)

:: Create .env file
echo.
echo [6/6] Creating .env file...
if not exist ".env" (
    copy .env.example .env >nul
    echo   .env created from .env.example
    echo   Edit .env to customize settings
) else (
    echo   .env already exists, skipping
)

:: Create data directories
if not exist "data" mkdir data
if not exist "data\uploads" mkdir data\uploads
if not exist "data\decompiled" mkdir data\decompiled
if not exist "data\reports" mkdir data\reports

echo.
echo ========================================
echo  Setup complete!
echo ========================================
echo.
echo  Next steps:
echo    1. Edit .env if needed
echo    2. Run start.bat to launch IntentHunter
echo    3. Open http://localhost:8745
echo.
pause
