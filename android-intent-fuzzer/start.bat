@echo off
setlocal enabledelayedexpansion

echo ========================================
echo  IntentHunter - Start
echo ========================================
echo.

:: Activate venv
if not exist "venv\Scripts\activate.bat" (
    echo ERROR: Virtual environment not found. Run setup.bat first.
    pause
    exit /b 1
)
call venv\Scripts\activate.bat

:: Check if emulator should start
set START_EMU=0
if "%1"=="--emulator" set START_EMU=1
if "%1"=="-e" set START_EMU=1

if %START_EMU%==1 (
    echo Starting Docker emulator...
    docker compose --profile emulator up -d emulator
    if %ERRORLEVEL% NEQ 0 (
        echo WARNING: Failed to start emulator. Continuing without it.
    ) else (
        echo Emulator starting in background. noVNC at http://localhost:6080
    )
    echo.
)

:: Create data dirs if missing
if not exist "data" mkdir data
if not exist "data\uploads" mkdir data\uploads
if not exist "data\decompiled" mkdir data\decompiled
if not exist "data\reports" mkdir data\reports

:: Start backend
echo Starting IntentHunter backend on http://localhost:8745 ...
echo Press Ctrl+C to stop.
echo.

:: Open browser after a short delay
start /b cmd /c "timeout /t 3 /nobreak >nul && start http://localhost:8745"

:: Run uvicorn
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8745 --reload

:: Cleanup on exit
if %START_EMU%==1 (
    echo.
    echo Stopping emulator...
    docker compose --profile emulator down
)

echo.
echo IntentHunter stopped.
pause
