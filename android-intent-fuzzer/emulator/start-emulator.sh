#!/usr/bin/env bash
set -euo pipefail

echo "[IntentHunter] Starting Android emulator..."

# Default emulator params (overridable via EMULATOR_PARAMS env)
EMU_PARAMS="${EMULATOR_PARAMS:--memory 2048 -cores 2 -no-window -no-audio -gpu swiftshader_indirect}"

# Start Xvfb for noVNC screen capture
export DISPLAY=:1
Xvfb :1 -screen 0 1080x2400x24 &
sleep 1

# Start emulator in background
emulator -avd intethunter \
    ${EMU_PARAMS} \
    -no-snapshot-save \
    -wipe-data \
    -port 5554 \
    &
EMU_PID=$!

echo "[IntentHunter] Emulator PID: ${EMU_PID}"
echo "[IntentHunter] Waiting for boot..."

# Wait for emulator to fully boot
TIMEOUT=180
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    BOOT_COMPLETE=$(adb -s emulator-5554 shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || echo "")
    if [ "$BOOT_COMPLETE" = "1" ]; then
        echo "[IntentHunter] Emulator booted after ${ELAPSED}s"
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done

if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "[IntentHunter] ERROR: Emulator did not boot within ${TIMEOUT}s"
    exit 1
fi

# Disable animations for faster testing
adb -s emulator-5554 shell settings put global window_animation_scale 0
adb -s emulator-5554 shell settings put global transition_animation_scale 0
adb -s emulator-5554 shell settings put global animator_duration_scale 0

# Enable ADB over TCP for external connections
adb -s emulator-5554 tcpip 5555
sleep 1

# Push and start Frida server
echo "[IntentHunter] Starting Frida server..."
adb -s emulator-5554 root
sleep 1
adb -s emulator-5554 push /opt/frida-server /data/local/tmp/frida-server
adb -s emulator-5554 shell chmod 755 /data/local/tmp/frida-server
adb -s emulator-5554 shell "nohup /data/local/tmp/frida-server -l 0.0.0.0:27042 &" &
sleep 2

# Verify Frida is running
FRIDA_CHECK=$(adb -s emulator-5554 shell "ps -A | grep frida" 2>/dev/null || echo "")
if echo "$FRIDA_CHECK" | grep -q "frida"; then
    echo "[IntentHunter] Frida server running"
else
    echo "[IntentHunter] WARNING: Frida server may not be running"
fi

# Start x11vnc for noVNC
x11vnc -display :1 -forever -nopw -shared -rfbport 5900 &
sleep 1

# Start noVNC (websocket proxy for VNC)
echo "[IntentHunter] Starting noVNC on port 6080..."
websockify --web /usr/share/novnc 6080 localhost:5900 &

echo "[IntentHunter] ================================================"
echo "[IntentHunter] Emulator ready"
echo "[IntentHunter]   ADB:   port 5555"
echo "[IntentHunter]   noVNC: http://localhost:6080"
echo "[IntentHunter]   Frida: port 27042"
echo "[IntentHunter] ================================================"

# Keep the container alive by waiting on the emulator process
wait ${EMU_PID}
