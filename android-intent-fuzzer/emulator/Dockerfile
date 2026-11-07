FROM ubuntu:22.04

LABEL maintainer="IntentHunter"
LABEL description="Android emulator with Frida server and noVNC"

ENV DEBIAN_FRONTEND=noninteractive \
    ANDROID_HOME=/opt/android-sdk \
    ANDROID_SDK_ROOT=/opt/android-sdk \
    PATH="${PATH}:/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools:/opt/android-sdk/emulator" \
    FRIDA_VERSION=16.5.2

# Base system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
    wget \
    xz-utils \
    openjdk-17-jdk-headless \
    libglu1-mesa \
    libpulse0 \
    libasound2 \
    libx11-6 \
    libxcb1 \
    libxcomposite1 \
    libxcursor1 \
    libxi6 \
    libxtst6 \
    libxrandr2 \
    libfreetype6 \
    libfontconfig1 \
    socat \
    adb \
    # noVNC deps
    net-tools \
    x11vnc \
    xvfb \
    novnc \
    websockify \
    && rm -rf /var/lib/apt/lists/*

# Install Android command-line tools
RUN mkdir -p ${ANDROID_HOME}/cmdline-tools && \
    cd ${ANDROID_HOME}/cmdline-tools && \
    curl -sSL -o cmdline-tools.zip \
        "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip" && \
    unzip -q cmdline-tools.zip && \
    mv cmdline-tools latest && \
    rm cmdline-tools.zip

# Accept licenses and install SDK components
RUN yes | sdkmanager --licenses > /dev/null 2>&1 && \
    sdkmanager --install \
        "platform-tools" \
        "emulator" \
        "platforms;android-34" \
        "system-images;android-34;google_apis;x86_64"

# Create AVD
RUN echo "no" | avdmanager create avd \
    --name "intethunter" \
    --package "system-images;android-34;google_apis;x86_64" \
    --device "pixel_6" \
    --force

# AVD config: disable GPU for container, increase RAM
RUN mkdir -p /root/.android/avd/intethunter.avd && \
    echo 'hw.gpu.enabled=yes\nhw.gpu.mode=swiftshader_indirect\nhw.ramSize=2048\nhw.lcd.density=320\nhw.lcd.width=1080\nhw.lcd.height=2400\ndisk.dataPartition.size=4096M\nhw.keyboard=yes\nhw.mainKeys=no' \
    >> /root/.android/avd/intethunter.avd/config.ini

# Download Frida server for x86_64
RUN cd /tmp && \
    curl -sSL -o frida-server.xz \
        "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-x86_64.xz" && \
    xz -d frida-server.xz && \
    chmod +x frida-server && \
    mv frida-server /opt/frida-server

# noVNC setup
RUN ln -sf /usr/share/novnc/vnc_lite.html /usr/share/novnc/index.html 2>/dev/null || true

COPY start-emulator.sh /opt/start-emulator.sh
RUN chmod +x /opt/start-emulator.sh

EXPOSE 5555 6080 27042

ENTRYPOINT ["/opt/start-emulator.sh"]
