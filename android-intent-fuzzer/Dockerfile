FROM node:20-slim AS frontend-build

WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --production=false 2>/dev/null || true
COPY frontend/ .
RUN npx vite build 2>/dev/null || mkdir -p dist

FROM python:3.11-slim

LABEL maintainer="IntentHunter"
LABEL description="IntentHunter - Android Intent Fuzzer"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    android-tools-adb \
    build-essential \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ backend/
COPY --from=frontend-build /frontend/dist frontend/dist/

RUN mkdir -p data/uploads data/decompiled data/reports

ENV IH_HOST=0.0.0.0 \
    IH_PORT=8745 \
    IH_DEBUG=false \
    IH_DOCKER_ENABLED=true

EXPOSE 8745

CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8745"]
