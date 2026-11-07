"""IntentHunter FastAPI application entry point."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from backend.api import api_router
from backend.config import settings
from backend.database import init_db

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("intethunter")

# Frontend build directory (Vite / React output)
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend" / "dist"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    logger.info(
        "IntentHunter %s starting on %s:%d",
        settings.version,
        settings.host,
        settings.port,
    )
    init_db()
    logger.info("Database initialized at %s", settings.db_path)
    logger.info("Uploads directory: %s", settings.uploads_dir)
    logger.info("Docker emulator: %s", "enabled" if settings.docker_enabled else "disabled")
    yield
    logger.info("IntentHunter shutting down")


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Android Intent Fuzzer -- automated security testing for Android app components",
    lifespan=lifespan,
)

# CORS -- allow all origins for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routes
app.include_router(api_router)

# Serve frontend static assets if the build directory exists
if FRONTEND_DIR.exists():
    app.mount(
        "/assets",
        StaticFiles(directory=str(FRONTEND_DIR / "assets")),
        name="frontend-assets",
    )


@app.get("/health")
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "ok",
        "version": settings.version,
        "app": settings.app_name,
    }


@app.get("/{full_path:path}")
async def spa_fallback(request: Request, full_path: str):
    """
    SPA fallback: serve frontend index.html for all non-API routes.
    This lets the React/Vue/Svelte router handle client-side routing.
    """
    # Skip if path starts with api/ or ws/ -- those are handled by routers
    if full_path.startswith(("api/", "ws/", "health")):
        return HTMLResponse(status_code=404, content="Not found")

    # Try to serve the exact static file first
    static_file = FRONTEND_DIR / full_path
    if static_file.is_file() and FRONTEND_DIR.exists():
        return FileResponse(static_file)

    # Fallback to index.html for SPA routing
    index = FRONTEND_DIR / "index.html"
    if index.exists():
        return FileResponse(index)

    # No frontend build available -- return a minimal page
    return HTMLResponse(
        content="""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IntentHunter</title>
<style>
    body{font-family:system-ui,sans-serif;background:#11111b;color:#cdd6f4;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
    .c{text-align:center;max-width:480px;padding:24px}
    h1{color:#89b4fa;margin-bottom:8px}
    p{color:#a6adc8}
    code{background:#1e1e2e;padding:2px 6px;border-radius:4px;font-size:14px}
    a{color:#89b4fa}
</style>
</head>
<body>
<div class="c">
    <h1>IntentHunter</h1>
    <p>Android Intent Fuzzer</p>
    <p style="margin-top:16px">Frontend not built yet. Run <code>cd frontend && npm run build</code> or access the API directly:</p>
    <p><a href="/docs">/docs</a> -- Swagger UI</p>
    <p><a href="/health">/health</a> -- Health check</p>
</div>
</body>
</html>""",
        status_code=200,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        workers=settings.workers,
    )
