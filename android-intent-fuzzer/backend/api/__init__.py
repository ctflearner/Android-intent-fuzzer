"""IntentHunter API router aggregation."""
from fastapi import APIRouter

from backend.api.scans import router as scans_router
from backend.api.findings import router as findings_router
from backend.api.devices import router as devices_router
from backend.api.reports import router as reports_router
from backend.api.ws import router as ws_router

api_router = APIRouter()
api_router.include_router(scans_router)
api_router.include_router(findings_router)
api_router.include_router(devices_router)
api_router.include_router(reports_router)
api_router.include_router(ws_router)
