"""API v1 Router registry."""

from fastapi import APIRouter

from app.api.v1.alerts import router as alerts_router
from app.api.v1.auth import router as auth_router
from app.api.v1.events import router as events_router
from app.api.v1.health import router as health_router
from app.api.v1.incidents import router as incidents_router

api_v1_router = APIRouter()
api_v1_router.include_router(health_router)
api_v1_router.include_router(auth_router)
api_v1_router.include_router(events_router)
api_v1_router.include_router(alerts_router)
api_v1_router.include_router(incidents_router)
