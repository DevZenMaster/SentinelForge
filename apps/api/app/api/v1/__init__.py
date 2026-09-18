"""API v1 Router registry."""

from fastapi import APIRouter

from app.api.v1.alerts import router as alerts_router
from app.api.v1.audit import router as audit_router
from app.api.v1.auth import router as auth_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.detection_rules import router as detection_rules_router
from app.api.v1.events import router as events_router
from app.api.v1.health import router as health_router
from app.api.v1.incidents import router as incidents_router
from app.api.v1.indicators import router as indicators_router
from app.api.v1.integrations import router as integrations_router
from app.api.v1.investigations import router as investigations_router
from app.api.v1.notification_policies import router as notification_policies_router
from app.api.v1.notifications import router as notifications_router
from app.api.v1.reports import router as reports_router
from app.api.v1.users import router as users_router

api_v1_router = APIRouter()
api_v1_router.include_router(health_router)
api_v1_router.include_router(auth_router)
api_v1_router.include_router(events_router)
api_v1_router.include_router(alerts_router)
api_v1_router.include_router(incidents_router)
api_v1_router.include_router(indicators_router)
api_v1_router.include_router(investigations_router)
api_v1_router.include_router(detection_rules_router)
api_v1_router.include_router(dashboard_router)
api_v1_router.include_router(audit_router)
api_v1_router.include_router(reports_router)
api_v1_router.include_router(users_router)
api_v1_router.include_router(integrations_router)
api_v1_router.include_router(notification_policies_router)
api_v1_router.include_router(notifications_router)
