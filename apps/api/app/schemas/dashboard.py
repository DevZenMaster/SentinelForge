"""SOC Security Dashboard Telemetry Schemas."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.alert import AlertResponse


class SOCDashboardMetricsResponse(BaseModel):
    """Deterministic, aggregate SOC operational metrics."""

    model_config = ConfigDict(from_attributes=True)

    open_alerts_count: int = Field(..., description="Active alerts in OPEN or ACKNOWLEDGED status")
    critical_alerts_count: int = Field(..., description="Active alerts with CRITICAL severity")
    high_alerts_count: int = Field(..., description="Active alerts with HIGH severity")
    unacknowledged_alerts_count: int = Field(
        ..., description="Active alerts pending acknowledgement"
    )
    unassigned_alerts_count: int = Field(..., description="Active alerts without analyst")
    sla_breached_alerts_count: int = Field(..., description="Alerts untriaged >24 hours")
    open_incidents_count: int = Field(..., description="Incidents in OPEN or IN_PROGRESS state")
    active_rules_count: int = Field(..., description="Rules currently in ACTIVE state")
    total_indicators_count: int = Field(..., description="Threat intelligence indicators")
    recent_alerts: list[AlertResponse] = Field(
        default_factory=list, description="Latest priority security alerts"
    )
    recent_activity: list[dict[str, Any]] = Field(
        default_factory=list, description="Recent operational audit log entries"
    )
