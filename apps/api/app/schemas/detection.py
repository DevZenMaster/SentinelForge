"""Schemas for Detection Engine Evaluation and Rule Management."""

import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.alert import AlertResponse


class DetectionRuleResponse(BaseModel):
    """Catalog representation of a detection rule."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    rule_id: str
    version: int
    name: str
    description: str
    severity: str
    enabled: bool
    event_type: str
    threshold: int
    time_window_seconds: int
    conditions: dict[str, Any]


class DetectionEvaluationResponse(BaseModel):
    """Response returned when an event is evaluated against detection rules."""

    event_id: uuid.UUID = Field(..., description="Target security event identifier")
    alerts_triggered: int = Field(..., description="Count of alerts created or deduplicated")
    alerts: list[AlertResponse] = Field(..., description="Details of triggered alerts")
