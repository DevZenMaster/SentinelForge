"""Schemas for Security Reporting, Metrics & Compliance Operations (Phase 12).

Defines validation models, query boundaries, and structured contracts for
deterministic, auditable security reporting.
"""

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ReportExportFormat(StrEnum):
    """Supported export formats for security reports."""

    CSV = "csv"
    JSON = "json"


class ReportType(StrEnum):
    """Categorical report types available for generation and export."""

    SUMMARY = "summary"
    ALERTS = "alerts"
    INCIDENTS = "incidents"
    DETECTIONS = "detections"
    SLA = "sla"
    THREAT_INTELLIGENCE = "threat-intelligence"
    ANALYST_ACTIVITY = "analyst-activity"
    AUDIT = "audit"
    COMPLIANCE = "compliance"


class ComplianceStatus(StrEnum):
    """Status indicating availability of factual control evidence."""

    EVIDENCE_AVAILABLE = "EVIDENCE_AVAILABLE"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ReportingTimeRange(BaseModel):
    """Bounded, timezone-aware UTC query time range."""

    model_config = ConfigDict(extra="forbid")

    start_time: datetime
    end_time: datetime

    @model_validator(mode="before")
    @classmethod
    def validate_and_normalize(cls, data: Any) -> Any:
        if isinstance(data, dict):
            now = datetime.now(UTC)
            end_val = data.get("end_time")
            start_val = data.get("start_time")

            # Default end_time to now if missing or None
            if end_val is None:
                end_dt = now
            elif isinstance(end_val, datetime):
                end_dt = end_val if end_val.tzinfo is not None else end_val.replace(tzinfo=UTC)
            else:
                end_dt = datetime.fromisoformat(str(end_val))
                if end_dt.tzinfo is None:
                    end_dt = end_dt.replace(tzinfo=UTC)

            # Default start_time to 30 days prior to end_dt if missing or None
            if start_val is None:
                start_dt = end_dt - timedelta(days=30)
            elif isinstance(start_val, datetime):
                start_dt = (
                    start_val if start_val.tzinfo is not None else start_val.replace(tzinfo=UTC)
                )
            else:
                start_dt = datetime.fromisoformat(str(start_val))
                if start_dt.tzinfo is None:
                    start_dt = start_dt.replace(tzinfo=UTC)

            # Strict UTC normalization
            start_dt = start_dt.astimezone(UTC)
            end_dt = end_dt.astimezone(UTC)

            # Check 1: start < end
            if start_dt >= end_dt:
                raise ValueError("start_time must be strictly before end_time")

            # Check 2: Max 365 days
            max_span = timedelta(days=365)
            if (end_dt - start_dt) > max_span:
                raise ValueError("Reporting time range cannot exceed 365 days (1 year)")

            # Check 3: Future timestamp beyond 5-minute clock skew allowance
            skew_limit = now + timedelta(minutes=5)
            if end_dt > skew_limit:
                raise ValueError(
                    "end_time cannot be in the future (beyond 5-minute clock skew allowance)"
                )

            data["start_time"] = start_dt
            data["end_time"] = end_dt
        return data


class DurationMetric(BaseModel):
    """Summary duration metrics (seconds) calculated from completed lifecycle events."""

    model_config = ConfigDict(extra="forbid")

    mean_seconds: float | None = Field(
        default=None, description="Average duration in seconds (null if no completed samples)"
    )
    median_seconds: float | None = Field(
        default=None, description="Median duration in seconds (null if no completed samples)"
    )
    min_seconds: float | None = Field(
        default=None, description="Minimum duration in seconds (null if no completed samples)"
    )
    max_seconds: float | None = Field(
        default=None, description="Maximum duration in seconds (null if no completed samples)"
    )
    sample_count: int = Field(
        default=0, ge=0, description="Total count of completed lifecycle records in calculation"
    )


class AlertLifecycleMetrics(BaseModel):
    """Detailed time-to-action metrics for detection alert triage."""

    model_config = ConfigDict(extra="forbid")

    time_to_acknowledge: DurationMetric
    time_to_assign: DurationMetric
    time_to_resolve: DurationMetric
    time_to_close: DurationMetric
    unacknowledged_count: int = Field(ge=0, description="Alerts not yet acknowledged")
    unassigned_count: int = Field(ge=0, description="Alerts not currently assigned")
    unresolved_count: int = Field(ge=0, description="Alerts not yet resolved")
    unclosed_count: int = Field(ge=0, description="Alerts not yet closed")


class OperationsSummaryReport(BaseModel):
    """High-level security operations posture and volume summary."""

    model_config = ConfigDict(extra="forbid")

    time_range: ReportingTimeRange
    total_alerts: int = Field(ge=0)
    alerts_by_severity: dict[str, int]
    alerts_by_status: dict[str, int]
    acknowledged_count: int = Field(ge=0)
    unacknowledged_count: int = Field(ge=0)
    assigned_count: int = Field(ge=0)
    unassigned_count: int = Field(ge=0)
    suppressed_count: int = Field(ge=0)
    resolved_count: int = Field(ge=0)
    closed_count: int = Field(ge=0)
    open_incident_cases: int = Field(ge=0)
    total_active_rules: int = Field(ge=0)
    total_active_indicators: int = Field(ge=0)
    generated_at: datetime


class AlertPerformanceReport(BaseModel):
    """Detailed alert performance and operational lifecycle report."""

    model_config = ConfigDict(extra="forbid")

    time_range: ReportingTimeRange
    total_alerts: int = Field(ge=0)
    alerts_by_severity: dict[str, int]
    alerts_by_status: dict[str, int]
    lifecycle: AlertLifecycleMetrics
    generated_at: datetime


class IncidentReport(BaseModel):
    """Incident response, case volume, duration, and resolution analysis."""

    model_config = ConfigDict(extra="forbid")

    time_range: ReportingTimeRange
    total_incidents: int = Field(ge=0)
    incidents_by_severity: dict[str, int]
    incidents_by_status: dict[str, int]
    resolution_breakdown: dict[str, int]
    duration_metrics: DurationMetric
    linked_alerts_count: int = Field(ge=0)
    generated_at: datetime


class DetectionRuleEffectivenessItem(BaseModel):
    """Detection rule telemetry breakdown by exact rule ID and version."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    rule_name: str
    rule_version: int
    current_status: str
    alert_count: int = Field(ge=0)
    severity_breakdown: dict[str, int]


class DetectionReport(BaseModel):
    """Detection engineering catalog health and rule effectiveness."""

    model_config = ConfigDict(extra="forbid")

    time_range: ReportingTimeRange
    total_active_rules: int = Field(ge=0)
    total_draft_rules: int = Field(ge=0)
    total_disabled_rules: int = Field(ge=0)
    total_deprecated_rules: int = Field(ge=0)
    rule_effectiveness: list[DetectionRuleEffectivenessItem]
    generated_at: datetime


class SLABreachItem(BaseModel):
    """Individual SLA breach instance with factual delay attribution."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str
    title: str
    severity: str
    created_at: datetime
    acknowledged_at: datetime | None
    triage_delay_seconds: float = Field(ge=0)
    assigned_to: str | None


class SLAReport(BaseModel):
    """Triage SLA performance report with explicit population denominator."""

    model_config = ConfigDict(extra="forbid")

    time_range: ReportingTimeRange
    sla_breached_count: int = Field(ge=0)
    applicable_alerts: int = Field(
        ge=0, description="Total CRITICAL and HIGH alerts created in window (denominator)"
    )
    breach_rate_percentage: float = Field(
        ge=0.0, le=100.0, description="Breach rate as a percentage of applicable alerts"
    )
    severity_distribution: dict[str, int]
    breached_alerts: list[SLABreachItem]
    generated_at: datetime


class ThreatIntelReport(BaseModel):
    """Threat intelligence indicator corpus and telemetry sighting observations."""

    model_config = ConfigDict(extra="forbid")

    time_range: ReportingTimeRange
    indicators_by_type: dict[str, int]
    indicators_by_status: dict[str, int]
    total_indicators: int = Field(ge=0)
    total_sightings_in_period: int = Field(ge=0)
    generated_at: datetime


class AnalystActivityItem(BaseModel):
    """Recorded operational actions performed by an analyst during the window."""

    model_config = ConfigDict(extra="forbid")

    user_id: str
    username: str
    alerts_acknowledged: int = Field(ge=0)
    alerts_assigned: int = Field(ge=0)
    alerts_resolved: int = Field(ge=0)
    triage_notes_created: int = Field(ge=0)
    incidents_updated: int = Field(ge=0)
    total_recorded_actions: int = Field(ge=0)


class AnalystActivityReport(BaseModel):
    """Auditable log of analyst operations within the reporting window.

    Strictly reports recorded actions for operational capacity review;
    prohibits subjective productivity scoring or performance ranking.
    """

    model_config = ConfigDict(extra="forbid")

    time_range: ReportingTimeRange
    disclaimer: str = Field(
        default=(
            "Recorded operational activity metrics only. "
            "Not intended for individual productivity scoring, competence evaluation, "
            "or automated performance ranking."
        )
    )
    analysts: list[AnalystActivityItem]
    generated_at: datetime


class SecurityAuditReport(BaseModel):
    """Aggregated security audit logging telemetry and authentication activity."""

    model_config = ConfigDict(extra="forbid")

    time_range: ReportingTimeRange
    total_audit_events: int = Field(ge=0)
    action_distribution: dict[str, int]
    resource_type_breakdown: dict[str, int]
    login_success_count: int = Field(ge=0)
    login_failure_count: int = Field(ge=0)
    generated_at: datetime


class ComplianceControlEvidenceItem(BaseModel):
    """Verifiable, objective evidence observation for a security control."""

    model_config = ConfigDict(extra="forbid")

    control_id: str
    control_name: str
    description: str
    evidence_source: str
    evidence_period: str
    evidence_count: int = Field(ge=0)
    status: ComplianceStatus


class ComplianceEvidenceReport(BaseModel):
    """Objective security control evidence mapping report."""

    model_config = ConfigDict(extra="forbid")

    time_range: ReportingTimeRange
    disclaimer: str = Field(
        default=(
            "SentinelForge provides verifiable operational evidence for audit inspection. "
            "SentinelForge does not issue, validate, or certify compliance attestations "
            "(e.g. ISO 27001, SOC 2, PCI-DSS)."
        )
    )
    controls: list[ComplianceControlEvidenceItem]
    generated_at: datetime
