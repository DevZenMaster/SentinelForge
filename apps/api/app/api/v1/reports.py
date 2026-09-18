"""Security Reporting, Metrics & Compliance Operations API Router (Phase 12).

Provides bounded, auditable reporting endpoints for security operations,
alert performance, incident response, detection engineering, threat intelligence,
SLA compliance, analyst activity, and export pipelines.
"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission
from app.core.rbac import (
    PERMISSION_REPORTS_AUDIT,
    PERMISSION_REPORTS_EXPORT,
    PERMISSION_REPORTS_READ,
)
from app.db.session import get_db
from app.models.auth import User
from app.schemas.reports import (
    AlertPerformanceReport,
    AnalystActivityReport,
    ComplianceEvidenceReport,
    DetectionReport,
    IncidentReport,
    OperationsSummaryReport,
    ReportExportFormat,
    ReportingTimeRange,
    ReportType,
    SecurityAuditReport,
    SLAReport,
    ThreatIntelReport,
)
from app.schemas.response import APIResponse, ResponseMetadata
from app.services.auth import record_audit_log, resolve_user_capabilities
from app.services.reports import (
    generate_report_export,
    get_alert_performance,
    get_analyst_activity_report,
    get_compliance_report,
    get_detection_report,
    get_incident_report,
    get_operations_summary,
    get_security_audit_report,
    get_sla_report,
    get_threat_intel_report,
)

router = APIRouter(prefix="/reports", tags=["Reports"])


def _build_metadata(request: Request) -> ResponseMetadata:
    request_id = getattr(request.state, "request_id", "unknown")
    return ResponseMetadata(
        timestamp=datetime.now(UTC).isoformat(),
        request_id=str(request_id),
    )


def get_reporting_time_range(
    start_time: datetime | None = Query(
        default=None, description="UTC start boundary (ISO 8601). Defaults to 30 days prior."
    ),
    end_time: datetime | None = Query(
        default=None, description="UTC end boundary (ISO 8601). Defaults to now."
    ),
) -> ReportingTimeRange:
    """Dependency validating bounded temporal query parameters."""
    try:
        return ReportingTimeRange.model_validate({"start_time": start_time, "end_time": end_time})
    except (ValueError, ValidationError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "code": "VALIDATION_ERROR",
                "message": str(exc),
            },
        ) from exc


async def _audit_report_generation(
    db: AsyncSession,
    request: Request,
    user: User,
    report_type: str,
    time_range: ReportingTimeRange,
) -> None:
    """Record auditable evidence of report inspection without leaking data bodies."""
    req_id = getattr(request.state, "request_id", None)
    source_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    await record_audit_log(
        db=db,
        action="REPORT_GENERATED",
        actor_user_id=user.id,
        resource_type="report",
        resource_id=report_type,
        request_id=str(req_id) if req_id else None,
        source_ip=source_ip,
        user_agent=user_agent,
        new_value={
            "report_type": report_type,
            "start_time": time_range.start_time.isoformat(),
            "end_time": time_range.end_time.isoformat(),
        },
    )


@router.get(
    "/summary",
    response_model=APIResponse[OperationsSummaryReport],
    status_code=status.HTTP_200_OK,
    summary="Security Operations Summary Report",
)
async def get_summary_report(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_REPORTS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    time_range: Annotated[ReportingTimeRange, Depends(get_reporting_time_range)],
) -> APIResponse[OperationsSummaryReport]:
    report = await get_operations_summary(db, time_range)
    await _audit_report_generation(db, request, current_user, "summary", time_range)
    return APIResponse(data=report, meta=_build_metadata(request))


@router.get(
    "/alerts",
    response_model=APIResponse[AlertPerformanceReport],
    status_code=status.HTTP_200_OK,
    summary="Alert Performance and Lifecycle Report",
)
async def get_alerts_report(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_REPORTS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    time_range: Annotated[ReportingTimeRange, Depends(get_reporting_time_range)],
) -> APIResponse[AlertPerformanceReport]:
    report = await get_alert_performance(db, time_range)
    await _audit_report_generation(db, request, current_user, "alerts", time_range)
    return APIResponse(data=report, meta=_build_metadata(request))


@router.get(
    "/incidents",
    response_model=APIResponse[IncidentReport],
    status_code=status.HTTP_200_OK,
    summary="Incident Operations and Resolution Report",
)
async def get_incidents_report(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_REPORTS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    time_range: Annotated[ReportingTimeRange, Depends(get_reporting_time_range)],
) -> APIResponse[IncidentReport]:
    report = await get_incident_report(db, time_range)
    await _audit_report_generation(db, request, current_user, "incidents", time_range)
    return APIResponse(data=report, meta=_build_metadata(request))


@router.get(
    "/detections",
    response_model=APIResponse[DetectionReport],
    status_code=status.HTTP_200_OK,
    summary="Detection Rule Effectiveness Report",
)
async def get_detections_report(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_REPORTS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    time_range: Annotated[ReportingTimeRange, Depends(get_reporting_time_range)],
) -> APIResponse[DetectionReport]:
    report = await get_detection_report(db, time_range)
    await _audit_report_generation(db, request, current_user, "detections", time_range)
    return APIResponse(data=report, meta=_build_metadata(request))


@router.get(
    "/threat-intelligence",
    response_model=APIResponse[ThreatIntelReport],
    status_code=status.HTTP_200_OK,
    summary="Threat Intelligence Corpus and Sightings Report",
)
async def get_threat_intelligence_report(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_REPORTS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    time_range: Annotated[ReportingTimeRange, Depends(get_reporting_time_range)],
) -> APIResponse[ThreatIntelReport]:
    report = await get_threat_intel_report(db, time_range)
    await _audit_report_generation(db, request, current_user, "threat-intelligence", time_range)
    return APIResponse(data=report, meta=_build_metadata(request))


@router.get(
    "/analyst-activity",
    response_model=APIResponse[AnalystActivityReport],
    status_code=status.HTTP_200_OK,
    summary="Analyst Recorded Activity Report",
)
async def get_analyst_activity(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_REPORTS_AUDIT))],
    db: Annotated[AsyncSession, Depends(get_db)],
    time_range: Annotated[ReportingTimeRange, Depends(get_reporting_time_range)],
) -> APIResponse[AnalystActivityReport]:
    report = await get_analyst_activity_report(db, time_range)
    await _audit_report_generation(db, request, current_user, "analyst-activity", time_range)
    return APIResponse(data=report, meta=_build_metadata(request))


@router.get(
    "/sla",
    response_model=APIResponse[SLAReport],
    status_code=status.HTTP_200_OK,
    summary="SLA Triage Performance Report",
)
async def get_sla_performance_report(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_REPORTS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    time_range: Annotated[ReportingTimeRange, Depends(get_reporting_time_range)],
) -> APIResponse[SLAReport]:
    report = await get_sla_report(db, time_range)
    await _audit_report_generation(db, request, current_user, "sla", time_range)
    return APIResponse(data=report, meta=_build_metadata(request))


@router.get(
    "/audit",
    response_model=APIResponse[SecurityAuditReport],
    status_code=status.HTTP_200_OK,
    summary="Security Audit Log Metrics Report",
)
async def get_audit_summary_report(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_REPORTS_AUDIT))],
    db: Annotated[AsyncSession, Depends(get_db)],
    time_range: Annotated[ReportingTimeRange, Depends(get_reporting_time_range)],
) -> APIResponse[SecurityAuditReport]:
    report = await get_security_audit_report(db, time_range)
    await _audit_report_generation(db, request, current_user, "audit", time_range)
    return APIResponse(data=report, meta=_build_metadata(request))


@router.get(
    "/compliance",
    response_model=APIResponse[ComplianceEvidenceReport],
    status_code=status.HTTP_200_OK,
    summary="Objective Compliance Control Evidence Report",
)
async def get_compliance_evidence_report(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_REPORTS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    time_range: Annotated[ReportingTimeRange, Depends(get_reporting_time_range)],
) -> APIResponse[ComplianceEvidenceReport]:
    report = await get_compliance_report(db, time_range)
    await _audit_report_generation(db, request, current_user, "compliance", time_range)
    return APIResponse(data=report, meta=_build_metadata(request))


@router.get(
    "/export",
    status_code=status.HTTP_200_OK,
    summary="Export Security Report Data (CSV or JSON)",
)
async def export_report(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_REPORTS_EXPORT))],
    db: Annotated[AsyncSession, Depends(get_db)],
    time_range: Annotated[ReportingTimeRange, Depends(get_reporting_time_range)],
    type: ReportType = Query(..., description="Report category to export"),
    format: ReportExportFormat = Query(
        default=ReportExportFormat.CSV, description="Export format (csv or json)"
    ),
) -> Response:
    # If exporting audit or analyst-activity, enforce PERMISSION_REPORTS_AUDIT
    if type in (ReportType.AUDIT, ReportType.ANALYST_ACTIVITY):
        if not current_user.is_superuser:
            _, perms = await resolve_user_capabilities(db, current_user.id)
            if PERMISSION_REPORTS_AUDIT not in perms:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "code": "FORBIDDEN",
                        "message": (
                            f"Permission '{PERMISSION_REPORTS_AUDIT}' required to export "
                            f"{type.value} report."
                        ),
                    },
                )

    req_id = getattr(request.state, "request_id", None)
    source_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    content, media_type, filename = await generate_report_export(
        db=db,
        report_type=type,
        time_range=time_range,
        export_format=format.value,
        actor_user_id=current_user.id,
        request_id=str(req_id) if req_id else None,
        source_ip=source_ip,
        user_agent=user_agent,
    )

    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
        },
    )
