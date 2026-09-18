"""Report Export Serialization and Sanitization Engine (CWE-1236 Protection)."""

import csv
import io
import logging
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.reports import (
    AlertPerformanceReport,
    AnalystActivityReport,
    ComplianceEvidenceReport,
    DetectionReport,
    IncidentReport,
    OperationsSummaryReport,
    ReportingTimeRange,
    ReportType,
    SecurityAuditReport,
    SLAReport,
    ThreatIntelReport,
)
from app.services.auth import record_audit_log
from app.services.reports.analyst_activity import get_analyst_activity_report
from app.services.reports.audit import get_security_audit_report
from app.services.reports.base import sanitize_csv_value
from app.services.reports.compliance import get_compliance_report
from app.services.reports.detections import get_detection_report
from app.services.reports.incidents import get_incident_report
from app.services.reports.operations import get_alert_performance, get_operations_summary
from app.services.reports.sla import get_sla_report
from app.services.reports.threat_intel import get_threat_intel_report

logger = logging.getLogger(__name__)


def _write_csv_rows(rows: list[list[Any]]) -> str:
    """Serialize tabular rows into RFC-4180 CSV with CWE-1236 cell sanitization."""
    output = io.StringIO()
    # Write UTF-8 BOM so spreadsheet viewers render unicode correctly
    output.write("\ufeff")
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    for row in rows:
        sanitized = [sanitize_csv_value(cell) for cell in row]
        writer.writerow(sanitized)
    return output.getvalue()


def export_summary_csv(report: OperationsSummaryReport) -> str:
    rows: list[list[Any]] = [
        ["METRIC", "VALUE"],
        ["Report Period Start", report.time_range.start_time.isoformat()],
        ["Report Period End", report.time_range.end_time.isoformat()],
        ["Total Alerts", report.total_alerts],
        ["Alerts - Critical", report.alerts_by_severity.get("CRITICAL", 0)],
        ["Alerts - High", report.alerts_by_severity.get("HIGH", 0)],
        ["Alerts - Medium", report.alerts_by_severity.get("MEDIUM", 0)],
        ["Alerts - Low", report.alerts_by_severity.get("LOW", 0)],
        ["Alerts - Info", report.alerts_by_severity.get("INFO", 0)],
        ["Status - Open", report.alerts_by_status.get("OPEN", 0)],
        ["Status - Acknowledged", report.alerts_by_status.get("ACKNOWLEDGED", 0)],
        ["Status - In Progress", report.alerts_by_status.get("IN_PROGRESS", 0)],
        ["Status - Suppressed", report.alerts_by_status.get("SUPPRESSED", 0)],
        ["Status - Resolved", report.alerts_by_status.get("RESOLVED", 0)],
        ["Status - Closed", report.alerts_by_status.get("CLOSED", 0)],
        ["Acknowledged Alerts", report.acknowledged_count],
        ["Unacknowledged Alerts", report.unacknowledged_count],
        ["Assigned Alerts", report.assigned_count],
        ["Unassigned Alerts", report.unassigned_count],
        ["Suppressed Alerts", report.suppressed_count],
        ["Resolved Alerts", report.resolved_count],
        ["Closed Alerts", report.closed_count],
        ["Open Incident Cases", report.open_incident_cases],
        ["Active Detection Rules", report.total_active_rules],
        ["Active Threat Indicators", report.total_active_indicators],
        ["Generated At", report.generated_at.isoformat()],
    ]
    return _write_csv_rows(rows)


def export_alerts_csv(report: AlertPerformanceReport) -> str:
    lifecycle = report.lifecycle
    rows: list[list[Any]] = [
        ["METRIC", "SAMPLE COUNT", "MEAN SECONDS", "MEDIAN SECONDS", "MIN SECONDS", "MAX SECONDS"],
        [
            "Time to Acknowledge",
            lifecycle.time_to_acknowledge.sample_count,
            lifecycle.time_to_acknowledge.mean_seconds,
            lifecycle.time_to_acknowledge.median_seconds,
            lifecycle.time_to_acknowledge.min_seconds,
            lifecycle.time_to_acknowledge.max_seconds,
        ],
        [
            "Time to Assign",
            lifecycle.time_to_assign.sample_count,
            lifecycle.time_to_assign.mean_seconds,
            lifecycle.time_to_assign.median_seconds,
            lifecycle.time_to_assign.min_seconds,
            lifecycle.time_to_assign.max_seconds,
        ],
        [
            "Time to Resolve",
            lifecycle.time_to_resolve.sample_count,
            lifecycle.time_to_resolve.mean_seconds,
            lifecycle.time_to_resolve.median_seconds,
            lifecycle.time_to_resolve.min_seconds,
            lifecycle.time_to_resolve.max_seconds,
        ],
        [
            "Time to Close",
            lifecycle.time_to_close.sample_count,
            lifecycle.time_to_close.mean_seconds,
            lifecycle.time_to_close.median_seconds,
            lifecycle.time_to_close.min_seconds,
            lifecycle.time_to_close.max_seconds,
        ],
        [],
        ["TRIAGE BACKLOG METRIC", "COUNT"],
        ["Unacknowledged Alerts", lifecycle.unacknowledged_count],
        ["Unassigned Alerts", lifecycle.unassigned_count],
        ["Unresolved Alerts", lifecycle.unresolved_count],
        ["Unclosed Alerts", lifecycle.unclosed_count],
    ]
    return _write_csv_rows(rows)


def export_incidents_csv(report: IncidentReport) -> str:
    rows: list[list[Any]] = [
        ["METRIC", "VALUE"],
        ["Total Incidents", report.total_incidents],
        ["Severity - Critical", report.incidents_by_severity.get("CRITICAL", 0)],
        ["Severity - High", report.incidents_by_severity.get("HIGH", 0)],
        ["Severity - Medium", report.incidents_by_severity.get("MEDIUM", 0)],
        ["Severity - Low", report.incidents_by_severity.get("LOW", 0)],
        ["Status - Open", report.incidents_by_status.get("OPEN", 0)],
        ["Status - In Progress", report.incidents_by_status.get("IN_PROGRESS", 0)],
        ["Status - Resolved", report.incidents_by_status.get("RESOLVED", 0)],
        ["Status - Closed", report.incidents_by_status.get("CLOSED", 0)],
        [
            "Resolution - True Positive Malicious",
            report.resolution_breakdown.get("TRUE_POSITIVE_MALICIOUS", 0),
        ],
        [
            "Resolution - True Positive Benign",
            report.resolution_breakdown.get("TRUE_POSITIVE_BENIGN", 0),
        ],
        ["Resolution - False Positive", report.resolution_breakdown.get("FALSE_POSITIVE", 0)],
        ["Resolution - Duplicate", report.resolution_breakdown.get("DUPLICATE", 0)],
        ["Resolution - Other", report.resolution_breakdown.get("OTHER", 0)],
        ["Mean Resolution Seconds", report.duration_metrics.mean_seconds],
        ["Median Resolution Seconds", report.duration_metrics.median_seconds],
        ["Linked Alerts Count", report.linked_alerts_count],
        ["Generated At", report.generated_at.isoformat()],
    ]
    return _write_csv_rows(rows)


def export_detections_csv(report: DetectionReport) -> str:
    rows: list[list[Any]] = [
        [
            "RULE ID",
            "RULE NAME",
            "VERSION",
            "CURRENT STATUS",
            "ALERT COUNT",
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
        ]
    ]
    for item in report.rule_effectiveness:
        rows.append(
            [
                item.rule_id,
                item.rule_name,
                item.rule_version,
                item.current_status,
                item.alert_count,
                item.severity_breakdown.get("CRITICAL", 0),
                item.severity_breakdown.get("HIGH", 0),
                item.severity_breakdown.get("MEDIUM", 0),
                item.severity_breakdown.get("LOW", 0),
                item.severity_breakdown.get("INFO", 0),
            ]
        )
    return _write_csv_rows(rows)


def export_sla_csv(report: SLAReport) -> str:
    rows: list[list[Any]] = [
        ["SUMMARY METRIC", "VALUE"],
        ["SLA Breached Count", report.sla_breached_count],
        ["Applicable Alerts (Denominator)", report.applicable_alerts],
        ["Breach Rate (%)", report.breach_rate_percentage],
        [],
        [
            "ALERT ID",
            "TITLE",
            "SEVERITY",
            "CREATED AT",
            "ACKNOWLEDGED AT",
            "TRIAGE DELAY (SECONDS)",
            "ASSIGNED TO",
        ],
    ]
    for item in report.breached_alerts:
        rows.append(
            [
                item.alert_id,
                item.title,
                item.severity,
                item.created_at.isoformat() if item.created_at else "",
                item.acknowledged_at.isoformat() if item.acknowledged_at else "",
                item.triage_delay_seconds,
                item.assigned_to or "Unassigned",
            ]
        )
    return _write_csv_rows(rows)


def export_threat_intel_csv(report: ThreatIntelReport) -> str:
    rows: list[list[Any]] = [
        ["METRIC", "VALUE"],
        ["Total Indicators", report.total_indicators],
        ["Total Sightings In Period", report.total_sightings_in_period],
        [],
        ["INDICATOR TYPE", "COUNT"],
    ]
    for ioc_type, count in report.indicators_by_type.items():
        rows.append([ioc_type, count])

    rows.append([])
    rows.append(["INDICATOR STATUS", "COUNT"])
    for ioc_status, count in report.indicators_by_status.items():
        rows.append([ioc_status, count])

    return _write_csv_rows(rows)


def export_analyst_activity_csv(report: AnalystActivityReport) -> str:
    rows: list[list[Any]] = [
        ["NOTICE", report.disclaimer],
        [],
        [
            "USER ID",
            "USERNAME",
            "ALERTS ACKNOWLEDGED",
            "ALERTS ASSIGNED",
            "ALERTS RESOLVED",
            "NOTES CREATED",
            "INCIDENTS UPDATED",
            "TOTAL ACTIONS",
        ],
    ]
    for analyst in report.analysts:
        rows.append(
            [
                analyst.user_id,
                analyst.username,
                analyst.alerts_acknowledged,
                analyst.alerts_assigned,
                analyst.alerts_resolved,
                analyst.triage_notes_created,
                analyst.incidents_updated,
                analyst.total_recorded_actions,
            ]
        )
    return _write_csv_rows(rows)


def export_audit_csv(report: SecurityAuditReport) -> str:
    rows: list[list[Any]] = [
        ["AUDIT SUMMARY METRIC", "COUNT"],
        ["Total Audit Events", report.total_audit_events],
        ["Login Successes", report.login_success_count],
        ["Login Failures", report.login_failure_count],
        [],
        ["ACTION", "COUNT"],
    ]
    for action, count in report.action_distribution.items():
        rows.append([action, count])

    rows.append([])
    rows.append(["RESOURCE TYPE", "COUNT"])
    for res_type, count in report.resource_type_breakdown.items():
        rows.append([res_type, count])

    return _write_csv_rows(rows)


def export_compliance_csv(report: ComplianceEvidenceReport) -> str:
    rows: list[list[Any]] = [
        ["DISCLAIMER", report.disclaimer],
        [],
        [
            "CONTROL ID",
            "CONTROL NAME",
            "DESCRIPTION",
            "EVIDENCE SOURCE",
            "EVIDENCE PERIOD",
            "EVIDENCE COUNT",
            "STATUS",
        ],
    ]
    for c in report.controls:
        rows.append(
            [
                c.control_id,
                c.control_name,
                c.description,
                c.evidence_source,
                c.evidence_period,
                c.evidence_count,
                c.status.value,
            ]
        )
    return _write_csv_rows(rows)


async def generate_report_export(
    db: AsyncSession,
    report_type: ReportType,
    time_range: ReportingTimeRange,
    export_format: str,
    actor_user_id: uuid.UUID | None,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, str, str]:
    """Generate export content, filename, and content-type, logging an audit trail."""
    # 1. Fetch data model based on report_type
    report_model: Any
    if report_type == ReportType.SUMMARY:
        report_model = await get_operations_summary(db, time_range)
    elif report_type == ReportType.ALERTS:
        report_model = await get_alert_performance(db, time_range)
    elif report_type == ReportType.INCIDENTS:
        report_model = await get_incident_report(db, time_range)
    elif report_type == ReportType.DETECTIONS:
        report_model = await get_detection_report(db, time_range)
    elif report_type == ReportType.SLA:
        report_model = await get_sla_report(db, time_range)
    elif report_type == ReportType.THREAT_INTELLIGENCE:
        report_model = await get_threat_intel_report(db, time_range)
    elif report_type == ReportType.ANALYST_ACTIVITY:
        report_model = await get_analyst_activity_report(db, time_range)
    elif report_type == ReportType.AUDIT:
        report_model = await get_security_audit_report(db, time_range)
    elif report_type == ReportType.COMPLIANCE:
        report_model = await get_compliance_report(db, time_range)
    else:
        raise ValueError(f"Unsupported report type: {report_type}")

    # 2. Format content
    start_str = time_range.start_time.strftime("%Y%m%d")
    end_str = time_range.end_time.strftime("%Y%m%d")
    clean_type = report_type.value.replace("_", "-")

    if export_format == "csv":
        if report_type == ReportType.SUMMARY:
            content = export_summary_csv(report_model)
        elif report_type == ReportType.ALERTS:
            content = export_alerts_csv(report_model)
        elif report_type == ReportType.INCIDENTS:
            content = export_incidents_csv(report_model)
        elif report_type == ReportType.DETECTIONS:
            content = export_detections_csv(report_model)
        elif report_type == ReportType.SLA:
            content = export_sla_csv(report_model)
        elif report_type == ReportType.THREAT_INTELLIGENCE:
            content = export_threat_intel_csv(report_model)
        elif report_type == ReportType.ANALYST_ACTIVITY:
            content = export_analyst_activity_csv(report_model)
        elif report_type == ReportType.AUDIT:
            content = export_audit_csv(report_model)
        elif report_type == ReportType.COMPLIANCE:
            content = export_compliance_csv(report_model)
        else:
            content = ""

        media_type = "text/csv; charset=utf-8"
        filename = f"sentinelforge-{clean_type}-{start_str}-{end_str}.csv"
    else:
        # JSON export
        content = report_model.model_dump_json(indent=2)
        media_type = "application/json"
        filename = f"sentinelforge-{clean_type}-{start_str}-{end_str}.json"

    # 3. Immutable Security Audit Logging
    await record_audit_log(
        db=db,
        action="REPORT_EXPORTED",
        actor_user_id=actor_user_id,
        resource_type="report",
        resource_id=report_type.value,
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
        new_value={
            "report_type": report_type.value,
            "format": export_format,
            "start_time": time_range.start_time.isoformat(),
            "end_time": time_range.end_time.isoformat(),
            "filename": filename,
        },
    )

    try:
        from app.services.notifications import emit_notification_event

        await emit_notification_event(
            db=db,
            event_type="REPORT_EXPORTED",
            source_resource_type="report",
            source_resource_id=report_type.value,
            payload_data={
                "report_type": report_type.value,
                "export_format": export_format,
                "filename": filename,
            },
            correlation_id=request_id,
        )
    except Exception:
        logger.warning("Failed to emit REPORT_EXPORTED notification event", exc_info=True)

    return content, media_type, filename
