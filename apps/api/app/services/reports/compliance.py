"""Objective Compliance Control Evidence Mapping Service."""

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.audit import AuditLog
from app.models.detection import DetectionRule
from app.models.incident import Incident
from app.schemas.reports import (
    ComplianceControlEvidenceItem,
    ComplianceEvidenceReport,
    ComplianceStatus,
    ReportingTimeRange,
)


async def get_compliance_report(
    db: AsyncSession, time_range: ReportingTimeRange
) -> ComplianceEvidenceReport:
    """Evaluate observable security control evidence without subjective or artificial scoring.

    Provides verifiable factual counts directly tied to underlying database rows.
    """
    evidence_period = (
        f"{time_range.start_time.strftime('%Y-%m-%d %H:%M:%SZ')} to "
        f"{time_range.end_time.strftime('%Y-%m-%d %H:%M:%SZ')}"
    )

    # Control 1: Append-Only Security Audit Logging
    audit_count_stmt = select(func.count(AuditLog.id)).where(
        AuditLog.timestamp >= time_range.start_time,
        AuditLog.timestamp <= time_range.end_time,
    )
    audit_count = (await db.execute(audit_count_stmt)).scalar_one()

    # Control 2: Multi-Tier Authentication & RBAC
    auth_count_stmt = select(func.count(AuditLog.id)).where(
        AuditLog.action.in_(["LOGIN_SUCCESS", "SESSION_CREATED"]),
        AuditLog.timestamp >= time_range.start_time,
        AuditLog.timestamp <= time_range.end_time,
    )
    auth_count = (await db.execute(auth_count_stmt)).scalar_one()

    # Control 3: Detection Alert Triage Accountability
    alert_triage_stmt = select(func.count(Alert.id)).where(
        Alert.acknowledged_at.is_not(None),
        Alert.created_at >= time_range.start_time,
        Alert.created_at <= time_range.end_time,
    )
    alert_triage_count = (await db.execute(alert_triage_stmt)).scalar_one()

    # Control 4: Immutable Versioned Detection Engineering
    detection_rules_stmt = select(func.count(DetectionRule.id)).where(
        DetectionRule.status == "ACTIVE"
    )
    detection_rules_count = (await db.execute(detection_rules_stmt)).scalar_one()

    # Control 5: Incident Response Case Management
    incident_cases_stmt = select(func.count(Incident.id)).where(
        Incident.created_at >= time_range.start_time,
        Incident.created_at <= time_range.end_time,
    )
    incident_cases_count = (await db.execute(incident_cases_stmt)).scalar_one()

    controls = [
        ComplianceControlEvidenceItem(
            control_id="CTRL-AUD-01",
            control_name="Append-Only Security Audit Logging",
            description=(
                "Immutable audit trail capturing all operational actions and state mutations."
            ),
            evidence_source="audit_logs",
            evidence_period=evidence_period,
            evidence_count=audit_count,
            status=(
                ComplianceStatus.EVIDENCE_AVAILABLE
                if audit_count > 0
                else ComplianceStatus.EVIDENCE_MISSING
            ),
        ),
        ComplianceControlEvidenceItem(
            control_id="CTRL-AUTH-01",
            control_name="Multi-Tier Authentication & RBAC",
            description="Cryptographically secure authentication and role-based access control.",
            evidence_source="audit_logs (LOGIN_SUCCESS, SESSION_CREATED)",
            evidence_period=evidence_period,
            evidence_count=auth_count,
            status=(
                ComplianceStatus.EVIDENCE_AVAILABLE
                if auth_count > 0
                else ComplianceStatus.EVIDENCE_MISSING
            ),
        ),
        ComplianceControlEvidenceItem(
            control_id="CTRL-ALRT-01",
            control_name="Detection Alert Triage Accountability",
            description=(
                "Human-in-the-loop analyst acknowledgement and explicit ownership attribution."
            ),
            evidence_source="alerts (acknowledged_at is not null)",
            evidence_period=evidence_period,
            evidence_count=alert_triage_count,
            status=(
                ComplianceStatus.EVIDENCE_AVAILABLE
                if alert_triage_count > 0
                else ComplianceStatus.EVIDENCE_MISSING
            ),
        ),
        ComplianceControlEvidenceItem(
            control_id="CTRL-DET-01",
            control_name="Immutable Versioned Detection Engineering",
            description=(
                "Active detection rules deployed with strict schema validation and version"
                " tracking."
            ),
            evidence_source="detection_rules (status = 'ACTIVE')",
            evidence_period=evidence_period,
            evidence_count=detection_rules_count,
            status=(
                ComplianceStatus.EVIDENCE_AVAILABLE
                if detection_rules_count > 0
                else ComplianceStatus.EVIDENCE_MISSING
            ),
        ),
        ComplianceControlEvidenceItem(
            control_id="CTRL-INC-01",
            control_name="Incident Response Case Management",
            description=(
                "Formal investigation dossiers, evidence preservation, and documented resolution"
                " categories."
            ),
            evidence_source="incidents",
            evidence_period=evidence_period,
            evidence_count=incident_cases_count,
            status=(
                ComplianceStatus.EVIDENCE_AVAILABLE
                if incident_cases_count > 0
                else ComplianceStatus.EVIDENCE_MISSING
            ),
        ),
    ]

    return ComplianceEvidenceReport(
        time_range=time_range,
        disclaimer=(
            "SentinelForge provides verifiable operational evidence for audit inspection. "
            "SentinelForge does not issue, validate, or certify compliance attestations "
            "(e.g. ISO 27001, SOC 2, PCI-DSS)."
        ),
        controls=controls,
        generated_at=datetime.now(UTC),
    )
