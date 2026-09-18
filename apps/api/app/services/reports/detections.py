"""Detection Engineering and Rule Effectiveness Reporting Service."""

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.detection import DetectionRule
from app.schemas.reports import (
    DetectionReport,
    DetectionRuleEffectivenessItem,
    ReportingTimeRange,
)

SEVERITY_KEYS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


async def get_detection_report(db: AsyncSession, time_range: ReportingTimeRange) -> DetectionReport:
    """Generate detection rule catalog health and rule effectiveness metrics."""
    # 1. Catalog status counts
    status_query = select(DetectionRule.status, func.count(DetectionRule.id)).group_by(
        DetectionRule.status
    )
    status_counts: dict[str, int] = {
        str(row[0]): int(row[1]) for row in (await db.execute(status_query)).all()
    }

    total_active = status_counts.get("ACTIVE", 0)
    total_draft = status_counts.get("DRAFT", 0)
    total_disabled = status_counts.get("DISABLED", 0)
    total_deprecated = status_counts.get("DEPRECATED", 0)

    # 2. Get all rules to resolve names and statuses
    rules_query = select(
        DetectionRule.rule_id,
        DetectionRule.version,
        DetectionRule.name,
        DetectionRule.status,
    )
    all_rules = (await db.execute(rules_query)).all()
    rule_lookup: dict[tuple[str, int], tuple[str, str]] = {
        (r.rule_id, r.version): (r.name, r.status) for r in all_rules
    }
    # Fallback by rule_id alone for the latest name/status
    rule_id_fallback: dict[str, tuple[str, str]] = {
        r.rule_id: (r.name, r.status) for r in all_rules
    }

    # 3. Alert distribution by exact (rule_id, rule_version) in the time window
    alert_query = (
        select(
            Alert.rule_id,
            Alert.rule_version,
            Alert.severity,
            func.count(Alert.id),
        )
        .where(
            Alert.created_at >= time_range.start_time,
            Alert.created_at <= time_range.end_time,
        )
        .group_by(Alert.rule_id, Alert.rule_version, Alert.severity)
    )
    alert_rows = (await db.execute(alert_query)).all()

    # Aggregate by (rule_id, rule_version)
    rule_activity: dict[tuple[str, int], dict[str, int]] = {}
    rule_severities: dict[tuple[str, int], dict[str, int]] = {}

    for r_id, r_ver, sev, count in alert_rows:
        key = (r_id, r_ver)
        if key not in rule_activity:
            rule_activity[key] = {"alert_count": 0}
            rule_severities[key] = {k: 0 for k in SEVERITY_KEYS}

        rule_activity[key]["alert_count"] += count
        norm_sev = sev.upper() if sev else "INFO"
        rule_severities[key][norm_sev] = rule_severities[key].get(norm_sev, 0) + count

    # Include all known active rules even if they fired 0 alerts
    for r in all_rules:
        if r.status == "ACTIVE":
            key = (r.rule_id, r.version)
            if key not in rule_activity:
                rule_activity[key] = {"alert_count": 0}
                rule_severities[key] = {k: 0 for k in SEVERITY_KEYS}

    # Build effectiveness items
    effectiveness_items: list[DetectionRuleEffectivenessItem] = []
    for (r_id, r_ver), meta in sorted(
        rule_activity.items(), key=lambda item: item[1]["alert_count"], reverse=True
    ):
        name, current_stat = rule_lookup.get(
            (r_id, r_ver), rule_id_fallback.get(r_id, (f"Rule {r_id}", "UNKNOWN"))
        )
        effectiveness_items.append(
            DetectionRuleEffectivenessItem(
                rule_id=r_id,
                rule_name=name,
                rule_version=r_ver,
                current_status=current_stat,
                alert_count=meta["alert_count"],
                severity_breakdown=rule_severities[(r_id, r_ver)],
            )
        )

    return DetectionReport(
        time_range=time_range,
        total_active_rules=total_active,
        total_draft_rules=total_draft,
        total_disabled_rules=total_disabled,
        total_deprecated_rules=total_deprecated,
        rule_effectiveness=effectiveness_items,
        generated_at=datetime.now(UTC),
    )
