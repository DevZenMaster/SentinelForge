"""Detection Engine Core.

Coordinates:
- Dynamic rule dispatch based on canonical event type
- Isolated fault-tolerant rule execution
- Deterministic deduplication with database constraint backing
- Transactional alert creation and evidence association (AlertEvent)
- Strict raw payload immutability preservation
"""

import logging
import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.metrics import system_metrics
from app.detection.base import BaseDetectionRule
from app.detection.configurable import ConfigurableDetectionRule
from app.detection.models import DetectionContext, DetectionResult
from app.detection.registry import RuleRegistry, default_rule_registry
from app.detection.rules import (
    Rule001BruteForceLogin,
    Rule002AccountSpray,
    Rule003SuspiciousLoginFollowingFailures,
    Rule004HttpAuthAbuse,
    Rule005PortScan,
)
from app.models.alert import Alert, AlertEvent
from app.models.detection import DetectionRule
from app.models.event import Event
from app.services.notifications import emit_notification_event

logger = logging.getLogger("sentinelforge.detection")


def build_rule_from_model(model: DetectionRule) -> BaseDetectionRule:
    """Instantiate appropriate rule instance from persistent DetectionRule model."""
    rule_cls_map: dict[str, type[BaseDetectionRule]] = {
        "RULE-001": Rule001BruteForceLogin,
        "RULE-002": Rule002AccountSpray,
        "RULE-003": Rule003SuspiciousLoginFollowingFailures,
        "RULE-004": Rule004HttpAuthAbuse,
        "RULE-005": Rule005PortScan,
    }
    cls = rule_cls_map.get(model.rule_id)
    if cls is not None:
        return cls(
            rule_id=model.rule_id,
            version=model.version,
            name=model.name,
            description=model.description,
            severity=model.severity,
            event_type=model.event_type,
            threshold=model.threshold,
            time_window_seconds=model.time_window_seconds,
        )
    return ConfigurableDetectionRule(
        rule_id=model.rule_id,
        version=model.version,
        name=model.name,
        description=model.description,
        severity=model.severity,
        event_type=model.event_type,
        threshold=model.threshold,
        time_window_seconds=model.time_window_seconds,
        conditions=model.conditions,
    )


class DetectionEngine:
    """Core engine evaluating canonical events against registered detection rules."""

    def __init__(self, registry: RuleRegistry | None = None) -> None:
        self.registry = registry or default_rule_registry
        self._custom_registry = registry is not None

    async def get_active_rules_for_event(
        self, db: AsyncSession, event_type: str
    ) -> list[BaseDetectionRule]:
        """Fetch active detection rules for the target event type.

        If a custom registry was explicitly passed to the engine, evaluates rules from it.
        Otherwise, inspects the database: only rules with status == 'ACTIVE' execute.
        If the database is unseeded (0 rules in table), falls back to the default registry.
        """
        if self._custom_registry:
            return self.registry.get_rules_for_event(event_type)

        stmt = select(DetectionRule).where(
            DetectionRule.status == "ACTIVE",
            DetectionRule.event_type == event_type,
        )
        active_models = (await db.execute(stmt)).scalars().all()
        if active_models:
            return [build_rule_from_model(m) for m in active_models]

        # Check whether table is populated or empty
        count_stmt = select(func.count(DetectionRule.id))
        total_rules = (await db.execute(count_stmt)).scalar() or 0
        if total_rules > 0:
            # Table contains rules, but none are ACTIVE for this event_type
            return []

        # Empty table fallback for unseeded test fixtures
        return self.registry.get_rules_for_event(event_type)

    async def evaluate_event(
        self,
        db: AsyncSession,
        event: Event,
    ) -> list[Alert]:
        """Evaluate a canonical event against all applicable rules.

        Fault-isolated: A failure in one rule evaluation never prevents other
        rules from executing, nor does it abort event persistence.

        Returns:
            list[Alert]: Created or deduplicated/updated alerts.
        """
        rules = await self.get_active_rules_for_event(db, event.event_type)
        if not rules:
            return []

        context = DetectionContext(event=event, db=db)
        generated_alerts: list[Alert] = []

        for rule in rules:
            try:
                result = await rule.evaluate(context)
                if result is not None and result.matched:
                    alert = await self._persist_detection_result(db, result, event)
                    if alert is not None:
                        generated_alerts.append(alert)
            except Exception as exc:
                # Fault isolation: log exception with structured context and continue
                logger.exception(
                    "Rule evaluation encountered unhandled error",
                    extra={
                        "rule_id": rule.rule_id,
                        "event_id": str(event.id),
                        "event_type": event.event_type,
                        "error": str(exc),
                    },
                )

        return generated_alerts

    async def evaluate_rule_explicit(
        self,
        db: AsyncSession,
        event: Event,
        rule_id: str,
    ) -> DetectionResult | None:
        """Evaluate a single rule by ID against an event without persisting alerts."""
        if self._custom_registry:
            rule: BaseDetectionRule | None = self.registry.get_rule(rule_id)
        else:
            stmt = select(DetectionRule).where(
                DetectionRule.rule_id == rule_id,
                DetectionRule.status == "ACTIVE",
            )
            model = (await db.execute(stmt)).scalar_one_or_none()
            if model is not None:
                rule = build_rule_from_model(model)
            else:
                total = (await db.execute(select(func.count(DetectionRule.id)))).scalar() or 0
                if total > 0:
                    return None
                rule = self.registry.get_rule(rule_id)

        if not rule:
            return None
        context = DetectionContext(event=event, db=db)
        return await rule.evaluate(context)

    async def _persist_detection_result(
        self,
        db: AsyncSession,
        result: DetectionResult,
        triggering_event: Event,
    ) -> Alert | None:
        """Persist or update an Alert with evidence links and strict deduplication."""
        # 1. Check for existing alert matching deterministic dedup_key
        stmt = select(Alert).where(Alert.dedup_key == result.dedup_key)
        existing_alert = (await db.execute(stmt)).scalar_one_or_none()

        if existing_alert is not None:
            # Deduplication: update metrics and temporal bounds
            existing_alert.observed_count = max(
                existing_alert.observed_count, result.observed_count
            )
            existing_alert.last_seen = max(existing_alert.last_seen, result.last_seen)
            existing_alert.evidence = result.evidence

            await self._link_contributing_events(
                db, existing_alert.id, result.contributing_event_ids
            )
            await db.commit()
            await db.refresh(existing_alert)

            logger.info(
                "Alert deduplicated and updated",
                extra={
                    "alert_id": str(existing_alert.id),
                    "rule_id": existing_alert.rule_id,
                    "dedup_key": existing_alert.dedup_key,
                    "observed_count": existing_alert.observed_count,
                },
            )
            return existing_alert

        # 2. Instantiate new alert
        alert = Alert(
            id=uuid.uuid4(),
            rule_id=result.rule_id,
            rule_version=result.rule_version,
            title=result.title,
            description=result.description,
            severity=result.severity,
            status="OPEN",
            dedup_key=result.dedup_key,
            correlation_key=result.correlation_key,
            observed_count=result.observed_count,
            threshold=result.threshold,
            evidence=result.evidence,
            source_ip=result.source_ip,
            username=result.username,
            first_seen=result.first_seen,
            last_seen=result.last_seen,
        )

        # 3. Save with nested transaction protecting against concurrent insertion race
        try:
            async with db.begin_nested():
                db.add(alert)
                await db.flush()
                await self._link_contributing_events(db, alert.id, result.contributing_event_ids)
            await db.commit()
            await db.refresh(alert)

            system_metrics.record_alert_event("created")
            system_metrics.record_detection_event(matched=1)

            try:
                await emit_notification_event(
                    db=db,
                    event_type="ALERT_CREATED",
                    source_resource_type="alert",
                    source_resource_id=str(alert.id),
                    payload_data={
                        "id": str(alert.id),
                        "title": alert.title,
                        "severity": alert.severity,
                        "status": alert.status,
                        "rule_id": alert.rule_id,
                        "rule_version": alert.rule_version,
                        "source_ip": alert.source_ip,
                        "username": alert.username,
                    },
                    correlation_id=alert.correlation_key,
                )
            except Exception:
                logger.warning("Failed to emit ALERT_CREATED notification event", exc_info=True)

            logger.info(
                "Alert generated and persisted",
                extra={
                    "alert_id": str(alert.id),
                    "rule_id": alert.rule_id,
                    "severity": alert.severity,
                    "correlation_key": alert.correlation_key,
                    "dedup_key": alert.dedup_key,
                },
            )
            return alert

        except IntegrityError:
            # Raced with another worker on uq_alerts_dedup_key
            stmt = select(Alert).where(Alert.dedup_key == result.dedup_key)
            raced_alert = (await db.execute(stmt)).scalar_one_or_none()
            if raced_alert is not None:
                raced_alert.observed_count = max(raced_alert.observed_count, result.observed_count)
                raced_alert.last_seen = max(raced_alert.last_seen, result.last_seen)
                raced_alert.evidence = result.evidence
                await self._link_contributing_events(
                    db, raced_alert.id, result.contributing_event_ids
                )
                await db.commit()
                await db.refresh(raced_alert)
                return raced_alert
            raise

    async def _link_contributing_events(
        self,
        db: AsyncSession,
        alert_id: uuid.UUID,
        event_ids: Sequence[uuid.UUID],
    ) -> None:
        """Associate contributing events to the alert in alert_events join table."""
        for event_id in event_ids:
            # Check for existing association to satisfy uq_alert_events_alert_id_event_id
            stmt = select(AlertEvent).where(
                AlertEvent.alert_id == alert_id,
                AlertEvent.event_id == event_id,
            )
            exists = (await db.execute(stmt)).scalar_one_or_none()
            if exists is None:
                ae = AlertEvent(
                    id=uuid.uuid4(),
                    alert_id=alert_id,
                    event_id=event_id,
                )
                db.add(ae)
        await db.flush()


default_detection_engine = DetectionEngine()
