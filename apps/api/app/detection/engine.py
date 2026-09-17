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

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.detection.models import DetectionContext, DetectionResult
from app.detection.registry import RuleRegistry, default_rule_registry
from app.models.alert import Alert, AlertEvent
from app.models.event import Event

logger = logging.getLogger("sentinelforge.detection")


class DetectionEngine:
    """Core engine evaluating canonical events against registered detection rules."""

    def __init__(self, registry: RuleRegistry | None = None) -> None:
        self.registry = registry or default_rule_registry

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
        rules = self.registry.get_rules_for_event(event.event_type)
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
