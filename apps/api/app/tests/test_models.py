"""Tests verifying model metadata, constraints, relationships, and indexing definitions."""

from app.models import (
    Base,
)


def test_registered_tables_presence() -> None:
    """Verify all 18 primary entities exist within the metadata."""
    expected_tables = {
        "users",
        "roles",
        "permissions",
        "user_roles",
        "role_permissions",
        "sessions",
        "events",
        "detection_rules",
        "alerts",
        "alert_events",
        "alert_notes",
        "incidents",
        "incident_alerts",
        "incident_events",
        "incident_notes",
        "audit_logs",
        "indicators",
        "indicator_events",
        "threat_intelligence",
        "integrations",
        "notification_policies",
        "notification_events",
        "notification_deliveries",
    }
    actual_tables = set(Base.metadata.tables.keys())
    assert expected_tables == actual_tables


def test_user_model_constraints() -> None:
    """Verify User constraints and indexes."""
    table = Base.metadata.tables["users"]
    assert table.c.username.unique or any(
        idx.unique and "username" in [col.name for col in idx.columns] for idx in table.indexes
    )
    assert table.c.email.unique or any(
        idx.unique and "email" in [col.name for col in idx.columns] for idx in table.indexes
    )
    assert not table.c.hashed_password.nullable


def test_event_model_compound_indexes() -> None:
    """Verify sliding window compound indexes on Event table."""
    table = Base.metadata.tables["events"]
    index_column_sets = [[col.name for col in idx.columns] for idx in table.indexes]

    assert ["source_ip", "timestamp"] in index_column_sets
    assert ["destination_ip", "timestamp"] in index_column_sets
    assert ["username", "timestamp"] in index_column_sets
    assert ["event_type", "timestamp"] in index_column_sets
    assert ["action", "timestamp"] in index_column_sets


def test_detection_rule_versioning_unique_constraint() -> None:
    """Verify DetectionRule enforces composite unique constraint on (rule_id, version)."""
    table = Base.metadata.tables["detection_rules"]
    unique_constraints = [
        [col.name for col in uq.columns] for uq in table.constraints if hasattr(uq, "columns")
    ]
    assert ["rule_id", "version"] in unique_constraints


def test_alert_events_foreign_key_actions() -> None:
    """Verify AlertEvent foreign key deletion behaviors (CASCADE on alert, RESTRICT on event)."""
    table = Base.metadata.tables["alert_events"]
    fk_map = {fk.parent.name: fk for fk in table.foreign_keys}

    assert fk_map["alert_id"].ondelete == "CASCADE"
    assert fk_map["event_id"].ondelete == "RESTRICT"


def test_incident_alerts_unique_constraint() -> None:
    """Verify IncidentAlert ensures an alert is not duplicated inside the same incident."""
    table = Base.metadata.tables["incident_alerts"]
    unique_constraints = [
        [col.name for col in uq.columns] for uq in table.constraints if hasattr(uq, "columns")
    ]
    assert ["incident_id", "alert_id"] in unique_constraints


def test_audit_log_indexes() -> None:
    """Verify AuditLog actor and resource composite timestamp indexes."""
    table = Base.metadata.tables["audit_logs"]
    index_column_sets = [[col.name for col in idx.columns] for idx in table.indexes]

    assert ["actor_user_id", "timestamp"] in index_column_sets
    assert ["resource_type", "resource_id", "timestamp"] in index_column_sets


def test_session_model_token_hash_constraint() -> None:
    """Verify Session table uses session_token_hash (SHA-256) instead of raw token."""
    table = Base.metadata.tables["sessions"]
    assert "session_token_hash" in table.c
    assert "session_token" not in table.c
    assert getattr(table.c.session_token_hash.type, "length", None) == 64
    assert table.c.session_token_hash.unique or any(
        idx.unique and "session_token_hash" in [col.name for col in idx.columns]
        for idx in table.indexes
    )


def test_event_model_external_event_id_constraint() -> None:
    """Verify Event table metadata defines external_event_id with unique constraint."""
    table = Base.metadata.tables["events"]
    assert "external_event_id" in table.c
    assert getattr(table.c.external_event_id.type, "length", None) == 128
    assert table.c.external_event_id.unique or any(
        idx.unique and "external_event_id" in [col.name for col in idx.columns]
        for idx in table.indexes
    )


def test_event_model_normalization_fields_and_indexes() -> None:
    """Verify Event table metadata defines all Phase 4 canonical fields and indexes."""
    table = Base.metadata.tables["events"]

    # Canonical & tracking columns presence
    expected_columns = [
        "source_port",
        "outcome",
        "normalization_status",
        "parser_name",
        "parser_version",
        "normalization_version",
        "normalized_at",
        "normalization_errors",
        "attributes",
    ]
    for col in expected_columns:
        assert col in table.c, f"Column '{col}' missing from events table"

    # Compound index check
    index_column_sets = [[c.name for c in idx.columns] for idx in table.indexes]
    assert ["event_type", "action", "timestamp"] in index_column_sets
    assert ["outcome"] in index_column_sets
    assert ["normalization_status"] in index_column_sets


def test_alert_model_dedup_and_evidence_fields() -> None:
    """Verify Alert table defines dedup, correlation, evidence fields and indexes."""
    table = Base.metadata.tables["alerts"]

    expected_columns = [
        "dedup_key",
        "correlation_key",
        "observed_count",
        "threshold",
        "evidence",
    ]
    for col in expected_columns:
        assert col in table.c, f"Column '{col}' missing from alerts table"
        assert not table.c[col].nullable, f"Column '{col}' should not be nullable"

    # Unique constraint on dedup_key
    unique_constraints = [
        [col.name for col in uq.columns] for uq in table.constraints if hasattr(uq, "columns")
    ]
    assert ["dedup_key"] in unique_constraints

    # Compound and single indexes
    index_column_sets = [[c.name for c in idx.columns] for idx in table.indexes]
    assert ["dedup_key"] in index_column_sets
    assert ["correlation_key"] in index_column_sets
    assert ["rule_id", "created_at"] in index_column_sets
    assert ["correlation_key", "created_at"] in index_column_sets


def test_incident_model_fields_and_indexes() -> None:
    """Verify Incident table defines all Phase 6 lifecycle fields and indexes."""
    table = Base.metadata.tables["incidents"]

    expected_columns = [
        "incident_id",
        "title",
        "description",
        "severity",
        "priority",
        "status",
        "assigned_to_user_id",
        "created_by_user_id",
        "resolved_by_user_id",
        "resolved_at",
        "resolution_category",
        "resolution_notes",
        "closed_by_user_id",
        "closed_at",
    ]
    for col in expected_columns:
        assert col in table.c, f"Column '{col}' missing from incidents table"

    # Unique constraint or index on incident_id
    assert table.c.incident_id.unique or any(
        idx.unique and "incident_id" in [col.name for col in idx.columns] for idx in table.indexes
    )

    # Indexes on status, severity, priority
    index_column_sets = [[c.name for c in idx.columns] for idx in table.indexes]
    assert ["status", "created_at"] in index_column_sets
    assert ["assigned_to_user_id", "status"] in index_column_sets
    assert ["severity", "created_at"] in index_column_sets
    assert ["priority", "created_at"] in index_column_sets


def test_incident_events_foreign_key_actions() -> None:
    """Verify IncidentEvent FK deletion behaviors (CASCADE on incident, RESTRICT on event)."""
    table = Base.metadata.tables["incident_events"]
    fk_map = {fk.parent.name: fk for fk in table.foreign_keys}

    assert fk_map["incident_id"].ondelete == "CASCADE"
    assert fk_map["event_id"].ondelete == "RESTRICT"

    unique_constraints = [
        [col.name for col in uq.columns] for uq in table.constraints if hasattr(uq, "columns")
    ]
    assert ["incident_id", "event_id"] in unique_constraints


def test_incident_notes_foreign_key_actions_and_indexes() -> None:
    """Verify IncidentNote FK deletion behavior (CASCADE on incident, RESTRICT on author)."""
    table = Base.metadata.tables["incident_notes"]
    fk_map = {fk.parent.name: fk for fk in table.foreign_keys}

    assert fk_map["incident_id"].ondelete == "CASCADE"
    assert fk_map["author_user_id"].ondelete == "RESTRICT"

    index_column_sets = [[c.name for c in idx.columns] for idx in table.indexes]
    assert ["incident_id", "created_at"] in index_column_sets


def test_indicator_models_constraints_and_foreign_keys() -> None:
    """Verify Indicator, IndicatorEvent, and ThreatIntelligence constraints and FK actions."""
    # 1. indicators table
    ind_table = Base.metadata.tables["indicators"]
    ind_unique = [
        [col.name for col in uq.columns] for uq in ind_table.constraints if hasattr(uq, "columns")
    ]
    assert ["type", "normalized_value"] in ind_unique

    # 2. indicator_events table (RESTRICT on event_id for evidence preservation)
    ie_table = Base.metadata.tables["indicator_events"]
    ie_fk_map = {fk.parent.name: fk for fk in ie_table.foreign_keys}
    assert ie_fk_map["indicator_id"].ondelete == "CASCADE"
    assert ie_fk_map["event_id"].ondelete == "RESTRICT"

    ie_unique = [
        [col.name for col in uq.columns] for uq in ie_table.constraints if hasattr(uq, "columns")
    ]
    assert ["indicator_id", "event_id", "extracted_from_field"] in ie_unique

    # 3. threat_intelligence table
    ti_table = Base.metadata.tables["threat_intelligence"]
    ti_fk_map = {fk.parent.name: fk for fk in ti_table.foreign_keys}
    assert ti_fk_map["indicator_id"].ondelete == "CASCADE"

    ti_unique = [
        [col.name for col in uq.columns] for uq in ti_table.constraints if hasattr(uq, "columns")
    ]
    assert ["indicator_id", "source", "source_reference"] in ti_unique


def test_alert_model_operations_fields_and_notes_table() -> None:
    """Verify Alert operational triage fields and alert_notes table constraints."""
    alerts_table = Base.metadata.tables["alerts"]
    assert "assignee_id" in alerts_table.c
    assert "acknowledged_by_id" in alerts_table.c
    assert "resolved_by_id" in alerts_table.c
    assert "closed_by_id" in alerts_table.c
    assert "suppressed_by_id" in alerts_table.c
    assert "suppression_reason" in alerts_table.c
    assert "suppressed_until" in alerts_table.c
    assert "version" in alerts_table.c

    notes_table = Base.metadata.tables["alert_notes"]
    assert not notes_table.c.content.nullable
    assert not notes_table.c.alert_id.nullable
    assert not notes_table.c.author_user_id.nullable
    notes_fk_map = {fk.parent.name: fk for fk in notes_table.foreign_keys}
    assert notes_fk_map["alert_id"].ondelete == "CASCADE"
    assert notes_fk_map["author_user_id"].ondelete == "RESTRICT"
