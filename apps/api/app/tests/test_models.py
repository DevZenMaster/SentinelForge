"""Tests verifying model metadata, constraints, relationships, and indexing definitions."""

from app.models import (
    Base,
)


def test_registered_tables_presence() -> None:
    """Verify all 13 primary entities exist within the metadata."""
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
        "incidents",
        "incident_alerts",
        "audit_logs",
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
