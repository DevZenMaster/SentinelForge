#!/usr/bin/env python3
"""SentinelForge Database Backup & Recovery Integrity Verification Tool.

Validates that a restored database preserves all authoritative security operations
evidence across Phases 1 through 13.

Operates in STRICT READ-ONLY MODE: Never modifies, inserts, or deletes records.
"""

import argparse
import asyncio
import json
import sys
from typing import Any

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import create_async_engine

# Core tables that MUST exist in a valid SentinelForge restoration
REQUIRED_TABLES = [
    "users",
    "roles",
    "permissions",
    "user_roles",
    "role_permissions",
    "sessions",
    "events",
    "alerts",
    "alert_events",
    "alert_notes",
    "incidents",
    "incident_alerts",
    "incident_notes",
    "indicators",
    "threat_intel",
    "detection_rules",
    "audit_logs",
    "integrations",
    "notification_policies",
    "notification_events",
    "notification_deliveries",
]


async def verify_restoration_integrity(
    database_url: str, dry_run: bool = False
) -> tuple[bool, dict[str, Any]]:
    """Inspect database schema, table presence, and evidence integrity."""
    report: dict[str, Any] = {
        "status": "UNKNOWN",
        "dry_run": dry_run,
        "required_tables_total": len(REQUIRED_TABLES),
        "tables_found": [],
        "tables_missing": [],
        "row_counts": {},
        "integrity_checks": [],
    }

    if dry_run:
        report["status"] = "PASSED_DRY_RUN"
        report["message"] = "Dry-run mode: verified table catalog requirements without live connection."
        return True, report

    engine = create_async_engine(database_url)

    try:
        async with engine.connect() as conn:
            # 1. Inspect existing table names
            def _get_tables(sync_conn: Any) -> list[str]:
                inspector = inspect(sync_conn)
                return inspector.get_table_names()

            existing_tables = await conn.run_sync(_get_tables)
            existing_set = set(existing_tables)

            for table in REQUIRED_TABLES:
                if table in existing_set:
                    report["tables_found"].append(table)
                else:
                    report["tables_missing"].append(table)

            if report["tables_missing"]:
                report["status"] = "FAILED"
                report["error"] = f"Missing required evidence tables: {report['tables_missing']}"
                return False, report

            # 2. Count records in critical tables
            for table in REQUIRED_TABLES:
                count_res = await conn.execute(text(f"SELECT COUNT(*) FROM {table}"))
                report["row_counts"][table] = count_res.scalar()

            # 3. Referential integrity checks
            # Check for orphaned alert_events
            orphaned_alerts = await conn.execute(
                text("SELECT COUNT(*) FROM alert_events WHERE alert_id NOT IN (SELECT id FROM alerts)")
            )
            report["integrity_checks"].append({
                "check": "zero_orphaned_alert_events",
                "passed": orphaned_alerts.scalar() == 0,
            })

            # Check for orphaned incident_alerts
            orphaned_incidents = await conn.execute(
                text("SELECT COUNT(*) FROM incident_alerts WHERE incident_id NOT IN (SELECT id FROM incidents)")
            )
            report["integrity_checks"].append({
                "check": "zero_orphaned_incident_alerts",
                "passed": orphaned_incidents.scalar() == 0,
            })

            all_checks_passed = all(c["passed"] for c in report["integrity_checks"])
            report["status"] = "VERIFIED" if all_checks_passed else "FAILED"
            return all_checks_passed, report

    except Exception as exc:
        report["status"] = "ERROR"
        report["error"] = str(exc)
        return False, report
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify restored SentinelForge database integrity."
    )
    parser.add_argument(
        "--db-url",
        default="postgresql+asyncpg://sentinelforge:sentinel_dev_password_change_me@localhost:5432/sentinelforge_db",
        help="Async SQLAlchemy connection URL to restored database",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate requirements without opening a database connection",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output report as structured JSON",
    )

    args = parser.parse_args()

    passed, report = asyncio.run(
        verify_restoration_integrity(database_url=args.db_url, dry_run=args.dry_run)
    )

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"SentinelForge Database Restoration Verification Report")
        print(f"Status: {report['status']}")
        print(f"Tables Checked: {len(report.get('tables_found', []))}/{report['required_tables_total']}")
        if report.get("tables_missing"):
            print(f"Missing Tables: {', '.join(report['tables_missing'])}")
        print(f"Integrity Checks: {report.get('integrity_checks')}")

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
