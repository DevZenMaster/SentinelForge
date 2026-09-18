"""Notification Payload Templates and Data Minimization (Phase 13).

Extracts allowlisted fields only, strictly omitting passwords, session secrets,
tokens, internal IDs, and excessive personal data.
Provides HTML and plain-text formatters with strict entity escaping.
"""

import html
from datetime import datetime
from typing import Any


def format_webhook_payload(
    event_id: str,
    event_type: str,
    created_at: datetime,
    payload_version: int,
    source_resource_type: str,
    source_resource_id: str,
    payload_data: dict[str, Any],
    correlation_id: str | None = None,
) -> dict[str, Any]:
    """Construct sanitized, deterministic JSON payload for external webhooks."""
    clean_data: dict[str, Any] = {}

    # Extract allowlisted fields depending on source
    if source_resource_type == "alert":
        clean_data["alert"] = {
            "id": payload_data.get("id"),
            "title": payload_data.get("title"),
            "severity": payload_data.get("severity"),
            "status": payload_data.get("status"),
            "rule_id": payload_data.get("rule_id"),
            "rule_version": payload_data.get("rule_version"),
            "source_ip": payload_data.get("source_ip"),
            "username": payload_data.get("username"),
            "created_at": payload_data.get("created_at"),
        }
    elif source_resource_type == "incident":
        clean_data["incident"] = {
            "id": payload_data.get("id"),
            "incident_id": payload_data.get("incident_id"),
            "title": payload_data.get("title"),
            "severity": payload_data.get("severity"),
            "priority": payload_data.get("priority"),
            "status": payload_data.get("status"),
            "created_at": payload_data.get("created_at"),
        }
    else:
        # Generic minimal payload (e.g. SLA breach, report export)
        allowed_keys = {
            "report_type",
            "export_format",
            "row_count",
            "sla_breach_count",
            "reason",
        }
        clean_data["metadata"] = {k: v for k, v in payload_data.items() if k in allowed_keys}

    return {
        "event_id": str(event_id),
        "event_type": event_type,
        "timestamp": created_at.isoformat(),
        "payload_version": payload_version,
        "source_resource_type": source_resource_type,
        "source_resource_id": str(source_resource_id),
        "correlation_id": correlation_id,
        "data": clean_data,
    }


def format_email_content(
    event_id: str,
    event_type: str,
    created_at: datetime,
    source_resource_type: str,
    source_resource_id: str,
    payload_data: dict[str, Any],
    base_url: str = "http://localhost:3000",
) -> tuple[str, str, str]:
    """Construct (subject, plain_text_body, html_body) for email delivery.

    All HTML variables are rigorously escaped against injection.
    """
    safe_event_type = html.escape(event_type)
    safe_id = html.escape(str(source_resource_id))
    safe_time = html.escape(created_at.isoformat())

    if source_resource_type == "alert":
        title = payload_data.get("title", "Security Alert")
        severity = payload_data.get("severity", "UNKNOWN")
        status = payload_data.get("status", "OPEN")
        link = f"{base_url}/alerts/{source_resource_id}"

        subject = f"[SentinelForge] {severity} Alert: {title} ({event_type})"
        plain = (
            f"SentinelForge Security Alert Notification\n\n"
            f"Event Type: {event_type}\n"
            f"Alert Title: {title}\n"
            f"Severity: {severity}\n"
            f"Status: {status}\n"
            f"Alert ID: {source_resource_id}\n"
            f"Timestamp: {created_at.isoformat()}\n\n"
            f"View Dossier: {link}\n"
        )
        safe_title = html.escape(str(title))
        safe_severity = html.escape(str(severity))
        safe_status = html.escape(str(status))
        safe_link = html.escape(link)

        html_body = (
            "<!DOCTYPE html>\n<html>\n"
            '<body style="font-family: sans-serif; background-color: #0f172a; '
            'color: #e2e8f0; padding: 20px;">\n'
            '  <div style="max-width: 600px; margin: 0 auto; background: #1e293b; '
            'border-radius: 8px; border: 1px solid #334155; padding: 24px;">\n'
            '    <h2 style="color: #38bdf8; margin-top: 0;">'
            "SentinelForge Security Notification</h2>\n"
            "    <p>An authoritative security event has occurred:</p>\n"
            '    <table style="width: 100%; border-collapse: collapse; margin: 16px 0;">\n'
            f'      <tr><td style="padding: 8px; color: #94a3b8;">Event Type:</td>'
            f'<td style="padding: 8px; font-weight: bold;">{safe_event_type}</td></tr>\n'
            f'      <tr><td style="padding: 8px; color: #94a3b8;">Alert Title:</td>'
            f'<td style="padding: 8px; font-weight: bold;">{safe_title}</td></tr>\n'
            f'      <tr><td style="padding: 8px; color: #94a3b8;">Severity:</td>'
            f'<td style="padding: 8px; font-weight: bold;">{safe_severity}</td></tr>\n'
            f'      <tr><td style="padding: 8px; color: #94a3b8;">Status:</td>'
            f'<td style="padding: 8px;">{safe_status}</td></tr>\n'
            f'      <tr><td style="padding: 8px; color: #94a3b8;">Alert ID:</td>'
            f'<td style="padding: 8px; font-family: monospace;">{safe_id}</td></tr>\n'
            f'      <tr><td style="padding: 8px; color: #94a3b8;">Timestamp:</td>'
            f'<td style="padding: 8px;">{safe_time}</td></tr>\n'
            "    </table>\n"
            '    <div style="margin-top: 24px;">\n'
            f'      <a href="{safe_link}" style="background: #2563eb; color: #ffffff; '
            "padding: 10px 20px; text-decoration: none; border-radius: 4px; "
            'display: inline-block;">Open Alert Dossier</a>\n'
            "    </div>\n"
            "  </div>\n"
            "</body>\n</html>"
        )
        return subject, plain, html_body

    if source_resource_type == "incident":
        inc_id = payload_data.get("incident_id", source_resource_id)
        title = payload_data.get("title", "Security Incident")
        severity = payload_data.get("severity", "UNKNOWN")
        status = payload_data.get("status", "OPEN")
        link = f"{base_url}/incidents/{source_resource_id}"

        subject = f"[SentinelForge] Incident {inc_id}: {title} ({event_type})"
        plain = (
            f"SentinelForge Incident Notification\n\n"
            f"Event Type: {event_type}\n"
            f"Incident: {inc_id} - {title}\n"
            f"Severity: {severity}\n"
            f"Status: {status}\n"
            f"Timestamp: {created_at.isoformat()}\n\n"
            f"View Case: {link}\n"
        )
        safe_inc_id = html.escape(str(inc_id))
        safe_title = html.escape(str(title))
        safe_severity = html.escape(str(severity))
        safe_status = html.escape(str(status))
        safe_link = html.escape(link)

        html_body = (
            "<!DOCTYPE html>\n<html>\n"
            '<body style="font-family: sans-serif; background-color: #0f172a; '
            'color: #e2e8f0; padding: 20px;">\n'
            '  <div style="max-width: 600px; margin: 0 auto; background: #1e293b; '
            'border-radius: 8px; border: 1px solid #334155; padding: 24px;">\n'
            '    <h2 style="color: #38bdf8; margin-top: 0;">'
            "SentinelForge Incident Notification</h2>\n"
            "    <p>An incident case update was recorded:</p>\n"
            '    <table style="width: 100%; border-collapse: collapse; margin: 16px 0;">\n'
            f'      <tr><td style="padding: 8px; color: #94a3b8;">Incident ID:</td>'
            f'<td style="padding: 8px; font-weight: bold; font-family: monospace;">'
            f"{safe_inc_id}</td></tr>\n"
            f'      <tr><td style="padding: 8px; color: #94a3b8;">Title:</td>'
            f'<td style="padding: 8px;">{safe_title}</td></tr>\n'
            f'      <tr><td style="padding: 8px; color: #94a3b8;">Severity:</td>'
            f'<td style="padding: 8px; font-weight: bold;">{safe_severity}</td></tr>\n'
            f'      <tr><td style="padding: 8px; color: #94a3b8;">Status:</td>'
            f'<td style="padding: 8px;">{safe_status}</td></tr>\n'
            f'      <tr><td style="padding: 8px; color: #94a3b8;">Timestamp:</td>'
            f'<td style="padding: 8px;">{safe_time}</td></tr>\n'
            "    </table>\n"
            '    <div style="margin-top: 24px;">\n'
            f'      <a href="{safe_link}" style="background: #2563eb; color: #ffffff; '
            "padding: 10px 20px; text-decoration: none; border-radius: 4px; "
            'display: inline-block;">Open Incident Case</a>\n'
            "    </div>\n"
            "  </div>\n"
            "</body>\n</html>"
        )
        return subject, plain, html_body

    # Default generic
    subject = f"[SentinelForge] Security Event: {event_type}"
    plain = (
        f"Event Type: {event_type}\n"
        f"Resource: {source_resource_type}:{source_resource_id}\n"
        f"Time: {created_at.isoformat()}\n"
    )
    html_body = (
        f"<p>Event: {safe_event_type}<br>"
        f"Resource: {html.escape(source_resource_type)}:{safe_id}</p>"
    )
    return subject, plain, html_body
