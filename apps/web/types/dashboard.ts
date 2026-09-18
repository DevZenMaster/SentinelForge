import { AlertSummary } from './alert';

export interface AuditLogActivity {
  id: string;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  actor_user_id?: string | null;
  timestamp: string;
}

export interface SOCDashboardMetrics {
  open_alerts_count: number;
  critical_alerts_count: number;
  high_alerts_count: number;
  unacknowledged_alerts_count: number;
  unassigned_alerts_count: number;
  sla_breached_alerts_count: number;
  open_incidents_count: number;
  active_rules_count: number;
  total_indicators_count: number;
  recent_alerts: AlertSummary[];
  recent_activity: AuditLogActivity[];
}
