export type ReportType =
  | 'summary'
  | 'alerts'
  | 'incidents'
  | 'detections'
  | 'sla'
  | 'threat-intelligence'
  | 'analyst-activity'
  | 'audit'
  | 'compliance';

export type ReportExportFormat = 'csv' | 'json';

export interface ReportingTimeRange {
  start_time: string;
  end_time: string;
}

export interface DurationMetric {
  mean_seconds: number | null;
  median_seconds: number | null;
  min_seconds: number | null;
  max_seconds: number | null;
  sample_count: number;
}

export interface AlertLifecycleMetrics {
  time_to_acknowledge: DurationMetric;
  time_to_assign: DurationMetric;
  time_to_resolve: DurationMetric;
  time_to_close: DurationMetric;
  unacknowledged_count: number;
  unassigned_count: number;
  unresolved_count: number;
  unclosed_count: number;
}

export interface OperationsSummaryReport {
  time_range: ReportingTimeRange;
  total_alerts: number;
  alerts_by_severity: Record<string, number>;
  alerts_by_status: Record<string, number>;
  acknowledged_count: number;
  unacknowledged_count: number;
  assigned_count: number;
  unassigned_count: number;
  suppressed_count: number;
  resolved_count: number;
  closed_count: number;
  open_incident_cases: number;
  total_active_rules: number;
  total_active_indicators: number;
  generated_at: string;
}

export interface AlertPerformanceReport {
  time_range: ReportingTimeRange;
  total_alerts: number;
  alerts_by_severity: Record<string, number>;
  alerts_by_status: Record<string, number>;
  lifecycle: AlertLifecycleMetrics;
  generated_at: string;
}

export interface IncidentReport {
  time_range: ReportingTimeRange;
  total_incidents: number;
  incidents_by_severity: Record<string, number>;
  incidents_by_status: Record<string, number>;
  resolution_breakdown: Record<string, number>;
  duration_metrics: DurationMetric;
  linked_alerts_count: number;
  generated_at: string;
}

export interface DetectionRuleEffectivenessItem {
  rule_id: string;
  rule_name: string;
  rule_version: number;
  current_status: string;
  alert_count: number;
  severity_breakdown: Record<string, number>;
}

export interface DetectionReport {
  time_range: ReportingTimeRange;
  total_active_rules: number;
  total_draft_rules: number;
  total_disabled_rules: number;
  total_deprecated_rules: number;
  rule_effectiveness: DetectionRuleEffectivenessItem[];
  generated_at: string;
}

export interface SLABreachItem {
  alert_id: string;
  title: string;
  severity: string;
  created_at: string;
  acknowledged_at: string | null;
  triage_delay_seconds: number;
  assigned_to: string | null;
}

export interface SLAReport {
  time_range: ReportingTimeRange;
  sla_breached_count: number;
  applicable_alerts: number;
  breach_rate_percentage: number;
  severity_distribution: Record<string, number>;
  breached_alerts: SLABreachItem[];
  generated_at: string;
}

export interface ThreatIntelReport {
  time_range: ReportingTimeRange;
  indicators_by_type: Record<string, number>;
  indicators_by_status: Record<string, number>;
  total_indicators: number;
  total_sightings_in_period: number;
  generated_at: string;
}

export interface AnalystActivityItem {
  user_id: string;
  username: string;
  alerts_acknowledged: number;
  alerts_assigned: number;
  alerts_resolved: number;
  triage_notes_created: number;
  incidents_updated: number;
  total_recorded_actions: number;
}

export interface AnalystActivityReport {
  time_range: ReportingTimeRange;
  disclaimer: string;
  analysts: AnalystActivityItem[];
  generated_at: string;
}

export interface SecurityAuditReport {
  time_range: ReportingTimeRange;
  total_audit_events: number;
  action_distribution: Record<string, number>;
  resource_type_breakdown: Record<string, number>;
  login_success_count: number;
  login_failure_count: number;
  generated_at: string;
}

export interface ComplianceControlEvidenceItem {
  control_id: string;
  control_name: string;
  description: string;
  evidence_source: string;
  evidence_period: string;
  evidence_count: number;
  status: 'EVIDENCE_AVAILABLE' | 'EVIDENCE_MISSING' | 'NOT_APPLICABLE';
}

export interface ComplianceEvidenceReport {
  time_range: ReportingTimeRange;
  disclaimer: string;
  controls: ComplianceControlEvidenceItem[];
  generated_at: string;
}
