export interface InvestigationTimelinePoint {
  id: string;
  entity_type: 'event' | 'alert' | 'incident' | 'indicator';
  timestamp: string;
  title: string;
  severity?: string | null;
  summary: string;
}

export interface InvestigationCorrelationContext {
  anchor_type: 'ip' | 'user' | 'hash' | 'domain';
  anchor_value: string;
  total_events: number;
  total_alerts: number;
  total_incidents: number;
  total_indicators: number;
  timeline: InvestigationTimelinePoint[];
  related_ips: string[];
  related_users: string[];
  risk_score: number;
}
