export type AlertStatus =
  | 'OPEN'
  | 'ACKNOWLEDGED'
  | 'IN_PROGRESS'
  | 'SUPPRESSED'
  | 'RESOLVED'
  | 'CLOSED';

export type AlertSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface UserSummary {
  id: string;
  username: string;
  email: string;
  full_name?: string | null;
}

export interface AlertNote {
  id: string;
  alert_id: string;
  author_user_id: string;
  author_username: string;
  content: string;
  created_at: string;
}

export interface AlertSummary {
  id: string;
  title: string;
  severity: AlertSeverity;
  status: AlertStatus;
  rule_id: string;
  rule_name: string;
  rule_version: number;
  priority_score: number;
  sla_breached: boolean;
  is_acknowledged: boolean;
  event_count: number;
  source_ip?: string | null;
  destination_ip?: string | null;
  username?: string | null;
  assignee?: UserSummary | null;
  acknowledged_by?: UserSummary | null;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  version: number;
}

export interface AlertDetail extends AlertSummary {
  description?: string | null;
  suppression_reason?: string | null;
  suppression_expires_at?: string | null;
  resolution_reason?: string | null;
  resolved_at?: string | null;
  closed_at?: string | null;
  acknowledged_at?: string | null;
  resolved_by?: UserSummary | null;
  closed_by?: UserSummary | null;
  suppressed_by?: UserSummary | null;
  events?: Array<{
    id: string;
    event_id: string;
    role: string;
    timestamp: string;
  }>;
  linked_incident_ids?: string[];
}

export interface AlertTransitionRequest {
  status: AlertStatus;
  reason?: string;
  version: number;
}

export interface AlertAcknowledgeRequest {
  version: number;
}

export interface AlertAssignRequest {
  assignee_id: string;
  version: number;
}

export interface AlertSuppressRequest {
  reason: string;
  duration_minutes: number;
  version: number;
}

export interface AlertResolveRequest {
  resolution_reason: string;
  version: number;
}

export interface AlertCloseRequest {
  close_reason?: string;
  version: number;
}

export interface AlertNoteCreateRequest {
  content: string;
}
