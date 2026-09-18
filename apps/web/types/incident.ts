import { UserSummary } from './alert';

export type IncidentStatus = 'OPEN' | 'IN_PROGRESS' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';
export type IncidentSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface IncidentAlertSummary {
  id: string;
  title: string;
  severity: string;
  status: string;
  priority_score: number;
  created_at: string;
}

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  lead_analyst_id?: string | null;
  lead_analyst?: UserSummary | null;
  created_at: string;
  updated_at: string;
  closed_at?: string | null;
  summary?: string | null;
  alerts?: IncidentAlertSummary[];
}

export interface IncidentCreateRequest {
  title: string;
  description: string;
  severity: IncidentSeverity;
  lead_analyst_id?: string | null;
}

export interface IncidentUpdateRequest {
  title?: string;
  description?: string;
  severity?: IncidentSeverity;
  status?: IncidentStatus;
  lead_analyst_id?: string | null;
}
