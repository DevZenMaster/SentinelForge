export interface AuditLogEntry {
  id: string;
  action: string;
  actor_user_id?: string | null;
  resource_type: string;
  resource_id?: string | null;
  request_id?: string | null;
  source_ip?: string | null;
  user_agent?: string | null;
  old_value?: Record<string, unknown> | null;
  new_value?: Record<string, unknown> | null;
  timestamp: string;
}
