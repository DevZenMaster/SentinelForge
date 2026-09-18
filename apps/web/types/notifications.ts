/**
 * TypeScript definitions for SentinelForge Notifications & Integrations (Phase 13).
 */

export type DestinationType = 'WEBHOOK' | 'EMAIL';

export type DeliveryStatus =
  | 'PENDING'
  | 'DELIVERING'
  | 'DELIVERED'
  | 'FAILED'
  | 'RETRYING'
  | 'EXHAUSTED'
  | 'CANCELLED';

export type NotificationEventType =
  | 'ALERT_CREATED'
  | 'ALERT_ESCALATED'
  | 'ALERT_ASSIGNED'
  | 'ALERT_ACKNOWLEDGED'
  | 'ALERT_RESOLVED'
  | 'ALERT_CLOSED'
  | 'ALERT_SUPPRESSED'
  | 'INCIDENT_CREATED'
  | 'INCIDENT_STATE_CHANGED'
  | 'INCIDENT_RESOLVED'
  | 'SLA_BREACH_DETECTED'
  | 'REPORT_EXPORTED';

export interface Integration {
  id: string;
  name: string;
  type: DestinationType;
  enabled: boolean;
  endpoint_url?: string | null;
  email_recipients?: string[] | null;
  is_secret_configured: boolean;
  secret_preview?: string | null;
  created_by_user_id?: string | null;
  updated_by_user_id?: string | null;
  last_delivery_at?: string | null;
  last_successful_delivery_at?: string | null;
  last_failed_delivery_at?: string | null;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface IntegrationCreate {
  name: string;
  type: DestinationType;
  enabled?: boolean;
  endpoint_url?: string | null;
  email_recipients?: string[] | null;
  secret_token?: string | null;
}

export interface IntegrationUpdate {
  name?: string | null;
  endpoint_url?: string | null;
  email_recipients?: string[] | null;
  secret_token?: string | null;
  enabled?: boolean | null;
  version: number;
}

export interface NotificationPolicy {
  id: string;
  name: string;
  description?: string | null;
  enabled: boolean;
  event_types: string[];
  min_severity?: string | null;
  destination_ids: string[];
  filters: Record<string, any>;
  cooldown_seconds: number;
  created_by_user_id?: string | null;
  updated_by_user_id?: string | null;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface NotificationPolicyCreate {
  name: string;
  description?: string | null;
  enabled?: boolean;
  event_types: string[];
  min_severity?: string | null;
  destination_ids: string[];
  filters?: Record<string, any>;
  cooldown_seconds?: number;
}

export interface NotificationPolicyUpdate {
  name?: string | null;
  description?: string | null;
  enabled?: boolean | null;
  event_types?: string[] | null;
  min_severity?: string | null;
  destination_ids?: string[] | null;
  filters?: Record<string, any> | null;
  cooldown_seconds?: number | null;
  version: number;
}

export interface NotificationDelivery {
  id: string;
  event_id: string;
  event_type: string;
  source_resource_type: string;
  source_resource_id: string;
  policy_id: string;
  policy_name: string;
  destination_id: string;
  destination_name: string;
  destination_type: string;
  idempotency_key: string;
  status: DeliveryStatus;
  attempt_count: number;
  max_attempts: number;
  first_attempted_at?: string | null;
  last_attempted_at?: string | null;
  next_retry_at?: string | null;
  delivered_at?: string | null;
  http_status?: number | null;
  failure_reason?: string | null;
  response_metadata: Record<string, any>;
  latency_ms?: number | null;
  event?: {
    id: string;
    event_type: string;
    source_resource_type: string;
    source_resource_id: string;
    payload?: Record<string, any>;
    created_at?: string;
  } | null;
  destination?: {
    id: string;
    name: string;
    type: string;
    endpoint_url?: string | null;
    email_recipients?: string[] | null;
  } | null;
  created_at: string;
  updated_at: string;
}

export interface NotificationTestResponse {
  destination_id: string;
  destination_name: string;
  destination_type: string;
  status: 'SUCCESS' | 'FAILED';
  http_status?: number | null;
  message: string;
  latency_ms: number;
}
