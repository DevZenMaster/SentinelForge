export interface SecurityEvent {
  id: string;
  external_event_id?: string | null;
  timestamp: string;
  ingested_at: string;
  source: string;
  source_type: string;
  source_ip?: string | null;
  destination_ip?: string | null;
  source_port?: number | null;
  destination_port?: number | null;
  event_type: string;
  action: string;
  outcome: string;
  username?: string | null;
  severity: string;
  message?: string | null;
  request_id?: string | null;
  raw_payload: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  normalization_status: string;
  parser_name?: string | null;
  parser_version?: string | null;
  normalization_version?: string | null;
  normalized_at?: string | null;
  normalization_errors?: Array<Record<string, unknown>>;
  attributes?: Record<string, unknown>;
}
