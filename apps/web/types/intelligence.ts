export type IndicatorType = 'ip' | 'domain' | 'sha256' | 'md5' | 'url';
export type ThreatLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface Indicator {
  id: string;
  type: IndicatorType;
  value: string;
  threat_level: ThreatLevel;
  confidence: number;
  description?: string | null;
  sources: string[];
  tags: string[];
  is_active: boolean;
  first_seen?: string | null;
  last_seen?: string | null;
  created_at: string;
  updated_at: string;
}

export interface IndicatorCreateRequest {
  type: IndicatorType;
  value: string;
  threat_level: ThreatLevel;
  confidence: number;
  description?: string;
  sources?: string[];
  tags?: string[];
}
