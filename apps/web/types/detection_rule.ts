export type RuleStatus = 'DRAFT' | 'ACTIVE' | 'DISABLED' | 'DEPRECATED';
export type RuleSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface DetectionRuleVersion {
  id: string;
  rule_id: string;
  version: number;
  title: string;
  description: string;
  severity: RuleSeverity;
  status: RuleStatus;
  criteria: Record<string, unknown>;
  author_user_id: string;
  created_at: string;
}

export interface DetectionRule {
  id: string;
  rule_id: string;
  name: string;
  description: string;
  severity: RuleSeverity;
  status: RuleStatus;
  current_version: number;
  criteria: Record<string, unknown>;
  tags: string[];
  created_at: string;
  updated_at: string;
  versions?: DetectionRuleVersion[];
}
