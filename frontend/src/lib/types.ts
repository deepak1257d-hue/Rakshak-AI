export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type FindingType = 'VULNERABILITY' | 'MISCONFIGURATION' | 'EXPOSURE' | 'INFORMATIONAL';
export type ConfidenceLevel = 'CONFIRMED' | 'PROBABLE' | 'INCONCLUSIVE';

export interface Finding {
  id: string;
  scan_id: string;
  workspace_id: string;
  title: string;
  cve_id?: string;
  severity: SeverityLevel;
  score?: number | null;
  score_source?: string | null;
  finding_type?: FindingType;
  category?: string;
  affected_asset?: string;
  port?: string;
  confidence?: ConfidenceLevel;
  detection_method?: string;
  technical_description?: string;
  security_impact?: string;
  evidence?: string;
  reachability_proof?: string;
  sanitized_output?: string;
  remediation_patch?: string;
  remediation_explanation?: string;
  status: 'OPEN' | 'IN_PROGRESS' | 'RESOLVED' | 'MUTED' | string;
  detected_at?: string;
  created_at?: string;
}

export interface TargetAsset {
  id: string;
  workspace_id: string;
  domain: string;
  verification_token: string;
  verification_status: 'PENDING' | 'VERIFIED' | 'FAILED';
  verification_method: 'DNS_TXT' | 'HTML_META' | 'HTTP_FILE' | 'LAB';
  lab_mode?: boolean;
  is_lab?: boolean;
  last_verified_at?: string;
  last_scan_at?: string;
  security_score?: number | null;
  open_findings_count: number;
  ip_address?: string;
  tech_stack?: string[];
  created_at: string;
}

export interface ScanRun {
  id: string;
  workspace_id: string;
  target_id: string;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'PARTIAL';
  progress_pct: number;
  current_stage: string;
  is_partial?: boolean;
  trace_id?: string;
  trace_url?: string;
  started_at: string;
  completed_at?: string;
}

export interface AttackSurfaceItem {
  id: string;
  asset_domain: string;
  type: 'DOMAIN' | 'SUBDOMAIN' | 'PORT' | 'SERVICE' | 'TECH' | 'TLS';
  label: string;
  detail: string;
  exposure_status: 'HIGH' | 'MEDIUM' | 'LOW' | 'SECURE';
}

export interface MonitoringLog {
  id: string;
  timestamp: string;
  event_type: 'SCAN_COMPLETED' | 'ENDPOINT_DETECTED' | 'CERT_CHECKED' | 'NO_CHANGES' | 'ALERT';
  message: string;
  asset: string;
}

export interface NotificationItem {
  id: string;
  title: string;
  description: string;
  timestamp: string;
  severity: SeverityLevel;
  read: boolean;
}

export interface ExecutiveSummary {
  scan_id: string;
  scan_status?: string;
  is_partial?: boolean;
  current_stage?: string;
  target_domain: string;
  target_verification_method?: string;
  is_lab_target?: boolean;
  ownership_badge?: string;
  ownership_warning?: string;
  composite_risk_score?: number | null;
  average_risk_score?: number | null;
  risk_score_basis?: string;
  risk_score_scope?: string;
  total_findings: number;
  critical_count: number;
  high_count: number;
  trace_id?: string;
  trace_url?: string;
  time_to_remediate_estimate?: string | null;
  time_to_remediate_status?: string;
  findings: Finding[];
}

