/**
 * Comprehensive TypeScript data contracts for VulnSight Frontend.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "certain" | "firm" | "tentative";
export type FindingStatus = "open" | "in_progress" | "remediated" | "verified" | "accepted_risk" | "false_positive";
export type RemediationStatus = "not_started" | "in_progress" | "done" | "accepted_risk";
export type VerificationStatus = "pending" | "running" | "passed" | "failed" | "error" | "cancelled";
export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";

export interface ScanTarget {
  id: string;
  scan_id: string;
  url: string;
  scheme: string;
  hostname: string;
  port: number | null;
  path: string;
  is_authorized: boolean;
  authorization_reference?: string;
  created_at: string;
}

export interface DiscoveredEndpoint {
  id: string;
  scan_id: string;
  target_id: string;
  method: string;
  url: string;
  path: string;
  status_code: number | null;
  content_type: string | null;
  discovered_at: string;
}

export interface ScanSession {
  id: string;
  name: string;
  status: ScanStatus;
  profile: string;
  status_message: string | null;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  target_count?: number;
  finding_count?: number;
  targets?: ScanTarget[];
  endpoints?: DiscoveredEndpoint[];
}

export interface ScanStatusResponse {
  id: string;
  status: ScanStatus;
  status_message: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface EvidenceItem {
  id: string;
  finding_id: string;
  kind: "request" | "response" | "text" | "log";
  label: string;
  content: string;
  content_sha256: string;
  is_redacted: boolean;
  created_at: string;
}

export interface RemediationItem {
  id: string;
  finding_id: string;
  summary: string;
  steps: string[];
  references: string[];
  status: RemediationStatus;
  notes: string | null;
  updated_at: string;
}

export interface VerificationRunItem {
  id: string;
  finding_id: string;
  status: VerificationStatus;
  started_at: string | null;
  finished_at: string | null;
  result_summary: string | null;
  details?: Record<string, unknown> | null;
  created_at: string;
}

export interface RiskAssessmentBreakdown {
  score: number;
  rating: "Critical" | "High" | "Medium" | "Low" | "Informational";
  severity: Severity;
  impact_score: number;
  likelihood_score: number;
  likelihood_level: "high" | "medium" | "low";
  confidence: Confidence;
  confidence_weight: number;
  formula: string;
  scoring_method: string;
  disclaimer: string;
}

export interface CodeSnippet {
  stack_name: string;
  vulnerable_code: string;
  secure_code: string;
  explanation: string;
}

export interface FrameworkGuidance {
  framework_name: string;
  recommendations: string[];
  config_snippet?: string | null;
}

export interface FixVerificationCriteria {
  what_should_change: string;
  check_to_rerun: string;
  expected_evidence: string;
  inconclusive_conditions: string;
}

export interface RemediationGuide {
  check_id: string;
  owasp_category: string;
  title: string;
  vulnerability_meaning: string;
  why_it_occurs: string;
  internal_workings: string;
  safe_exploitation_scenario: string;
  business_impact: string;
  root_cause: string;
  step_by_step_remediation: string[];
  code_examples: Record<string, CodeSnippet>;
  framework_guidance: Record<string, FrameworkGuidance>;
  fix_verification: FixVerificationCriteria;
  references: string[];
}

export interface FindingSummary {
  id: string;
  scan_id: string;
  endpoint_id: string | null;
  check_id: string;
  owasp_category: string;
  title: string;
  vulnerability_name?: string | null;
  affected_url?: string | null;
  severity: Severity;
  confidence: Confidence;
  risk_score: number;
  detection_method: string;
  status: FindingStatus;
  remediation_status?: RemediationStatus | null;
  created_at: string;
  detection_timestamp?: string | null;
  updated_at: string;
}

export interface FindingDetail extends FindingSummary {
  description: string;
  fingerprint: string | null;
  endpoint?: DiscoveredEndpoint | null;
  evidence: EvidenceItem[];
  technical_evidence: EvidenceItem[];
  remediation: RemediationItem | null;
  risk_assessment: RiskAssessmentBreakdown | null;
  remediation_guide: RemediationGuide | null;
  verification_runs: VerificationRunItem[];
}

export interface ReportItem {
  id: string;
  scan_id: string;
  title: string;
  version: string;
  format: "json" | "markdown" | "pdf";
  created_at: string;
  summary?: Record<string, unknown>;
}

export interface OperatorUser {
  id: string;
  email: string;
  display_name: string;
  role: string;
}
