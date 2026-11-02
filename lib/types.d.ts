/**
 * Website Security Testing Toolkit - Type Definitions
 */

export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export type VerificationStatus = 'Confirmed' | 'Potential' | 'Secure';

export interface SecurityPayload {
  id: string;
  category: string;
  payload: string;
  purpose: string;
  expected_secure_behavior: string;
  expected_vulnerable_behavior: string;
  risk_level: SeverityLevel;
  remediation: string;
}

export interface SecurityFinding {
  id: string;
  category: string;
  severity: SeverityLevel;
  title: string;
  endpoint: string;
  method: string;
  status: VerificationStatus;
  evidence: string;
  reproduction_steps: string[];
  impact: string;
  remediation: string;
  owasp_ref?: string;
  cwe_ref?: string;
}

export interface ScanTargetConfig {
  baseUrl: string;
  allowedHosts: string[];
  timeoutMs: number;
  maxConcurrency: number;
  authorized: boolean;
}

export interface SecurityAssessmentReport {
  target_application: string;
  target_url: string;
  assessment_date: string;
  tested_endpoints: string[];
  summary: {
    total_findings: number;
    confirmed: number;
    potential: number;
    by_severity: Record<SeverityLevel, number>;
  };
  findings: SecurityFinding[];
}
