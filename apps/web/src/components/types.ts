export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type ObservationStatus = "CONFIRMED" | "OBSERVED" | "INFERRED" | "NOT_ASSESSED" | "FIXED";
export type ConfidenceLevel = "CONFIRMED" | "LIKELY" | "POTENTIAL" | "INFORMATIONAL";

export interface Evidence {
  type: string;
  summary: string;
  request?: Record<string, any>;
  response?: Record<string, any>;
  response_headers?: Record<string, string>;
  raw_data?: Record<string, any>;
  matched_data?: string;
  command?: string;
  timestamp: string;
}

export interface Recommendation {
  summary: string;
  remediation: string;
  config_snippet?: string;
}

export interface Verification {
  command: string;
  tool: string;
  description: string;
}

export interface AIIntelligenceReport {
  provider_name?: string;
  model_version?: string;
  observation?: string;
  evidence_summary?: string;
  security_meaning?: string;
  confidence_explanation?: string;
  impact?: string;
  real_world_context?: string;
  recommendation?: string;
  verification_method?: string;
  explanation?: string;
  contextual_impact?: string;
  research_summary?: string;
  comparative_examples?: string;
  developer_recommendations?: string[];
  priority_rationale?: string;
  source_citations?: Array<{
    title: string;
    url: string;
    source_type: string;
    snippet?: string;
  }>;
  is_grounded?: boolean;
}

export interface Finding {
  id: string;
  scan_id?: string;
  probe?: string;
  target?: string;
  category: string;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  status: ObservationStatus;
  title: string;
  description: string;
  impact_explanation?: string;
  impact?: string;
  remediation?: string;
  recommendation?: Recommendation | string;
  verification_command?: string;
  verification?: Verification;
  rule_id?: string;
  owasp_top10?: string;
  owasp_asvs?: string;
  cwe_id?: string;
  cwe?: string;
  cve_id?: string;
  cve?: string;
  ai_intelligence?: AIIntelligenceReport;
  evidence: Evidence;
  timestamp?: string;
  references?: Array<{ name: string; url: string }>;
}

export interface CategoryScore {
  category_name: string;
  score: number;
  weight_percentage: number;
  findings_count: number;
  confirmed_issues_count: number;
}

export interface NotAssessedArea {
  area: string;
  reason: string;
  explanation: string;
}

export type HeaderTestStatus = "PASS" | "WARN" | "FAIL" | "INFO";

export interface HeaderTestResult {
  id: string;
  name: string;
  header_name?: string;
  status: HeaderTestStatus;
  score_modifier: number;
  observed_value?: string | null;
  expected_value: string;
  description: string;
  advice: string;
  doc_url: string;
}

export interface ScoreCard {
  score_version?: string;
  overall_score: number;
  letter_grade: string;
  score_philosophy?: string;
  category_scores: Record<string, CategoryScore>;
  confirmed_flaws_count: number;
  observed_properties_count: number;
  not_assessed_boundaries?: NotAssessedArea[];
  header_test_matrix?: HeaderTestResult[];
}

export interface RiskAssessment {
  posture_summary: string;
  critical_risks: string[];
  positive_notes: string[];
}

export interface PageAsset {
  url: string;
  path: string;
  title?: string;
  status_code?: number;
  is_internal?: boolean;
  discovered_via: string;
}

export interface APIAsset {
  path: string;
  method: string;
  is_public?: boolean;
}

export interface ScriptAsset {
  url: string;
  is_external?: boolean;
  cdn_provider?: string;
  has_sri: boolean;
  sri_hash?: string;
}

export interface FormAsset {
  action: string;
  method: string;
  inputs: Array<{ name: string; input_type: string; is_sensitive?: boolean }>;
  has_password?: boolean;
  is_secure_action?: boolean;
}

export interface ExternalDependency {
  origin: string;
  category: string;
  resource_count: number;
  sample_urls?: string[];
}

export interface AttackSurface {
  target?: string;
  pages: PageAsset[];
  apis: APIAsset[];
  scripts: ScriptAsset[];
  forms: FormAsset[];
  external_dependencies: ExternalDependency[];
  robots_txt?: {
    is_present: boolean;
    disallowed_paths: string[];
    allowed_paths: string[];
    sitemaps: string[];
  };
  sitemaps?: string[];
  exposure_summary?: string;
}

export interface TargetScope {
  raw_target: string;
  normalized_url: string;
  scheme: string;
  host: string;
  port: number;
  resolved_ips: string[];
  is_private: boolean;
  allow_private: boolean;
}

export interface ScanResult {
  id?: string;
  scan_id?: string;
  target_id?: string;
  raw_target?: string;
  normalized_url?: string;
  target?: TargetScope;
  status?: string;
  duration_seconds: number;
  score_card: ScoreCard;
  risk_assessment?: RiskAssessment;
  attack_surface?: AttackSurface;
  header_test_matrix?: HeaderTestResult[];
  findings: Finding[];
  severity_counts: Record<string, number>;
  start_time?: string;
  end_time?: string;
  domain_verified?: boolean;
  domain_ownership_proof?: string;
}

export interface DomainChallenge {
  domain: string;
  token: string;
  dns_record_name: string;
  dns_record_type: string;
  dns_record_value: string;
  http_url: string;
  http_expected_content: string;
  created_at: string;
  expires_at: string;
  instructions: {
    dns_txt: string;
    http_well_known: string;
  };
}

export interface DomainOwnershipRecord {
  domain: string;
  verified: boolean;
  verified_at?: string;
  verification_method?: string;
  proof?: string;
  expires_at?: string;
}

