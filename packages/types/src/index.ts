// EXPOSE Security Intelligence Platform - Core Shared Types

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type Confidence = 'CONFIRMED' | 'LIKELY' | 'POTENTIAL' | 'INFORMATIONAL';

export type ObservationStatus = 'CONFIRMED' | 'OBSERVED' | 'INFERRED' | 'NOT_ASSESSED' | 'FIXED';

export type Category =
  | 'TRANSPORT_SECURITY'
  | 'BROWSER_SECURITY'
  | 'COOKIE_SESSION_SECURITY'
  | 'CONFIGURATION'
  | 'ATTACK_SURFACE'
  | 'INFORMATION_EXPOSURE'
  | 'API_SECURITY'
  | 'THIRD_PARTY_RESOURCES'
  | 'AUTHENTICATION'
  | 'CRYPTOGRAPHY'
  | 'HTTP_HEADERS'
  | 'COOKIE_SECURITY'
  | 'SECURITY_METADATA'
  | 'INFORMATION_DISCLOSURE'
  | 'MIXED_CONTENT'
  | 'NETWORK_POSTURE'
  | 'CLIENT_SIDE_SECURITY'
  | 'EXTERNAL_EXPOSURE';

export type EvidenceType =
  | 'HTTP_EXCHANGE'
  | 'DNS_RECORD'
  | 'TLS_HANDSHAKE'
  | 'CERTIFICATE_METADATA'
  | 'COOKIE_ATTRIBUTE'
  | 'DOM_CONTENT'
  | 'RAW_SOCKET'
  | 'SOURCE_MAP'
  | 'CLIENT_CONFIG'
  | 'NUCLEI_MATCH'
  | 'SCRIPT_REFERENCE';

export interface Evidence {
  type: EvidenceType;
  summary: string;
  request?: Record<string, unknown>;
  response_headers?: Record<string, string>;
  raw_data?: Record<string, unknown>;
  matched_data?: string;
  command?: string;
  timestamp: string;
}

export interface ResearchSource {
  name: string;
  url: string;
}

export interface Recommendation {
  summary: string;
  remediation: string;
  config_snippet?: string;
  research_sources?: ResearchSource[];
}

export interface Verification {
  command: string;
  tool: string;
  description: string;
}

export interface SourceCitation {
  title: string;
  url: string;
  source_type: string; // OWASP, NIST, CISA, CVE, VENDOR_DOC, REPUTABLE_RESEARCH, RFC_STANDARD
  snippet?: string;
  citation_indices?: number[];
}

export interface AIIntelligenceReport {
  provider_name: string;
  model_version?: string;
  generated_at: string;
  explanation: string;
  contextual_impact: string;
  research_summary: string;
  comparative_examples: string;
  developer_recommendations: string[];
  priority_rationale: string;
  source_citations: SourceCitation[];
  is_grounded: boolean;
}

export interface FindingPriorityItem {
  finding_id: string;
  title: string;
  priority_rank: number;
  urgency_tier: string;
  justification: string;
}

export interface AIPrioritizationReport {
  target: string;
  prioritized_items: FindingPriorityItem[];
  executive_summary: string;
  remediation_roadmap: string[];
}

export interface Finding {
  id: string;
  scan_id?: string;
  probe?: string;
  target?: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  status: ObservationStatus;
  category: Category;
  rule_id?: string;
  owasp_top10?: string;
  owasp_asvs?: string;
  owasp_mapping?: string;
  asvs_mapping?: string;
  cwe?: string;
  cwe_id?: string;
  cve?: string;
  cve_id?: string;
  ai_intelligence?: AIIntelligenceReport;
  impact_explanation?: string;
  evidence: Evidence;
  impact?: string;
  recommendation?: Recommendation;
  remediation?: string;
  verification_command?: string;
  references?: ResearchSource[];
  verification?: Verification;
  created_at?: string;
}

export interface NotAssessedArea {
  area: string;
  reason: string;
  explanation: string;
}

export interface CategoryScore {
  category_name: string;
  score: number;
  weight_percentage: number;
  findings_count: number;
  confirmed_issues_count: number;
}

export interface ScoreCard {
  score_version: string;
  overall_score: number;
  letter_grade: string;
  category_scores: Record<string, CategoryScore>;
  confirmed_flaws_count: number;
  observed_properties_count: number;
  not_assessed_boundaries: NotAssessedArea[];
}

export interface PageAsset {
  url: string;
  path: string;
  title?: string;
  status_code?: number;
  is_internal: boolean;
  discovered_via: string; // html_anchor, sitemap, robots_txt
}

export interface APIAsset {
  path: string;
  method: string;
  source_script?: string;
  parameters?: string[];
  is_public: boolean;
}

export interface StaticAsset {
  url: string;
  asset_type: string; // stylesheet, image, font, media, manifest, icon
  mime_type?: string;
  is_external: boolean;
}

export interface ScriptAsset {
  url: string;
  is_external: boolean;
  cdn_provider?: string;
  has_sri: boolean;
  sri_hash?: string;
}

export interface FormInput {
  name: string;
  input_type: string;
  is_sensitive: boolean;
}

export interface FormAsset {
  action: string;
  method: string;
  inputs: FormInput[];
  has_password: boolean;
  is_secure_action: boolean;
}

export interface ExternalDependency {
  origin: string;
  category: string; // CDN, Analytics, Fonts, Social, Ads, Auth, Unknown
  resource_count: number;
  sample_urls?: string[];
}

export interface RobotsTxtAsset {
  is_present: boolean;
  disallowed_paths: string[];
  allowed_paths: string[];
  sitemaps: string[];
}

export interface AttackSurface {
  target: string;
  pages: PageAsset[];
  apis: APIAsset[];
  assets: StaticAsset[];
  scripts: ScriptAsset[];
  forms: FormAsset[];
  external_dependencies: ExternalDependency[];
  robots_txt?: RobotsTxtAsset;
  sitemaps?: string[];
  exposure_summary: string;
  discovered_at?: string;
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

export interface ProbeStatus {
  probe_name: string;
  status: 'completed' | 'failed' | 'cancelled';
  duration_seconds: number;
  error_message?: string;
}

export interface ScanResult {
  scan_id: string;
  target: TargetScope;
  start_time: string;
  end_time?: string;
  duration_seconds: number;
  score_card?: ScoreCard;
  attack_surface?: AttackSurface;
  probe_statuses: ProbeStatus[];
  findings: Finding[];
  ai_prioritization?: AIPrioritizationReport;
  severity_counts: Record<Severity, number>;
}

export interface HealthResponse {
  status: 'healthy';
  service: string;
  version: string;
  uptime_seconds: number;
  timestamp: string;
}

export interface DependencyStatus {
  status: 'UP' | 'DOWN';
  latency_ms?: number;
  error?: string;
}

export interface ReadyResponse {
  status: 'ready' | 'not_ready';
  service: string;
  version: string;
  timestamp: string;
  dependencies: {
    postgres: DependencyStatus;
    redis: DependencyStatus;
  };
}

export interface APIEnvelope<T> {
  status: 'success' | 'error';
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: unknown[];
  };
}

// Phase 15: Verification Types
export type VerificationStatus = 'FIXED' | 'STILL_VULNERABLE' | 'FAILED';

export interface VerificationResult {
  verification_id: string;
  scan_id: string;
  finding_id: string;
  status: VerificationStatus;
  message: string;
  score_before: number;
  score_after: number;
  score_delta: number;
  before_evidence_summary: string;
  after_evidence?: Evidence;
  timestamp: string;
}

// Phase 16: Security History & Diff Types
export type FindingDiffType = 'NEW' | 'FIXED' | 'CHANGED' | 'UNCHANGED';

export interface FindingDiffItem {
  finding_id: string;
  rule_id?: string;
  title: string;
  category: string;
  diff_type: FindingDiffType;
  severity_current?: Severity;
  severity_previous?: Severity;
  detail: string;
}

export interface SecurityDiff {
  target: string;
  current_scan_id: string;
  previous_scan_id?: string;
  score_current: number;
  score_previous?: number;
  score_delta: number;
  new_findings: FindingDiffItem[];
  fixed_findings: FindingDiffItem[];
  changed_findings: FindingDiffItem[];
  unchanged_findings: FindingDiffItem[];
  summary: string;
}

export interface ScanHistoryItem {
  scan_id: string;
  target: string;
  timestamp: string;
  score: number;
  letter_grade: string;
  confirmed_flaws_count: number;
  duration_seconds?: number;
}
