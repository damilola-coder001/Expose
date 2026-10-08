package domain

import "time"

// Target represents a registered website/domain identity.
type Target struct {
	ID           string    `json:"id"`
	Domain       string    `json:"domain"`
	DefaultPort  int       `json:"default_port"`
	IsVerified   bool      `json:"is_verified"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ResearchSource provides authoritative references (RFCs, OWASP, NIST).
type ResearchSource struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Recommendation defines specific actionable guidance for remediation.
type Recommendation struct {
	Summary        string           `json:"summary"`
	Remediation    string           `json:"remediation"`
	ConfigSnippet  string           `json:"config_snippet,omitempty"`
	ResearchSources []ResearchSource `json:"research_sources,omitempty"`
}

// Verification provides copy-paste CLI commands allowing independent operator validation.
type Verification struct {
	Command     string `json:"command"`
	Tool        string `json:"tool"` // curl, openssl, dig
	Description string `json:"description"`
}

// Evidence captures raw, verifiable wire/socket observations.
type Evidence struct {
	Type            EvidenceType           `json:"type"`
	Summary         string                 `json:"summary"`
	Request         map[string]interface{} `json:"request,omitempty"`
	ResponseHeaders map[string]string      `json:"response_headers,omitempty"`
	RawData         map[string]interface{} `json:"raw_data,omitempty"`
	MatchedData     string                 `json:"matched_data,omitempty"`
	Command         string                 `json:"command,omitempty"`
	Timestamp       time.Time              `json:"timestamp"`
}

// SourceCitation records authoritative verified references (OWASP, NIST, CISA, RFCs).
type SourceCitation struct {
	Title      string `json:"title"`
	URL        string `json:"url"`
	SourceType string `json:"source_type"`
	Snippet    string `json:"snippet,omitempty"`
}

// AIIntelligenceReport represents grounded AI security intelligence for a finding.
type AIIntelligenceReport struct {
	ProviderName             string           `json:"provider_name"`
	ModelVersion             string           `json:"model_version,omitempty"`
	GeneratedAt              time.Time        `json:"generated_at"`
	Explanation              string           `json:"explanation"`
	ContextualImpact         string           `json:"contextual_impact"`
	ResearchSummary          string           `json:"research_summary"`
	ComparativeExamples      string           `json:"comparative_examples"`
	DeveloperRecommendations []string         `json:"developer_recommendations"`
	PriorityRationale        string           `json:"priority_rationale"`
	SourceCitations          []SourceCitation `json:"source_citations,omitempty"`
	IsGrounded               bool             `json:"is_grounded"`
}

// Finding represents a single security observation supported by empirical proof.
// Follows Phase 5 Standardized Finding Format:
// Finding, Severity, Confidence, Category, Evidence, Impact, Recommendation, References.
type Finding struct {
	ID                  string                `json:"id"`
	ScanID              string                `json:"scan_id"`
	Title               string                `json:"title"`
	Description         string                `json:"description"`
	Severity            Severity              `json:"severity"`
	Confidence          Confidence            `json:"confidence"`
	Status              ObservationStatus     `json:"status"`
	Category            Category              `json:"category"`
	RuleID              string                `json:"rule_id"`
	OWASPTop10          string                `json:"owasp_top10,omitempty"`
	OWASPASVS           string                `json:"owasp_asvs,omitempty"`
	OWASPMapping        string                `json:"owasp_mapping,omitempty"`
	ASVSMapping         string                `json:"asvs_mapping,omitempty"`
	CWE                 string                `json:"cwe,omitempty"`
	CVE                 string                `json:"cve,omitempty"`
	AIIntelligence      *AIIntelligenceReport `json:"ai_intelligence,omitempty"`
	Evidence            Evidence              `json:"evidence"`
	Impact              string                `json:"impact"`
	Recommendation      Recommendation        `json:"recommendation"`
	References          []ResearchSource      `json:"references,omitempty"`
	Verification        Verification          `json:"verification"`
	CreatedAt           time.Time             `json:"created_at"`
}

// Asset represents a discovered infrastructure element (certificate, IP, host).
type Asset struct {
	ID           string                 `json:"id"`
	TargetID     string                 `json:"target_id"`
	Type         AssetType              `json:"type"`
	Value        string                 `json:"value"`
	Attributes   map[string]interface{} `json:"attributes,omitempty"`
	DiscoveredAt time.Time              `json:"discovered_at"`
}

// SecurityCategory models domain scoring weights and boundaries.
type SecurityCategory struct {
	Name        Category `json:"name"`
	DisplayName string   `json:"display_name"`
	Weight      int      `json:"weight"`
	Description string   `json:"description"`
}

// NotAssessedArea documents explicit out-of-scope boundaries to guarantee transparency.
type NotAssessedArea struct {
	Area        string `json:"area"`
	Reason      string `json:"reason"`
	Explanation string `json:"explanation"`
}

// CategoryScore contains score metrics for a domain.
type CategoryScore struct {
	CategoryName         string `json:"category_name"`
	Score                int    `json:"score"`
	WeightPercentage     int    `json:"weight_percentage"`
	FindingsCount        int    `json:"findings_count"`
	ConfirmedIssuesCount int    `json:"confirmed_issues_count"`
}

// ScoreCard holds the overall 0-100 posture score.
type ScoreCard struct {
	ScoreVersion            string                   `json:"score_version"`
	OverallScore            int                      `json:"overall_score"`
	LetterGrade             string                   `json:"letter_grade"`
	CategoryScores          map[string]CategoryScore `json:"category_scores"`
	ConfirmedFlawsCount     int                      `json:"confirmed_flaws_count"`
	ObservedPropertiesCount int                      `json:"observed_properties_count"`
	NotAssessedBoundaries   []NotAssessedArea        `json:"not_assessed_boundaries"`
}

// RiskAssessment provides an executive summary of risk derived from empirical findings.
type RiskAssessment struct {
	PostureSummary string   `json:"posture_summary"`
	CriticalRisks  []string `json:"critical_risks"`
	PositiveNotes  []string `json:"positive_notes"`
	GeneratedAt    time.Time `json:"generated_at"`
}

// Scan represents an execution instance.
type Scan struct {
	ID                      string            `json:"id"`
	TargetID                string            `json:"target_id"`
	RawTarget               string            `json:"raw_target"`
	NormalizedURL           string            `json:"normalized_url"`
	Status                  ScanStatus        `json:"status"`
	ScoreCard               *ScoreCard        `json:"score_card,omitempty"`
	RiskAssessment          *RiskAssessment   `json:"risk_assessment,omitempty"`
	AttackSurface           *AttackSurface    `json:"attack_surface,omitempty"`
	Findings                []Finding         `json:"findings"`
	Assets                  []Asset           `json:"assets,omitempty"`
	SeverityCounts          map[Severity]int  `json:"severity_counts"`
	DurationSeconds         float64           `json:"duration_seconds"`
	ErrorMessage            string            `json:"error_message,omitempty"`
	StartedAt               time.Time         `json:"started_at"`
	CompletedAt             *time.Time        `json:"completed_at,omitempty"`
}

// ScanHistory tracks historical posture progress of a target over time.
type ScanHistory struct {
	TargetID     string    `json:"target_id"`
	ScanID       string    `json:"scan_id"`
	Score        int       `json:"score"`
	Grade        string    `json:"grade"`
	FindingsCount int      `json:"findings_count"`
	Timestamp    time.Time `json:"timestamp"`
}
