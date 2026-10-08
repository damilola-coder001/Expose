package models

import "time"

// Severity level of a security finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Confidence of finding observation.
type Confidence string

const (
	ConfidenceConfirmed Confidence = "CONFIRMED"
	ConfidenceHigh      Confidence = "HIGH"
	ConfidenceMedium    Confidence = "MEDIUM"
)

// ObservationStatus defines the empirical distinction for reports.
type ObservationStatus string

const (
	StatusConfirmed   ObservationStatus = "CONFIRMED"
	StatusObserved    ObservationStatus = "OBSERVED"
	StatusInferred    ObservationStatus = "INFERRED"
	StatusNotAssessed ObservationStatus = "NOT_ASSESSED"
	StatusFixed       ObservationStatus = "FIXED"
)

// Category groups findings by security domain.
type Category string

const (
	CategoryTransportSecurity    Category = "TRANSPORT_SECURITY"
	CategoryCryptography         Category = "CRYPTOGRAPHY"
	CategoryDNSConfiguration     Category = "DNS_CONFIGURATION"
	CategoryEmailSecurity        Category = "EMAIL_SECURITY"
	CategoryCookieSecurity       Category = "COOKIE_SECURITY"
	CategorySecurityMetadata     Category = "SECURITY_METADATA"
	CategoryInformationDisclosure Category = "INFORMATION_DISCLOSURE"
	CategoryNetworkPosture       Category = "NETWORK_POSTURE"
)

// EvidenceType represents the origin of the verifiable proof.
type EvidenceType string

const (
	EvidenceHTTPExchange        EvidenceType = "HTTP_EXCHANGE"
	EvidenceDNSRecord           EvidenceType = "DNS_RECORD"
	EvidenceTLSHandshake        EvidenceType = "TLS_HANDSHAKE"
	EvidenceCertificateMetadata EvidenceType = "CERTIFICATE_METADATA"
	EvidenceRawSocket           EvidenceType = "RAW_SOCKET"
	EvidenceSecurityTxt         EvidenceType = "SECURITY_TXT"
)

// Evidence contains raw verifiable data.
type Evidence struct {
	Type      EvidenceType           `json:"type"`
	Summary   string                 `json:"summary"`
	Request   map[string]interface{} `json:"request,omitempty"`
	Response  map[string]interface{} `json:"response,omitempty"`
	RawData   map[string]interface{} `json:"raw_data,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// Finding represents a single security observation.
type Finding struct {
	ID                  string            `json:"id"`
	Probe               string            `json:"probe"`
	Target              string            `json:"target"`
	Category            Category          `json:"category"`
	Severity            Severity          `json:"severity"`
	Confidence          Confidence        `json:"confidence"`
	Status              ObservationStatus `json:"status"`
	Title               string            `json:"title"`
	Description         string            `json:"description"`
	ImpactExplanation   string            `json:"impact_explanation,omitempty"`
	Remediation         string            `json:"remediation"`
	VerificationCommand string            `json:"verification_command,omitempty"`
	CWEID               string            `json:"cwe_id,omitempty"`
	CVEID               string            `json:"cve_id,omitempty"`
	Evidence            Evidence          `json:"evidence"`
	Timestamp           time.Time         `json:"timestamp"`
}

// NotAssessedArea documents explicit out-of-scope boundaries.
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
	OverallScore            int                      `json:"overall_score"`
	LetterGrade             string                   `json:"letter_grade"`
	CategoryScores          map[string]CategoryScore `json:"category_scores"`
	ConfirmedFlawsCount     int                      `json:"confirmed_flaws_count"`
	ObservedPropertiesCount int                      `json:"observed_properties_count"`
	NotAssessedBoundaries   []NotAssessedArea        `json:"not_assessed_boundaries"`
}

// TargetScope defines target attributes and safety flags.
type TargetScope struct {
	RawTarget     string   `json:"raw_target"`
	NormalizedURL string   `json:"normalized_url"`
	Scheme        string   `json:"scheme"`
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	ResolvedIPs   []string `json:"resolved_ips"`
	IsPrivate     bool     `json:"is_private"`
	AllowPrivate  bool     `json:"allow_private"`
}

// ProbeStatus tracks probe execution lifecycle.
type ProbeStatus struct {
	ProbeName       string  `json:"probe_name"`
	Status          string  `json:"status"` // "completed", "failed", "cancelled"
	DurationSeconds float64 `json:"duration_seconds"`
	ErrorMessage    string  `json:"error_message,omitempty"`
}

// ScanResult is the root report output.
type ScanResult struct {
	ScanID          string            `json:"scan_id"`
	Target          TargetScope       `json:"target"`
	StartTime       time.Time         `json:"start_time"`
	EndTime         *time.Time        `json:"end_time,omitempty"`
	DurationSeconds float64           `json:"duration_seconds"`
	ScoreCard       *ScoreCard        `json:"score_card,omitempty"`
	ProbeStatuses   []ProbeStatus     `json:"probe_statuses"`
	Findings        []Finding         `json:"findings"`
	SeverityCounts  map[string]int    `json:"severity_counts"`
}
