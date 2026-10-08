package nuclei

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/expose/expose/apps/api/internal/domain"
)

// RawNucleiRecord models the JSON output emitted by Nuclei in -jsonl mode.
type RawNucleiRecord struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string   `json:"name"`
		Author         any      `json:"author"`
		Severity       string   `json:"severity"`
		Description    string   `json:"description"`
		Reference      any      `json:"reference"`
		Remediation    string   `json:"remediation"`
		Classification struct {
			CVEID       any     `json:"cve-id"`
			CWEID       any     `json:"cwe-id"`
			CVSSMetrics string  `json:"cvss-metrics"`
			CVSSScore   float64 `json:"cvss-score"`
		} `json:"classification"`
		Metadata map[string]interface{} `json:"metadata"`
		Tags     any                    `json:"tags"`
	} `json:"info"`
	Type             string    `json:"type"`
	Host             string    `json:"host"`
	Port             string    `json:"port"`
	Scheme           string    `json:"scheme"`
	URL              string    `json:"url"`
	MatchedAt        string    `json:"matched-at"`
	ExtractedResults []string  `json:"extracted-results"`
	Request          string    `json:"request"`
	Response         string    `json:"response"`
	CurlCommand      string    `json:"curl-command"`
	Timestamp        time.Time `json:"timestamp"`
}

// NormalizeNucleiRecord transforms a raw Nuclei JSONL record into a standardized Expose domain.Finding.
// Enforces the core rule: Evidence first. Intelligence second.
// Distinguishes Severity from Confidence explicitly:
// A theoretical or banner-detected finding is never marked CONFIRMED unless empirical proof is present.
func NormalizeNucleiRecord(data []byte, scanID string) (*domain.Finding, error) {
	var raw RawNucleiRecord
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to decode nuclei jsonl record: %w", err)
	}

	if raw.TemplateID == "" {
		return nil, fmt.Errorf("invalid nuclei record: missing template-id")
	}

	severity := mapSeverity(raw.Info.Severity)
	confidence := determineConfidence(&raw)
	category := mapCategory(raw.TemplateID, raw.Type)
	findingID := generateNucleiFindingID(scanID, raw.TemplateID, raw.MatchedAt)

	// Extract references
	references := extractReferences(raw.Info.Reference)

	// Extract CWE and CVE
	cwe := extractStringOrList(raw.Info.Classification.CWEID)
	cve := extractStringOrList(raw.Info.Classification.CVEID)

	// Evidence compilation
	matchedSnippet := ""
	if len(raw.ExtractedResults) > 0 {
		matchedSnippet = strings.Join(raw.ExtractedResults, "; ")
	} else if raw.MatchedAt != "" {
		matchedSnippet = raw.MatchedAt
	}

	evidenceSummary := fmt.Sprintf("Template %q matched at %s", raw.TemplateID, raw.MatchedAt)
	if raw.CurlCommand != "" {
		evidenceSummary += fmt.Sprintf(" (verified via curl: %s)", raw.CurlCommand)
	}

	evidence := domain.Evidence{
		Type:        domain.EvidenceNucleiMatch,
		Summary:     evidenceSummary,
		MatchedData: matchedSnippet,
		Command:     raw.CurlCommand,
		Timestamp:   raw.Timestamp,
	}

	if evidence.Timestamp.IsZero() {
		evidence.Timestamp = time.Now().UTC()
	}

	// Request/Response evidence truncation for memory safety
	if raw.Request != "" {
		evidence.Request = map[string]interface{}{
			"raw_wire": truncateString(raw.Request, 2048),
		}
	}
	if raw.Response != "" {
		evidence.RawData = map[string]interface{}{
			"raw_response_snippet": truncateString(raw.Response, 2048),
			"matched_at":            raw.MatchedAt,
		}
	}

	// Build Recommendation
	remediation := raw.Info.Remediation
	if remediation == "" {
		remediation = fmt.Sprintf("Review configuration for %s and restrict public access to %s.", raw.Info.Name, raw.MatchedAt)
	}

	recommendation := domain.Recommendation{
		Summary:         fmt.Sprintf("Remediate exposure identified by %s.", raw.Info.Name),
		Remediation:     remediation,
		ResearchSources: references,
	}

	// Impact assessment
	impact := buildImpact(&raw, severity)

	// Observation Status
	status := domain.StatusObserved
	if confidence == domain.ConfidenceConfirmed {
		status = domain.StatusConfirmed
	}

	verificationCmd := raw.CurlCommand
	if verificationCmd == "" {
		verificationCmd = fmt.Sprintf("curl -sIL %q", raw.MatchedAt)
	}

	finding := &domain.Finding{
		ID:             findingID,
		ScanID:         scanID,
		Title:          raw.Info.Name,
		Description:    raw.Info.Description,
		Severity:       severity,
		Confidence:     confidence,
		Status:         status,
		Category:       category,
		RuleID:         fmt.Sprintf("NUCLEI_%s", strings.ToUpper(strings.ReplaceAll(raw.TemplateID, "-", "_"))),
		OWASPMapping:   "A05:2021-Security Misconfiguration",
		CWE:            cwe,
		CVE:            cve,
		Evidence:       evidence,
		Impact:         impact,
		Recommendation: recommendation,
		References:     references,
		Verification: domain.Verification{
			Command:     verificationCmd,
			Tool:        "curl",
			Description: "Replay HTTP request to observe server response",
		},
		CreatedAt: time.Now().UTC(),
	}

	return finding, nil
}

func mapSeverity(raw string) domain.Severity {
	switch strings.ToLower(raw) {
	case "critical":
		return domain.SeverityCritical
	case "high":
		return domain.SeverityHigh
	case "medium":
		return domain.SeverityMedium
	case "low":
		return domain.SeverityLow
	case "info":
		return domain.SeverityInfo
	default:
		return domain.SeverityLow
	}
}

// determineConfidence enforces:
// "Do not use severity as a substitute for confidence. A theoretical weakness should not be presented as a confirmed vulnerability."
func determineConfidence(raw *RawNucleiRecord) domain.Confidence {
	// If it's purely informational technology fingerprinting
	if strings.ToLower(raw.Info.Severity) == "info" {
		return domain.ConfidenceInformational
	}

	// If HTTP response wire data contains HTTP 200 OK and extracted results prove the leak
	has200OK := strings.Contains(raw.Response, "200 OK") || strings.Contains(raw.Response, "HTTP/1.1 200") || strings.Contains(raw.Response, "HTTP/2 200")
	hasExtractedContent := len(raw.ExtractedResults) > 0

	if has200OK && hasExtractedContent {
		// Verifiable wire content extracted
		return domain.ConfidenceConfirmed
	}

	if has200OK {
		// URL reached with 200 OK, but without extracted regex confirmation
		return domain.ConfidenceLikely
	}

	// Passive observation or status mismatch
	return domain.ConfidencePotential
}

func mapCategory(templateID, protocol string) domain.Category {
	tid := strings.ToLower(templateID)
	switch {
	case strings.Contains(tid, "ssl") || strings.Contains(tid, "tls"):
		return domain.CategoryTransportSecurity
	case strings.Contains(tid, "dns") || protocol == "dns":
		return domain.CategoryNetworkPosture
	case strings.Contains(tid, "cors") || strings.Contains(tid, "header"):
		return domain.CategoryHTTPHeaders
	case strings.Contains(tid, "cookie"):
		return domain.CategoryCookieSecurity
	case strings.Contains(tid, "git") || strings.Contains(tid, "env") || strings.Contains(tid, "backup") || strings.Contains(tid, "exposure"):
		return domain.CategoryExternalExposure
	case strings.Contains(tid, "tech") || strings.Contains(tid, "detect"):
		return domain.CategoryInformationDisclosure
	default:
		return domain.CategoryExternalExposure
	}
}

func extractReferences(refField any) []domain.ResearchSource {
	var sources []domain.ResearchSource
	if refField == nil {
		return sources
	}

	switch v := refField.(type) {
	case string:
		if strings.HasPrefix(v, "http") {
			sources = append(sources, domain.ResearchSource{Name: "Reference", URL: v})
		}
	case []interface{}:
		for _, item := range v {
			if str, ok := item.(string); ok && strings.HasPrefix(str, "http") {
				sources = append(sources, domain.ResearchSource{Name: "Reference", URL: str})
			}
		}
	case []string:
		for _, str := range v {
			if strings.HasPrefix(str, "http") {
				sources = append(sources, domain.ResearchSource{Name: "Reference", URL: str})
			}
		}
	}
	return sources
}

func extractStringOrList(field any) string {
	if field == nil {
		return ""
	}
	switch v := field.(type) {
	case string:
		return v
	case []interface{}:
		var items []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				items = append(items, s)
			}
		}
		return strings.Join(items, ", ")
	case []string:
		return strings.Join(v, ", ")
	default:
		return fmt.Sprintf("%v", v)
	}
}

func buildImpact(raw *RawNucleiRecord, severity domain.Severity) string {
	tid := strings.ToLower(raw.TemplateID)
	switch {
	case strings.Contains(tid, "env"):
		return "Critical exposure: .env files frequently contain database passwords, API credentials, and cryptographic secret keys."
	case strings.Contains(tid, "git"):
		return "High exposure: .git directory leakage allows complete reconstruction of source code and commits, exposing proprietary logic and embedded secrets."
	case strings.Contains(tid, "backup"):
		return "High exposure: Backup archive files (.sql, .tar.gz) often contain database dumps and full filesystem contents."
	case strings.Contains(tid, "cors"):
		return "Medium security misconfiguration: Insecure wildcard or reflected Access-Control-Allow-Origin headers allow malicious sites to read sensitive responses."
	case strings.Contains(tid, "server-status"):
		return "Low information disclosure: Server status monitors reveal active client requests, backend IP addresses, and traffic metrics."
	default:
		switch severity {
		case domain.SeverityCritical:
			return "Direct compromise of host confidentiality, integrity, or service availability."
		case domain.SeverityHigh:
			return "Significant exposure of sensitive assets or authentication vectors."
		case domain.SeverityMedium:
			return "Misconfiguration providing attackers with pivot or reconnaissance advantages."
		default:
			return "Externally observable configuration anomaly or information disclosure."
		}
	}
}

func generateNucleiFindingID(scanID, templateID, matchedAt string) string {
	h := sha256.New()
	h.Write([]byte(scanID + ":" + templateID + ":" + matchedAt))
	return "fnd_nuc_" + hex.EncodeToString(h.Sum(nil))[:16]
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + " ...[truncated]"
}
