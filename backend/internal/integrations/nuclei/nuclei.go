package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/expose/expose-backend/internal/models"
	"github.com/expose/expose-backend/internal/probes"
)

// Runner manages safe, non-destructive execution of the Nuclei component.
// Nuclei is a modular probe component of Expose, not the platform itself.
type Runner struct {
	binaryPath   string
	maxRateLimit int // Max requests per second
}

func NewRunner() *Runner {
	path, err := exec.LookPath("nuclei")
	if err != nil {
		path = "" // Not installed in current environment
	}
	return &Runner{
		binaryPath:   path,
		maxRateLimit: 5, // Strict safe rate limit per safety model
	}
}

func (r *Runner) IsAvailable() bool {
	return r.binaryPath != ""
}

// NucleiJSONLine represents the structured output from nuclei -jsonl.
type NucleiJSONLine struct {
	TemplateID   string `json:"template-id"`
	Info         struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Reference   []string `json:"reference"`
		Tags        []string `json:"tags"`
		Remediation string   `json:"remediation"`
	} `json:"info"`
	MatchedAt    string `json:"matched-at"`
	Type         string `json:"type"`
	ExtractedResults []string `json:"extracted-results"`
	Request      string `json:"request"`
	Response     string `json:"response"`
}

// ExecuteSafeRun executes safe, non-invasive informational/misconfiguration checks.
func (r *Runner) ExecuteSafeRun(ctx context.Context, target *models.TargetScope) ([]models.Finding, error) {
	if !r.IsAvailable() {
		// Nuclei component is optional and skipped gracefully if binary is not installed
		return nil, nil
	}

	// Safe tags only: misconfiguration, exposure, ssl, dns, tech. (NO rce, sqli, fuzz, dos)
	safeTags := "misconfig,exposure,ssl,dns,tech"

	args := []string{
		"-target", target.NormalizedURL,
		"-silent",
		"-jsonl",
		"-rate-limit", fmt.Sprintf("%d", r.maxRateLimit),
		"-concurrency", "2",
		"-timeout", "5",
		"-tags", safeTags,
		"-severity", "info,low,medium,high",
	}

	cmd := exec.CommandContext(ctx, r.binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}

	var findings []models.Finding
	scanner := bufio.NewScanner(&stdout)

	for scanner.Scan() {
		var line NucleiJSONLine
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
			continue
		}

		sev := mapSeverity(line.Info.Severity)
		evidence := models.Evidence{
			Type:    models.EvidenceHTTPExchange,
			Summary: fmt.Sprintf("Nuclei component matched template '%s' at %s", line.TemplateID, line.MatchedAt),
			RawData: map[string]interface{}{
				"template_id":       line.TemplateID,
				"tags":              line.Info.Tags,
				"extracted_results": line.ExtractedResults,
			},
		}
		if line.Request != "" {
			evidence.Request = map[string]interface{}{"raw": line.Request}
		}
		if line.Response != "" {
			evidence.Response = map[string]interface{}{"raw_excerpt": line.Response[:min(len(line.Response), 500)]}
		}

		finding := probes.CreateFinding(
			"nuclei_component",
			target,
			models.CategoryInformationDisclosure,
			sev,
			models.ConfidenceConfirmed,
			models.StatusConfirmed,
			line.Info.Name,
			line.Info.Description,
			"Observed and verified by Nuclei component safe template execution.",
			line.Info.Remediation,
			fmt.Sprintf("nuclei -u %s -id %s", target.NormalizedURL, line.TemplateID),
			"",
			"",
			evidence,
		)
		findings = append(findings, finding)
	}

	return findings, nil
}

func mapSeverity(sev string) models.Severity {
	switch strings.ToLower(sev) {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	case "low":
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
