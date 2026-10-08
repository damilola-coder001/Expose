package nuclei

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/expose/expose/apps/api/internal/domain"
)

func TestTemplateCatalogValidation(t *testing.T) {
	// 1. Default (empty) request returns all approved templates
	all, err := ValidateTemplates(nil)
	if err != nil {
		t.Fatalf("expected nil error for default catalog, got: %v", err)
	}
	if len(all) == 0 {
		t.Errorf("expected approved templates in default catalog, got 0")
	}

	// 2. Valid template selection
	valid, err := ValidateTemplates([]string{"git-config-exposure", "env-file-exposure"})
	if err != nil {
		t.Fatalf("expected valid templates to pass, got: %v", err)
	}
	if len(valid) != 2 {
		t.Errorf("expected 2 valid templates, got %d", len(valid))
	}

	// 3. Arbitrary URL rejection
	_, err = ValidateTemplates([]string{"https://evil.com/exploit.yaml"})
	if err == nil || !strings.Contains(err.Error(), ErrArbitraryTemplateNotAllowed.Error()) {
		t.Errorf("expected ErrArbitraryTemplateNotAllowed for URL, got: %v", err)
	}

	// 4. Directory traversal rejection
	_, err = ValidateTemplates([]string{"../../etc/passwd"})
	if err == nil || !strings.Contains(err.Error(), ErrArbitraryTemplateNotAllowed.Error()) {
		t.Errorf("expected ErrArbitraryTemplateNotAllowed for path traversal, got: %v", err)
	}

	// 5. Unknown template rejection
	_, err = ValidateTemplates([]string{"nonexistent-exploit-template"})
	if err == nil || !strings.Contains(err.Error(), ErrTemplateNotFound.Error()) {
		t.Errorf("expected ErrTemplateNotFound for unknown template, got: %v", err)
	}
}

func TestNormalizeNucleiRecord(t *testing.T) {
	rawJSON := `{
		"template-id": "git-config-exposure",
		"info": {
			"name": "Git Config File Exposure",
			"author": ["author1"],
			"severity": "medium",
			"description": "Exposed git config leaking repository credentials.",
			"reference": ["https://owasp.org/reference", "https://cwe.mitre.org"],
			"remediation": "Deny access to .git directory.",
			"classification": {
				"cve-id": ["CVE-2020-0001"],
				"cwe-id": ["CWE-200"],
				"cvss-score": 5.3
			}
		},
		"type": "http",
		"host": "example.com",
		"matched-at": "https://example.com/.git/config",
		"extracted-results": ["[core]\nrepositoryformatversion = 0"],
		"request": "GET /.git/config HTTP/1.1\nHost: example.com\n\n",
		"response": "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n[core]",
		"curl-command": "curl -sI https://example.com/.git/config",
		"timestamp": "2026-09-09T14:00:00Z"
	}`

	scanID := "scan_test_123"
	finding, err := NormalizeNucleiRecord([]byte(rawJSON), scanID)
	if err != nil {
		t.Fatalf("NormalizeNucleiRecord failed: %v", err)
	}

	if finding.ScanID != scanID {
		t.Errorf("expected scanID %q, got %q", scanID, finding.ScanID)
	}
	if finding.Severity != domain.SeverityMedium {
		t.Errorf("expected severity MEDIUM, got %v", finding.Severity)
	}
	// Because HTTP 200 OK and extracted result are present, confidence should be CONFIRMED
	if finding.Confidence != domain.ConfidenceConfirmed {
		t.Errorf("expected confidence CONFIRMED for verified wire proof, got %v", finding.Confidence)
	}
	if finding.Status != domain.StatusConfirmed {
		t.Errorf("expected status CONFIRMED, got %v", finding.Status)
	}
	if finding.Category != domain.CategoryExternalExposure {
		t.Errorf("expected category EXTERNAL_EXPOSURE, got %v", finding.Category)
	}
	if len(finding.References) != 2 {
		t.Errorf("expected 2 references, got %d", len(finding.References))
	}
	if finding.CVE != "CVE-2020-0001" {
		t.Errorf("expected CVE-2020-0001, got %v", finding.CVE)
	}
	if finding.Verification.Command != "curl -sI https://example.com/.git/config" {
		t.Errorf("expected curl verification command, got %v", finding.Verification.Command)
	}
}

func TestTheoreticalWeaknessConfidenceDistinction(t *testing.T) {
	// When a finding is reported but without 200 OK wire response or without extracted content,
	// confidence must NOT be CONFIRMED even if severity is high.
	rawJSON := `{
		"template-id": "tech-detect",
		"info": {
			"name": "PHP Technology Detected",
			"severity": "info",
			"description": "Server runs PHP 8.1."
		},
		"type": "http",
		"matched-at": "https://example.com/",
		"response": "HTTP/1.1 200 OK"
	}`

	finding, err := NormalizeNucleiRecord([]byte(rawJSON), "scan_info_1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if finding.Confidence != domain.ConfidenceInformational {
		t.Errorf("expected ConfidenceInformational for info severity, got %v", finding.Confidence)
	}
}

func TestWorkerConcurrencyLimits(t *testing.T) {
	cfg := WorkerConfig{
		MaxConcurrency: 1,
		Timeout:        2 * time.Second,
		BinaryPath:     "nuclei-nonexistent",
	}

	worker := NewWorker(cfg)

	// Hold the single concurrency slot
	worker.sem <- struct{}{}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	job := ScanJob{
		ScanID:      "scan_concurrency",
		TargetURL:   "https://example.com",
		TemplateIDs: []string{"git-config-exposure"},
	}

	_, err := worker.ExecuteScan(ctx, job)
	if err != ErrWorkerOverloaded && err != ErrScanCancelled {
		t.Errorf("expected ErrWorkerOverloaded or ErrScanCancelled, got %v", err)
	}

	// Release semaphore
	<-worker.sem
}
