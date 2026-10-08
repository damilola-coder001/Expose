package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/expose/expose/apps/api/internal/domain"
	"github.com/expose/expose/apps/api/internal/scope"
)

var (
	ErrExecutionTimeout    = errors.New("nuclei scan execution exceeded timeout threshold")
	ErrScanCancelled       = errors.New("nuclei scan was cancelled by operator")
	ErrWorkerOverloaded    = errors.New("nuclei scanning worker pool at maximum concurrency limit")
	ErrScopeValidationFail = errors.New("target scope validation rejected the destination")
)

// WorkerConfig defines execution boundaries and isolation limits.
type WorkerConfig struct {
	MaxConcurrency int
	Timeout        time.Duration
	BinaryPath     string
}

// DefaultConfig returns safe production defaults.
func DefaultConfig() WorkerConfig {
	return WorkerConfig{
		MaxConcurrency: 3,
		Timeout:        30 * time.Second,
		BinaryPath:     "nuclei",
	}
}

// Worker coordinates safe, isolated Nuclei scanner operations.
type Worker struct {
	cfg        WorkerConfig
	sem        chan struct{}
	mu         sync.Mutex
	binaryPath string
	hasBinary  bool
}

// NewWorker initializes a Nuclei execution worker with strict concurrency limits.
func NewWorker(cfg WorkerConfig) *Worker {
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = 3
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}

	binPath, err := exec.LookPath(cfg.BinaryPath)
	hasBin := err == nil

	return &Worker{
		cfg:        cfg,
		sem:        make(chan struct{}, cfg.MaxConcurrency),
		binaryPath: binPath,
		hasBinary:  hasBin,
	}
}

// GetVersionMetadata returns tracked scanner and template versioning.
func (w *Worker) GetVersionMetadata() VersionMetadata {
	return CurrentVersion
}

// HasBinary reports whether the real Nuclei binary was discovered on PATH.
func (w *Worker) HasBinary() bool {
	return w.hasBinary
}

// ScanJob represents an incoming scanning request.
type ScanJob struct {
	ScanID      string
	TargetURL   string
	TemplateIDs []string
}

// ExecuteScan executes approved scanner operations within strict isolation boundaries.
func (w *Worker) ExecuteScan(ctx context.Context, job ScanJob) ([]domain.Finding, error) {
	// 1. Target Scope Validation (SSRF & RFC1918 Protection)
	validTarget, err := scope.Validate(job.TargetURL, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %s (%v)", ErrScopeValidationFail, job.TargetURL, err)
	}

	// 2. Approved Template Whitelisting (Reject arbitrary user templates)
	approvedTemplates, err := ValidateTemplates(job.TemplateIDs)
	if err != nil {
		return nil, err
	}
	if len(approvedTemplates) == 0 {
		return nil, ErrEmptyTemplateSelection
	}

	// 3. Concurrency Limiting (Worker Isolation)
	select {
	case w.sem <- struct{}{}:
		defer func() { <-w.sem }()
	case <-ctx.Done():
		return nil, ErrScanCancelled
	default:
		return nil, ErrWorkerOverloaded
	}

	// 4. Bounded Context Timeout
	scanCtx, cancel := context.WithTimeout(ctx, w.cfg.Timeout)
	defer cancel()

	// 5. Execution Pipeline
	if w.hasBinary {
		return w.runBinary(scanCtx, job.ScanID, validTarget.NormalizedURL, approvedTemplates)
	}

	// 6. Safe Native Probe Fallback
	// When the nuclei binary is not pre-packaged in the runtime container, execute
	// the approved safe template checks using safe network socket transport.
	return w.runNativeFallback(scanCtx, job.ScanID, validTarget.NormalizedURL, approvedTemplates)
}

// runBinary invokes the isolated nuclei CLI subprocess with non-destructive flags.
func (w *Worker) runBinary(ctx context.Context, scanID, targetURL string, templates []ApprovedTemplate) ([]domain.Finding, error) {
	var templatePaths []string
	for _, t := range templates {
		templatePaths = append(templatePaths, "-t", t.Path)
	}

	args := append([]string{
		"-u", targetURL,
		"-jsonl",
		"-silent",
		"-timeout", "10",
		"-no-interactsh",
		"-max-host-error", "3",
	}, templatePaths...)

	cmd := exec.CommandContext(ctx, w.binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, ErrExecutionTimeout
		}
		if ctx.Err() == context.Canceled {
			return nil, ErrScanCancelled
		}
		// Non-zero exit code might simply mean no vulnerabilities found or minor network timeout
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("nuclei execution error: %w (stderr: %s)", err, stderr.String())
		}
	}

	return w.parseJSONLOutput(scanID, &stdout)
}

// parseJSONLOutput parses raw JSONL stream from Nuclei and normalizes each record.
func (w *Worker) parseJSONLOutput(scanID string, reader io.Reader) ([]domain.Finding, error) {
	var findings []domain.Finding
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		finding, err := NormalizeNucleiRecord(line, scanID)
		if err != nil {
			// Skip malformed record, log error in production
			continue
		}
		findings = append(findings, *finding)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading nuclei output: %w", err)
	}

	return findings, nil
}

// runNativeFallback simulates the safe approved templates directly via safe transport
// ensuring the platform functions out-of-the-box in environments lacking the nuclei binary.
func (w *Worker) runNativeFallback(ctx context.Context, scanID, targetURL string, templates []ApprovedTemplate) ([]domain.Finding, error) {
	var findings []domain.Finding
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	trimmedURL := strings.TrimRight(targetURL, "/")

	for _, t := range templates {
		select {
		case <-ctx.Done():
			return nil, ErrScanCancelled
		default:
		}

		switch t.ID {
		case "git-config-exposure":
			testURL := trimmedURL + "/.git/config"
			req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Expose-Security-Intelligence/1.0")

			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
				bodyStr := string(body)

				// Empirical proof: HTTP 200 and git config syntax
				if resp.StatusCode == http.StatusOK && strings.Contains(bodyStr, "[core]") {
					rawJSON := fmt.Sprintf(`{
						"template-id": "git-config-exposure",
						"info": {
							"name": "Git Configuration File Exposure",
							"severity": "medium",
							"description": "Publicly exposed .git/config file leaking repository branches, remotes, and commit metadata.",
							"reference": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"],
							"classification": {"cwe-id": ["CWE-200"]}
						},
						"type": "http",
						"matched-at": %q,
						"extracted-results": ["[core] section detected"],
						"response": %q,
						"curl-command": %q
					}`, testURL, "HTTP/1.1 200 OK\n\n"+bodyStr, "curl -sIL "+testURL)

					if f, err := NormalizeNucleiRecord([]byte(rawJSON), scanID); err == nil {
						findings = append(findings, *f)
					}
				}
			}

		case "env-file-exposure":
			testURL := trimmedURL + "/.env"
			req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Expose-Security-Intelligence/1.0")

			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
				bodyStr := string(body)

				// Must look like genuine env file with KEY=VALUE pairs, not a generic 200 HTML error page
				if resp.StatusCode == http.StatusOK && !strings.Contains(bodyStr, "<html") && strings.Contains(bodyStr, "=") {
					rawJSON := fmt.Sprintf(`{
						"template-id": "env-file-exposure",
						"info": {
							"name": "Environment (.env) Configuration File Exposure",
							"severity": "high",
							"description": "Publicly accessible .env file revealing internal configuration secrets and database credentials.",
							"reference": ["https://cwe.mitre.org/data/definitions/200.html"],
							"classification": {"cwe-id": ["CWE-200"], "cve-id": ["CVE-2017-9841"]}
						},
						"type": "http",
						"matched-at": %q,
						"extracted-results": ["Environment variable declaration observed"],
						"response": %q,
						"curl-command": %q
					}`, testURL, "HTTP/1.1 200 OK\n\n"+bodyStr, "curl -sIL "+testURL)

					if f, err := NormalizeNucleiRecord([]byte(rawJSON), scanID); err == nil {
						findings = append(findings, *f)
					}
				}
			}

		case "server-status-exposure":
			testURL := trimmedURL + "/server-status"
			req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Expose-Security-Intelligence/1.0")

			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
				bodyStr := string(body)

				if resp.StatusCode == http.StatusOK && strings.Contains(bodyStr, "Apache Server Status") {
					rawJSON := fmt.Sprintf(`{
						"template-id": "server-status-exposure",
						"info": {
							"name": "Apache Server Status Page Exposed",
							"severity": "low",
							"description": "The Apache mod_status endpoint is publicly exposed, disclosing server metrics and active requests.",
							"reference": ["https://httpd.apache.org/docs/current/mod/mod_status.html"],
							"classification": {"cwe-id": ["CWE-200"]}
						},
						"type": "http",
						"matched-at": %q,
						"extracted-results": ["Apache Server Status banner"],
						"response": %q,
						"curl-command": %q
					}`, testURL, "HTTP/1.1 200 OK\n\n"+bodyStr, "curl -sIL "+testURL)

					if f, err := NormalizeNucleiRecord([]byte(rawJSON), scanID); err == nil {
						findings = append(findings, *f)
					}
				}
			}
		}
	}

	return findings, nil
}
