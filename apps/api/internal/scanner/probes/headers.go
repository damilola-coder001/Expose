package probes

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/expose/expose/apps/api/internal/domain"
	"github.com/expose/expose/apps/api/internal/scope"
)

type HeadersProbe struct{}

func NewHeadersProbe() *HeadersProbe {
	return &HeadersProbe{}
}

func (p *HeadersProbe) Name() string {
	return "security_headers"
}

func (p *HeadersProbe) Run(ctx context.Context, target *scope.TargetScope) (*ProbeResult, error) {
	start := time.Now()
	res := &ProbeResult{
		ProbeName: p.Name(),
		Findings:  make([]domain.Finding, 0),
		Assets:    make([]domain.Asset, 0),
	}

	client := scope.NewSafeHTTPClient(8*time.Second, target.AllowPrivate)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.NormalizedURL, nil)
	if err != nil {
		res.Duration = time.Since(start)
		res.Error = err
		return res, err
	}
	req.Header.Set("User-Agent", "Expose-Security-Scanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		res.Duration = time.Since(start)
		res.Error = err
		return res, nil
	}
	defer resp.Body.Close()

	headers := extractHeaders(resp.Header)
	statusLine := fmt.Sprintf("%s %d %s", resp.Proto, resp.StatusCode, http.StatusText(resp.StatusCode))

	// 1. Strict-Transport-Security (HSTS)
	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		res.Findings = append(res.Findings, domain.Finding{
			ID:          GenerateFindingID("fnd_hsts_missing"),
			Title:       "Missing HTTP Strict Transport Security (HSTS)",
			Description: "The Strict-Transport-Security header is missing, allowing browsers to downgrade connections to insecure plaintext HTTP.",
			Severity:    domain.SeverityHigh,
			Confidence:  domain.ConfidenceConfirmed,
			Status:      domain.StatusConfirmed,
			Category:    domain.CategoryHTTPHeaders,
			RuleID:      "HSTS_MISSING",
			OWASPMapping: "A05:2021-Security Misconfiguration",
			ASVSMapping:  "V14.4.5",
			CWE:         "CWE-523",
			Evidence: domain.Evidence{
				Type:            domain.EvidenceHTTPExchange,
				Summary:         fmt.Sprintf("Observed %s with strict-transport-security: missing", statusLine),
				Request:         map[string]interface{}{"url": target.NormalizedURL, "method": "GET"},
				ResponseHeaders: headers,
				Timestamp:       time.Now().UTC(),
			},
			Impact: "Allows SSL-stripping and active MitM downgrade attacks against visitors.",
			Recommendation: domain.Recommendation{
				Summary:       "Enable HSTS with at least 1 year max-age.",
				Remediation:   "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
				ConfigSnippet: "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
			},
			Verification: domain.Verification{
				Command:     fmt.Sprintf("curl -sI %s | grep -i '^strict-transport-security:'", target.NormalizedURL),
				Tool:        "curl",
				Description: "Check for presence of HSTS header",
			},
			CreatedAt: time.Now().UTC(),
		})
	} else {
		// Check max-age
		maxAgeRegex := regexp.MustCompile(`max-age=(\d+)`)
		match := maxAgeRegex.FindStringSubmatch(strings.ToLower(hsts))
		if len(match) > 1 {
			seconds, _ := strconv.Atoi(match[1])
			if seconds < 31536000 {
				res.Findings = append(res.Findings, domain.Finding{
					ID:          GenerateFindingID("fnd_hsts_short_maxage"),
					Title:       "HSTS max-age Is Insufficient",
					Description: fmt.Sprintf("HSTS max-age is set to %d seconds (less than the recommended 31536000 seconds / 1 year).", seconds),
					Severity:    domain.SeverityMedium,
					Confidence:  domain.ConfidenceConfirmed,
					Status:      domain.StatusObserved,
					Category:    domain.CategoryHTTPHeaders,
					RuleID:      "HSTS_SHORT_MAX_AGE",
					OWASPMapping: "A05:2021-Security Misconfiguration",
					ASVSMapping:  "V14.4.5",
					CWE:         "CWE-523",
					Evidence: domain.Evidence{
						Type:            domain.EvidenceHTTPExchange,
						Summary:         fmt.Sprintf("Strict-Transport-Security: %s", hsts),
						ResponseHeaders: headers,
						Timestamp:       time.Now().UTC(),
					},
					Impact: "Browsers may prematurely forget the HTTPS-only policy between user visits.",
					Recommendation: domain.Recommendation{
						Summary:     "Increase HSTS max-age to 31536000 seconds.",
						Remediation: "Update Strict-Transport-Security to max-age=31536000.",
					},
					Verification: domain.Verification{
						Command:     fmt.Sprintf("curl -sI %s | grep -i '^strict-transport-security:'", target.NormalizedURL),
						Tool:        "curl",
						Description: "Inspect HSTS max-age parameter",
					},
					CreatedAt: time.Now().UTC(),
				})
			} else {
				res.Findings = append(res.Findings, domain.Finding{
					ID:          GenerateFindingID("fnd_hsts_valid"),
					Title:       "HSTS Header Configured Correctly",
					Description: fmt.Sprintf("HSTS header observed with adequate duration: %s.", hsts),
					Severity:    domain.SeverityInfo,
					Confidence:  domain.ConfidenceConfirmed,
					Status:      domain.StatusObserved,
					Category:    domain.CategoryHTTPHeaders,
					RuleID:      "HSTS_CONFIGURED",
					OWASPMapping: "A05:2021-Security Misconfiguration",
					ASVSMapping:  "V14.4.5",
					CWE:         "CWE-523",
					Evidence: domain.Evidence{
						Type:            domain.EvidenceHTTPExchange,
						Summary:         fmt.Sprintf("Strict-Transport-Security: %s", hsts),
						ResponseHeaders: headers,
						Timestamp:       time.Now().UTC(),
					},
					Impact: "Protects against connection downgrade and SSL stripping attacks.",
					Recommendation: domain.Recommendation{
						Summary:     "Maintain current HSTS configuration.",
						Remediation: "Ensure certificate renewals occur seamlessly before expiration.",
					},
					Verification: domain.Verification{
						Command:     fmt.Sprintf("curl -sI %s | grep -i '^strict-transport-security:'", target.NormalizedURL),
						Tool:        "curl",
						Description: "Confirm HSTS configuration",
					},
					CreatedAt: time.Now().UTC(),
				})
			}
		}
	}

	// 2. Content-Security-Policy (CSP)
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		res.Findings = append(res.Findings, domain.Finding{
			ID:          GenerateFindingID("fnd_csp_missing"),
			Title:       "Missing Content-Security-Policy (CSP)",
			Description: "No Content-Security-Policy header observed. Browsers cannot enforce resource whitelists or mitigate Cross-Site Scripting (XSS).",
			Severity:    domain.SeverityHigh,
			Confidence:  domain.ConfidenceConfirmed,
			Status:      domain.StatusConfirmed,
			Category:    domain.CategoryHTTPHeaders,
			RuleID:      "CSP_MISSING",
			OWASPMapping: "A05:2021-Security Misconfiguration",
			ASVSMapping:  "V14.4.3",
			CWE:         "CWE-1021",
			Evidence: domain.Evidence{
				Type:            domain.EvidenceHTTPExchange,
				Summary:         fmt.Sprintf("Observed %s with content-security-policy: missing", statusLine),
				ResponseHeaders: headers,
				Timestamp:       time.Now().UTC(),
			},
			Impact: "Increases exposure to stored and reflected Cross-Site Scripting (XSS) and data exfiltration.",
			Recommendation: domain.Recommendation{
				Summary:       "Implement a restrictive Content-Security-Policy.",
				Remediation:   "Define explicit default-src, script-src, style-src, and frame-ancestors directives.",
				ConfigSnippet: "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';\" always;",
			},
			Verification: domain.Verification{
				Command:     fmt.Sprintf("curl -sI %s | grep -i '^content-security-policy:'", target.NormalizedURL),
				Tool:        "curl",
				Description: "Check for Content-Security-Policy",
			},
			CreatedAt: time.Now().UTC(),
		})
	} else {
		// Check for dangerous directives
		lowerCSP := strings.ToLower(csp)
		if strings.Contains(lowerCSP, "'unsafe-inline'") || strings.Contains(lowerCSP, "'unsafe-eval'") {
			res.Findings = append(res.Findings, domain.Finding{
				ID:          GenerateFindingID("fnd_csp_unsafe"),
				Title:       "Weak CSP Directive Detected ('unsafe-inline' or 'unsafe-eval')",
				Description: "CSP contains permissive bypasses ('unsafe-inline' or 'unsafe-eval'), weakening XSS mitigations.",
				Severity:    domain.SeverityMedium,
				Confidence:  domain.ConfidenceConfirmed,
				Status:      domain.StatusObserved,
				Category:    domain.CategoryHTTPHeaders,
				RuleID:      "CSP_UNSAFE_DIRECTIVES",
				OWASPMapping: "A03:2021-Injection",
				ASVSMapping:  "V14.4.3",
				CWE:         "CWE-79",
				Evidence: domain.Evidence{
					Type:            domain.EvidenceHTTPExchange,
					Summary:         fmt.Sprintf("Content-Security-Policy: %s", csp),
					ResponseHeaders: headers,
					Timestamp:       time.Now().UTC(),
				},
				Impact: "Attacker-injected inline scripts may execute despite the presence of CSP.",
				Recommendation: domain.Recommendation{
					Summary:     "Refactor inline scripts to use cryptographic nonces or hashes.",
					Remediation: "Replace 'unsafe-inline' with nonce-based or hash-based script execution.",
				},
				Verification: domain.Verification{
					Command:     fmt.Sprintf("curl -sI %s | grep -i '^content-security-policy:'", target.NormalizedURL),
					Tool:        "curl",
					Description: "Inspect CSP directives",
				},
				CreatedAt: time.Now().UTC(),
			})
		}
	}

	// 3. X-Content-Type-Options
	xcto := resp.Header.Get("X-Content-Type-Options")
	if !strings.EqualFold(strings.TrimSpace(xcto), "nosniff") {
		res.Findings = append(res.Findings, domain.Finding{
			ID:          GenerateFindingID("fnd_xcto_missing"),
			Title:       "Missing or Misconfigured X-Content-Type-Options",
			Description: "X-Content-Type-Options is not set to 'nosniff', permitting MIME-type sniffing attacks.",
			Severity:    domain.SeverityMedium,
			Confidence:  domain.ConfidenceConfirmed,
			Status:      domain.StatusConfirmed,
			Category:    domain.CategoryHTTPHeaders,
			RuleID:      "X_CONTENT_TYPE_OPTIONS_MISSING",
			OWASPMapping: "A05:2021-Security Misconfiguration",
			ASVSMapping:  "V14.4.4",
			CWE:         "CWE-16",
			Evidence: domain.Evidence{
				Type:            domain.EvidenceHTTPExchange,
				Summary:         fmt.Sprintf("x-content-type-options observed value: %q (expected 'nosniff')", xcto),
				ResponseHeaders: headers,
				Timestamp:       time.Now().UTC(),
			},
			Impact: "Browsers may treat non-executable files (like images or plain text) as JavaScript, enabling XSS.",
			Recommendation: domain.Recommendation{
				Summary:       "Set X-Content-Type-Options to 'nosniff'.",
				Remediation:   "Add header: X-Content-Type-Options: nosniff",
				ConfigSnippet: "add_header X-Content-Type-Options \"nosniff\" always;",
			},
			Verification: domain.Verification{
				Command:     fmt.Sprintf("curl -sI %s | grep -i '^x-content-type-options:'", target.NormalizedURL),
				Tool:        "curl",
				Description: "Verify X-Content-Type-Options header",
			},
			CreatedAt: time.Now().UTC(),
		})
	} else {
		res.Findings = append(res.Findings, domain.Finding{
			ID:          GenerateFindingID("fnd_xcto_valid"),
			Title:       "X-Content-Type-Options Configured Properly",
			Description: "X-Content-Type-Options: nosniff is enabled, preventing MIME-sniffing exploits.",
			Severity:    domain.SeverityInfo,
			Confidence:  domain.ConfidenceConfirmed,
			Status:      domain.StatusObserved,
			Category:    domain.CategoryHTTPHeaders,
			RuleID:      "X_CONTENT_TYPE_OPTIONS_NOSNIFF",
			OWASPMapping: "A05:2021-Security Misconfiguration",
			ASVSMapping:  "V14.4.4",
			CWE:         "CWE-16",
			Evidence: domain.Evidence{
				Type:            domain.EvidenceHTTPExchange,
				Summary:         "x-content-type-options: nosniff",
				ResponseHeaders: headers,
				Timestamp:       time.Now().UTC(),
			},
			Impact: "Protects against drive-by downloads and unexpected MIME type execution.",
			Recommendation: domain.Recommendation{
				Summary:     "Maintain 'nosniff' setting.",
				Remediation: "Keep header enabled globally.",
			},
			Verification: domain.Verification{
				Command:     fmt.Sprintf("curl -sI %s | grep -i '^x-content-type-options:'", target.NormalizedURL),
				Tool:        "curl",
				Description: "Check nosniff header",
			},
			CreatedAt: time.Now().UTC(),
		})
	}

	// 4. Clickjacking / Frame Protections (X-Frame-Options & CSP frame-ancestors)
	xfo := resp.Header.Get("X-Frame-Options")
	hasFrameAncestors := strings.Contains(strings.ToLower(csp), "frame-ancestors")

	if xfo == "" && !hasFrameAncestors {
		res.Findings = append(res.Findings, domain.Finding{
			ID:          GenerateFindingID("fnd_clickjacking_missing"),
			Title:       "Missing Clickjacking Defense (No X-Frame-Options or frame-ancestors)",
			Description: "Neither X-Frame-Options nor CSP frame-ancestors is present. The page can be embedded into malicious iframes.",
			Severity:    domain.SeverityHigh,
			Confidence:  domain.ConfidenceConfirmed,
			Status:      domain.StatusConfirmed,
			Category:    domain.CategoryHTTPHeaders,
			RuleID:      "CLICKJACKING_PROTECTION_MISSING",
			OWASPMapping: "A05:2021-Security Misconfiguration",
			ASVSMapping:  "V14.4.3",
			CWE:         "CWE-1021",
			Evidence: domain.Evidence{
				Type:            domain.EvidenceHTTPExchange,
				Summary:         "Neither x-frame-options nor frame-ancestors observed",
				ResponseHeaders: headers,
				Timestamp:       time.Now().UTC(),
			},
			Impact: "Adversaries can embed the site in transparent overlays to trick users into executing unintended actions.",
			Recommendation: domain.Recommendation{
				Summary:       "Configure X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
				Remediation:   "Add X-Frame-Options: DENY or SAMEORIGIN to prevent unauthorized framing.",
				ConfigSnippet: "add_header X-Frame-Options \"DENY\" always;",
			},
			Verification: domain.Verification{
				Command:     fmt.Sprintf("curl -sI %s | grep -iE '^(x-frame-options|content-security-policy):'", target.NormalizedURL),
				Tool:        "curl",
				Description: "Check framing protections",
			},
			CreatedAt: time.Now().UTC(),
		})
	}

	// 5. Referrer-Policy
	refPolicy := resp.Header.Get("Referrer-Policy")
	if refPolicy == "" {
		res.Findings = append(res.Findings, domain.Finding{
			ID:          GenerateFindingID("fnd_referrer_missing"),
			Title:       "Missing Referrer-Policy Header",
			Description: "No Referrer-Policy header specified. Browsers may leak sensitive URL parameters to external sites.",
			Severity:    domain.SeverityLow,
			Confidence:  domain.ConfidenceConfirmed,
			Status:      domain.StatusConfirmed,
			Category:    domain.CategoryHTTPHeaders,
			RuleID:      "REFERRER_POLICY_MISSING",
			OWASPMapping: "A05:2021-Security Misconfiguration",
			ASVSMapping:  "V14.4.7",
			CWE:         "CWE-200",
			Evidence: domain.Evidence{
				Type:            domain.EvidenceHTTPExchange,
				Summary:         "Referrer-Policy header not present",
				ResponseHeaders: headers,
				Timestamp:       time.Now().UTC(),
			},
			Impact: "Sensitive path or query parameters (tokens, session IDs) might leak in Referer headers when navigating external links.",
			Recommendation: domain.Recommendation{
				Summary:       "Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer.",
				Remediation:   "Add header: Referrer-Policy: strict-origin-when-cross-origin",
				ConfigSnippet: "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
			},
			Verification: domain.Verification{
				Command:     fmt.Sprintf("curl -sI %s | grep -i '^referrer-policy:'", target.NormalizedURL),
				Tool:        "curl",
				Description: "Check Referrer-Policy header",
			},
			CreatedAt: time.Now().UTC(),
		})
	}

	// 6. Permissions-Policy
	permPolicy := resp.Header.Get("Permissions-Policy")
	if permPolicy == "" {
		res.Findings = append(res.Findings, domain.Finding{
			ID:          GenerateFindingID("fnd_permissions_missing"),
			Title:       "Missing Permissions-Policy Header",
			Description: "Permissions-Policy header is absent. Browser hardware features (camera, mic, geolocation) are unconstrained by default.",
			Severity:    domain.SeverityLow,
			Confidence:  domain.ConfidenceConfirmed,
			Status:      domain.StatusObserved,
			Category:    domain.CategoryHTTPHeaders,
			RuleID:      "PERMISSIONS_POLICY_MISSING",
			OWASPMapping: "A05:2021-Security Misconfiguration",
			ASVSMapping:  "V14.4.8",
			CWE:         "CWE-16",
			Evidence: domain.Evidence{
				Type:            domain.EvidenceHTTPExchange,
				Summary:         "Permissions-Policy header not present",
				ResponseHeaders: headers,
				Timestamp:       time.Now().UTC(),
			},
			Impact: "Embedded third-party scripts or iframes could attempt unauthorized hardware API access.",
			Recommendation: domain.Recommendation{
				Summary:       "Define Permissions-Policy restricting sensitive browser features.",
				Remediation:   "Add Permissions-Policy: camera=(), microphone=(), geolocation=()",
				ConfigSnippet: "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;",
			},
			Verification: domain.Verification{
				Command:     fmt.Sprintf("curl -sI %s | grep -i '^permissions-policy:'", target.NormalizedURL),
				Tool:        "curl",
				Description: "Check Permissions-Policy header",
			},
			CreatedAt: time.Now().UTC(),
		})
	}

	res.Duration = time.Since(start)
	return res, nil
}
