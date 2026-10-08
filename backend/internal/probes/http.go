package probes

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/expose/expose-backend/internal/models"
)

type HTTPProbe struct{}

func NewHTTPProbe() *HTTPProbe {
	return &HTTPProbe{}
}

func (p *HTTPProbe) Name() string {
	return "http_headers"
}

func (p *HTTPProbe) Category() models.Category {
	return models.CategoryTransportSecurity
}

func (p *HTTPProbe) Execute(ctx context.Context, target *models.TargetScope) ([]models.Finding, error) {
	var findings []models.Finding

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// 1. Plain HTTP to HTTPS Redirection Check
	if target.Scheme == "https" {
		noRedirectClient := &http.Client{
			Transport: tr,
			Timeout:   6 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		httpURL := fmt.Sprintf("http://%s", target.Host)
		if target.Port != 443 && target.Port != 80 {
			httpURL = fmt.Sprintf("http://%s:%d", target.Host, target.Port)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", httpURL, nil)
		if err == nil {
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Expose-Security-Intelligence/0.1.0)")
			resp, rErr := noRedirectClient.Do(req)
			if rErr == nil {
				defer resp.Body.Close()
				loc := resp.Header.Get("Location")
				isRedirectToHTTPS := (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 307 || resp.StatusCode == 308) &&
					strings.HasPrefix(strings.ToLower(loc), "https://")

				if !isRedirectToHTTPS {
					evidence := models.Evidence{
						Type:    models.EvidenceHTTPExchange,
						Summary: fmt.Sprintf("HTTP endpoint (%s) returned status %d without redirecting to HTTPS.", httpURL, resp.StatusCode),
						Request: map[string]interface{}{"method": "GET", "url": httpURL},
						Response: map[string]interface{}{
							"status_code": resp.StatusCode,
							"location":    loc,
						},
					}
					findings = append(findings, CreateFinding(
						p.Name(), target, models.CategoryTransportSecurity, models.SeverityMedium,
						models.ConfidenceConfirmed, models.StatusConfirmed,
						"Missing HTTP to HTTPS Redirection Enforcement",
						fmt.Sprintf("Requests made to plaintext '%s' do not automatically redirect to HTTPS.", httpURL),
						"Cleartext HTTP traffic can be intercepted and tampered with by man-in-the-middle adversaries on local or ISP networks.",
						"Configure your web server to issue a 301 Permanent Redirect for all HTTP traffic to HTTPS.",
						fmt.Sprintf("curl -sI %s | grep -Ei 'HTTP/|Location:'", httpURL),
						"CWE-319", "", evidence,
					))
				} else {
					evidence := models.Evidence{
						Type:    models.EvidenceHTTPExchange,
						Summary: fmt.Sprintf("HTTP endpoint redirects to HTTPS: %s", loc),
						Response: map[string]interface{}{"status_code": resp.StatusCode, "location": loc},
					}
					findings = append(findings, CreateFinding(
						p.Name(), target, models.CategoryTransportSecurity, models.SeverityInfo,
						models.ConfidenceConfirmed, models.StatusObserved,
						"HTTP to HTTPS Redirection Enforced",
						fmt.Sprintf("Plaintext HTTP requests to '%s' automatically redirect to encrypted HTTPS.", httpURL),
						"Prevents accidental cleartext transmission of credentials and cookies.",
						"Maintain HTTPS redirection policies.",
						fmt.Sprintf("curl -sI %s | grep -Ei 'HTTP/|Location:'", httpURL),
						"", "", evidence,
					))
				}
			}
		}
	}

	// 2. Query Primary Endpoint
	followClient := &http.Client{
		Transport: tr,
		Timeout:   8 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", target.NormalizedURL, nil)
	if err != nil {
		return findings, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Expose-Security-Intelligence/0.1.0)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := followClient.Do(req)
	if err != nil {
		evidence := models.Evidence{
			Type:    models.EvidenceHTTPExchange,
			Summary: fmt.Sprintf("Failed to connect to %s: %v", target.NormalizedURL, err),
			RawData: map[string]interface{}{"error": err.Error()},
		}
		findings = append(findings, CreateFinding(
			p.Name(), target, models.CategoryTransportSecurity, models.SeverityHigh,
			models.ConfidenceConfirmed, models.StatusConfirmed,
			"HTTP Service Unreachable",
			fmt.Sprintf("HTTP connection to '%s' failed: %v", target.NormalizedURL, err),
			"The web service appears unavailable or rejecting scan connections.",
			"Verify web server availability and routing.",
			fmt.Sprintf("curl -sI %s", target.NormalizedURL),
			"", "", evidence,
		))
		return findings, nil
	}
	defer resp.Body.Close()

	headers := resp.Header
	headersMap := make(map[string]interface{})
	for k, v := range headers {
		headersMap[k] = strings.Join(v, ", ")
	}

	respEvidence := map[string]interface{}{
		"status_code": resp.StatusCode,
		"headers":     headersMap,
		"url":         resp.Request.URL.String(),
	}

	// A. Strict-Transport-Security (HSTS)
	hsts := headers.Get("Strict-Transport-Security")
	if target.Scheme == "https" {
		if hsts == "" {
			evidence := models.Evidence{
				Type:     models.EvidenceHTTPExchange,
				Summary:  fmt.Sprintf("No Strict-Transport-Security header returned by %s", target.NormalizedURL),
				Response: respEvidence,
			}
			findings = append(findings, CreateFinding(
				p.Name(), target, models.CategoryTransportSecurity, models.SeverityMedium,
				models.ConfidenceConfirmed, models.StatusConfirmed,
				"Missing HTTP Strict Transport Security (HSTS)",
				"HTTP Strict Transport Security (HSTS) is not enabled.",
				"Browsers may attempt unencrypted connections on first visits, leaving visitors vulnerable to SSL-stripping MITM attacks.",
				"Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to HTTPS responses.",
				fmt.Sprintf("curl -sI %s | grep -i strict-transport-security", target.NormalizedURL),
				"CWE-319", "", evidence,
			))
		} else {
			re := regexp.MustCompile(`(?i)max-age=(\d+)`)
			matches := re.FindStringSubmatch(hsts)
			if len(matches) > 1 {
				maxAge, _ := strconv.Atoi(matches[1])
				if maxAge < 31536000 {
					evidence := models.Evidence{
						Type:     models.EvidenceHTTPExchange,
						Summary:  fmt.Sprintf("HSTS max-age is %d seconds (under 1 year).", maxAge),
						Response: map[string]interface{}{"hsts": hsts},
					}
					findings = append(findings, CreateFinding(
						p.Name(), target, models.CategoryTransportSecurity, models.SeverityLow,
						models.ConfidenceConfirmed, models.StatusConfirmed,
						"Low HSTS max-age Duration",
						fmt.Sprintf("The HSTS max-age is set to %d seconds (recommended: 31,536,000s / 1 year).", maxAge),
						"A short HSTS window increases susceptibility to downgrade attacks if a user does not revisit frequently.",
						"Increase HSTS max-age directive to at least 31536000 seconds.",
						fmt.Sprintf("curl -sI %s | grep -i strict-transport-security", target.NormalizedURL),
						"CWE-319", "", evidence,
					))
				} else {
					evidence := models.Evidence{
						Type:     models.EvidenceHTTPExchange,
						Summary:  fmt.Sprintf("HSTS configured: %s", hsts),
						Response: map[string]interface{}{"hsts": hsts},
					}
					findings = append(findings, CreateFinding(
						p.Name(), target, models.CategoryTransportSecurity, models.SeverityInfo,
						models.ConfidenceConfirmed, models.StatusObserved,
						"HTTP Strict Transport Security (HSTS) Active",
						fmt.Sprintf("HSTS is configured with max-age=%d seconds.", maxAge),
						"Guarantees browser-enforced HTTPS connections for subsequent visits.",
						"Maintain HSTS header and consider submission to the HSTS preload list.",
						fmt.Sprintf("curl -sI %s | grep -i strict-transport-security", target.NormalizedURL),
						"", "", evidence,
					))
				}
			}
		}
	}

	// B. Content-Security-Policy (CSP)
	csp := headers.Get("Content-Security-Policy")
	if csp == "" {
		evidence := models.Evidence{
			Type:     models.EvidenceHTTPExchange,
			Summary:  fmt.Sprintf("No Content-Security-Policy header returned by %s", target.NormalizedURL),
			Response: respEvidence,
		}
		findings = append(findings, CreateFinding(
			p.Name(), target, models.CategoryTransportSecurity, models.SeverityMedium,
			models.ConfidenceConfirmed, models.StatusConfirmed,
			"Missing Content-Security-Policy (CSP) Header",
			"Content-Security-Policy (CSP) is not configured.",
			"Leaves the application with no defense-in-depth against Cross-Site Scripting (XSS), data exfiltration, or rogue scripts.",
			"Deploy a Content-Security-Policy header restricting allowed origins for scripts, styles, and frames.",
			fmt.Sprintf("curl -sI %s | grep -i content-security-policy", target.NormalizedURL),
			"CWE-1021", "", evidence,
		))
	} else if strings.Contains(csp, "'unsafe-inline'") && !strings.Contains(csp, "nonce-") && !strings.Contains(csp, "sha256-") {
		evidence := models.Evidence{
			Type:     models.EvidenceHTTPExchange,
			Summary:  fmt.Sprintf("CSP contains 'unsafe-inline' without nonce/hash: %s", csp),
			Response: map[string]interface{}{"csp": csp},
		}
		findings = append(findings, CreateFinding(
			p.Name(), target, models.CategoryTransportSecurity, models.SeverityLow,
			models.ConfidenceConfirmed, models.StatusConfirmed,
			"Insecure Content-Security-Policy: 'unsafe-inline' Permitted",
			"The CSP includes 'unsafe-inline' without cryptographic nonces or hashes.",
			"Weakens XSS mitigations by allowing arbitrary inline script execution.",
			"Refactor inline scripts or employ cryptographic nonces ('nonce-...').",
			fmt.Sprintf("curl -sI %s | grep -i content-security-policy", target.NormalizedURL),
			"CWE-79", "", evidence,
		))
	} else {
		evidence := models.Evidence{
			Type:     models.EvidenceHTTPExchange,
			Summary:  "Content-Security-Policy header is active.",
			Response: map[string]interface{}{"csp": csp},
		}
		findings = append(findings, CreateFinding(
			p.Name(), target, models.CategoryTransportSecurity, models.SeverityInfo,
			models.ConfidenceConfirmed, models.StatusObserved,
			"Content-Security-Policy (CSP) Configured",
			"Application publishes a Content-Security-Policy restricting resource execution.",
			"Provides browser-enforced boundaries limiting Cross-Site Scripting impact.",
			"Review CSP reporting endpoints periodically.",
			fmt.Sprintf("curl -sI %s | grep -i content-security-policy", target.NormalizedURL),
			"", "", evidence,
		))
	}

	// C. Clickjacking Defense (X-Frame-Options / frame-ancestors)
	xfo := headers.Get("X-Frame-Options")
	hasFrameAncestors := strings.Contains(csp, "frame-ancestors")
	if xfo == "" && !hasFrameAncestors {
		evidence := models.Evidence{
			Type:     models.EvidenceHTTPExchange,
			Summary:  "Neither X-Frame-Options nor CSP frame-ancestors headers are present.",
			Response: respEvidence,
		}
		findings = append(findings, CreateFinding(
			p.Name(), target, models.CategoryTransportSecurity, models.SeverityMedium,
			models.ConfidenceConfirmed, models.StatusConfirmed,
			"Missing Clickjacking Defense (X-Frame-Options / frame-ancestors)",
			"The response lacks both 'X-Frame-Options' and CSP 'frame-ancestors'.",
			"Adversaries can embed your web application in hidden iframes to perform UI redressing / clickjacking attacks against logged-in users.",
			"Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors 'self''.",
			fmt.Sprintf("curl -sI %s | grep -Ei 'x-frame-options|frame-ancestors'", target.NormalizedURL),
			"CWE-1021", "", evidence,
		))
	}

	// D. MIME-Sniffing (X-Content-Type-Options)
	xcto := headers.Get("X-Content-Type-Options")
	if !strings.EqualFold(strings.TrimSpace(xcto), "nosniff") {
		evidence := models.Evidence{
			Type:     models.EvidenceHTTPExchange,
			Summary:  fmt.Sprintf("X-Content-Type-Options is '%s' (expected 'nosniff').", xcto),
			Response: respEvidence,
		}
		findings = append(findings, CreateFinding(
			p.Name(), target, models.CategoryTransportSecurity, models.SeverityLow,
			models.ConfidenceConfirmed, models.StatusConfirmed,
			"Missing or Ineffective X-Content-Type-Options Header",
			"The 'X-Content-Type-Options: nosniff' header is missing.",
			"Browsers may execute uploaded text or image files as JavaScript/HTML if they guess a different MIME type.",
			"Add 'X-Content-Type-Options: nosniff' to all HTTP responses.",
			fmt.Sprintf("curl -sI %s | grep -i x-content-type-options", target.NormalizedURL),
			"CWE-16", "", evidence,
		))
	}

	// E. Referrer-Policy
	refPolicy := headers.Get("Referrer-Policy")
	if refPolicy == "" {
		evidence := models.Evidence{
			Type:     models.EvidenceHTTPExchange,
			Summary:  "Referrer-Policy header is not present.",
			Response: respEvidence,
		}
		findings = append(findings, CreateFinding(
			p.Name(), target, models.CategoryTransportSecurity, models.SeverityLow,
			models.ConfidenceConfirmed, models.StatusConfirmed,
			"Missing Referrer-Policy Header",
			"No Referrer-Policy header is configured.",
			"Sensitive URLs and query parameters may leak to external third-party servers via the HTTP Referer header.",
			"Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
			fmt.Sprintf("curl -sI %s | grep -i referrer-policy", target.NormalizedURL),
			"CWE-200", "", evidence,
		))
	}

	// F. Server version disclosure
	versionRegex := regexp.MustCompile(`\d+\.\d+`)
	for _, hName := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"} {
		val := headers.Get(hName)
		if val != "" && versionRegex.MatchString(val) {
			evidence := models.Evidence{
				Type:     models.EvidenceHTTPExchange,
				Summary:  fmt.Sprintf("Header '%s' reveals detailed version: '%s'", hName, val),
				Response: map[string]interface{}{hName: val},
			}
			findings = append(findings, CreateFinding(
				p.Name(), target, models.CategoryInformationDisclosure, models.SeverityLow,
				models.ConfidenceConfirmed, models.StatusConfirmed,
				fmt.Sprintf("Technology Version Disclosure via '%s' Header", hName),
				fmt.Sprintf("HTTP response reveals exact software version: '%s: %s'.", hName, val),
				"Disclosing exact software builds simplifies reconnaissance and vulnerability targeting for automated exploit scanners.",
				fmt.Sprintf("Configure the web server or reverse proxy to suppress or mask '%s'.", hName),
				fmt.Sprintf("curl -sI %s | grep -i %s", target.NormalizedURL, hName),
				"CWE-200", "", evidence,
			))
		}
	}

	return findings, nil
}
