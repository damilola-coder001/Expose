package probes

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/expose/expose/apps/api/internal/domain"
	"github.com/expose/expose/apps/api/internal/scope"
)

type MixedContentProbe struct{}

func NewMixedContentProbe() *MixedContentProbe {
	return &MixedContentProbe{}
}

func (p *MixedContentProbe) Name() string {
	return "mixed_content"
}

func (p *MixedContentProbe) Run(ctx context.Context, target *scope.TargetScope) (*ProbeResult, error) {
	start := time.Now()
	res := &ProbeResult{
		ProbeName: p.Name(),
		Findings:  make([]domain.Finding, 0),
		Assets:    make([]domain.Asset, 0),
	}

	if target.Scheme != "https" {
		res.Duration = time.Since(start)
		return res, nil
	}

	client := scope.NewSafeHTTPClient(8*time.Second, target.AllowPrivate)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.NormalizedURL, nil)
	if err != nil {
		res.Duration = time.Since(start)
		return res, nil
	}
	req.Header.Set("User-Agent", "Expose-Security-Scanner/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		res.Duration = time.Since(start)
		return res, nil
	}
	defer resp.Body.Close()

	// Read up to 256KB to inspect initial DOM resources
	limitReader := io.LimitReader(resp.Body, 256*1024)
	bodyBytes, err := io.ReadAll(limitReader)
	if err != nil || len(bodyBytes) == 0 {
		res.Duration = time.Since(start)
		return res, nil
	}

	body := string(bodyBytes)

	// 1. Active Mixed Content (Scripts, Iframes, Stylesheets)
	activeScriptRegex := regexp.MustCompile(`(?i)<script[^>]+src=["'](http://[^"']+)["']`)
	activeIframeRegex := regexp.MustCompile(`(?i)<iframe[^>]+src=["'](http://[^"']+)["']`)
	activeLinkRegex := regexp.MustCompile(`(?i)<link[^>]+href=["'](http://[^"']+)["']`)

	for _, match := range activeScriptRegex.FindAllStringSubmatch(body, 5) {
		if len(match) > 1 {
			res.Findings = append(res.Findings, domain.Finding{
				ID:          GenerateFindingID("fnd_active_mixed_script"),
				Title:       "Active Mixed Content Detected (<script> over HTTP)",
				Description: fmt.Sprintf("An insecure JavaScript resource is loaded over plaintext HTTP on an HTTPS page: %s", match[1]),
				Severity:    domain.SeverityHigh,
				Confidence:  domain.ConfidenceConfirmed,
				Status:      domain.StatusConfirmed,
				Category:    domain.CategoryMixedContent,
				RuleID:      "MIXED_CONTENT_ACTIVE_SCRIPT",
				OWASPMapping: "A02:2021-Cryptographic Failures",
				ASVSMapping:  "V14.4.6",
				CWE:         "CWE-319",
				Evidence: domain.Evidence{
					Type: domain.EvidenceDOMContent,
					Summary: fmt.Sprintf("Script tag loads: %s", match[1]),
					RawData: map[string]interface{}{"url": match[1], "tag": match[0]},
					Timestamp: time.Now().UTC(),
				},
				Impact: "Attacker on local network can modify the plaintext script to execute arbitrary malicious code in the context of the HTTPS page.",
				Recommendation: domain.Recommendation{
					Summary:     "Upgrade all script sources to https:// or use protocol-relative URLs.",
					Remediation: fmt.Sprintf("Change %s to https://.", match[1]),
				},
				Verification: domain.Verification{
					Command:     fmt.Sprintf("curl -s %s | grep -i '%s'", target.NormalizedURL, match[1]),
					Tool:        "curl",
					Description: "Check for insecure script URL in page HTML",
				},
				CreatedAt: time.Now().UTC(),
			})
		}
	}

	for _, match := range activeIframeRegex.FindAllStringSubmatch(body, 5) {
		if len(match) > 1 {
			res.Findings = append(res.Findings, domain.Finding{
				ID:          GenerateFindingID("fnd_active_mixed_iframe"),
				Title:       "Active Mixed Content Detected (<iframe> over HTTP)",
				Description: fmt.Sprintf("An insecure iframe is embedded over plaintext HTTP on an HTTPS page: %s", match[1]),
				Severity:    domain.SeverityHigh,
				Confidence:  domain.ConfidenceConfirmed,
				Status:      domain.StatusConfirmed,
				Category:    domain.CategoryMixedContent,
				RuleID:      "MIXED_CONTENT_ACTIVE_IFRAME",
				OWASPMapping: "A02:2021-Cryptographic Failures",
				ASVSMapping:  "V14.4.6",
				CWE:         "CWE-319",
				Evidence: domain.Evidence{
					Type: domain.EvidenceDOMContent,
					Summary: fmt.Sprintf("Iframe tag loads: %s", match[1]),
					RawData: map[string]interface{}{"url": match[1], "tag": match[0]},
					Timestamp: time.Now().UTC(),
				},
				Impact: "The embedded frame can be hijacked and injected with phishing or exploits.",
				Recommendation: domain.Recommendation{
					Summary:     "Upgrade iframe src to https://.",
					Remediation: fmt.Sprintf("Change %s to https://.", match[1]),
				},
				Verification: domain.Verification{
					Command:     fmt.Sprintf("curl -s %s | grep -i '%s'", target.NormalizedURL, match[1]),
					Tool:        "curl",
					Description: "Check for insecure iframe URL in page HTML",
				},
				CreatedAt: time.Now().UTC(),
			})
		}
	}

	for _, match := range activeLinkRegex.FindAllStringSubmatch(body, 5) {
		if len(match) > 1 {
			res.Findings = append(res.Findings, domain.Finding{
				ID:          GenerateFindingID("fnd_active_mixed_css"),
				Title:       "Mixed Content Detected (<link> stylesheet over HTTP)",
				Description: fmt.Sprintf("A stylesheet or icon is loaded over plaintext HTTP on an HTTPS page: %s", match[1]),
				Severity:    domain.SeverityMedium,
				Confidence:  domain.ConfidenceConfirmed,
				Status:      domain.StatusConfirmed,
				Category:    domain.CategoryMixedContent,
				RuleID:      "MIXED_CONTENT_STYLESHEET",
				OWASPMapping: "A02:2021-Cryptographic Failures",
				ASVSMapping:  "V14.4.6",
				CWE:         "CWE-319",
				Evidence: domain.Evidence{
					Type: domain.EvidenceDOMContent,
					Summary: fmt.Sprintf("Link tag loads: %s", match[1]),
					RawData: map[string]interface{}{"url": match[1], "tag": match[0]},
					Timestamp: time.Now().UTC(),
				},
				Impact: "Tampered CSS can be used to alter page appearance or exfiltrate sensitive form keystrokes.",
				Recommendation: domain.Recommendation{
					Summary:     "Upgrade stylesheet links to https://.",
					Remediation: fmt.Sprintf("Change %s to https://.", match[1]),
				},
				Verification: domain.Verification{
					Command:     fmt.Sprintf("curl -s %s | grep -i '%s'", target.NormalizedURL, match[1]),
					Tool:        "curl",
					Description: "Check for insecure stylesheet in HTML",
				},
				CreatedAt: time.Now().UTC(),
			})
		}
	}

	// 2. Passive Mixed Content (Images)
	imgRegex := regexp.MustCompile(`(?i)<img[^>]+src=["'](http://[^"']+)["']`)
	for _, match := range imgRegex.FindAllStringSubmatch(body, 3) {
		if len(match) > 1 {
			res.Findings = append(res.Findings, domain.Finding{
				ID:          GenerateFindingID("fnd_passive_mixed_img"),
				Title:       "Passive Mixed Content Detected (<img> over HTTP)",
				Description: fmt.Sprintf("An image is loaded over plaintext HTTP on an HTTPS page: %s", match[1]),
				Severity:    domain.SeverityLow,
				Confidence:  domain.ConfidenceConfirmed,
				Status:      domain.StatusConfirmed,
				Category:    domain.CategoryMixedContent,
				RuleID:      "MIXED_CONTENT_PASSIVE_IMAGE",
				OWASPMapping: "A02:2021-Cryptographic Failures",
				ASVSMapping:  "V14.4.6",
				CWE:         "CWE-319",
				Evidence: domain.Evidence{
					Type: domain.EvidenceDOMContent,
					Summary: fmt.Sprintf("Image tag loads: %s", match[1]),
					RawData: map[string]interface{}{"url": match[1]},
					Timestamp: time.Now().UTC(),
				},
				Impact: "Network eavesdroppers can see and swap the image, causing mixed-content padlock warnings.",
				Recommendation: domain.Recommendation{
					Summary:     "Host all images securely over https://.",
					Remediation: fmt.Sprintf("Change %s to https://.", match[1]),
				},
				Verification: domain.Verification{
					Command:     fmt.Sprintf("curl -s %s | grep -i '%s'", target.NormalizedURL, match[1]),
					Tool:        "curl",
					Description: "Check for insecure image src in HTML",
				},
				CreatedAt: time.Now().UTC(),
			})
		}
	}

	// If no mixed content issues found and HTML was inspected, record clean observation
	if len(res.Findings) == 0 {
		res.Findings = append(res.Findings, domain.Finding{
			ID:          GenerateFindingID("fnd_mixed_content_clean"),
			Title:       "No Mixed Content Detected in Initial HTML",
			Description: "All external scripts, stylesheets, iframes, and images referenced in the root HTML use secure HTTPS URLs.",
			Severity:    domain.SeverityInfo,
			Confidence:  domain.ConfidenceConfirmed,
			Status:      domain.StatusObserved,
			Category:    domain.CategoryMixedContent,
			RuleID:      "MIXED_CONTENT_CLEAN",
			OWASPMapping: "A02:2021-Cryptographic Failures",
			ASVSMapping:  "V14.4.6",
			CWE:         "CWE-319",
			Evidence: domain.Evidence{
				Type:      domain.EvidenceDOMContent,
				Summary:   fmt.Sprintf("Scanned %d bytes of initial HTML response; zero insecure http:// resources found", len(bodyBytes)),
				Timestamp: time.Now().UTC(),
			},
			Impact: "Maintains uninterrupted HTTPS encryption and green lock padlock integrity for all visitors.",
			Recommendation: domain.Recommendation{
				Summary:     "Enforce upgrade-insecure-requests in CSP.",
				Remediation: "Add 'upgrade-insecure-requests' to Content-Security-Policy header.",
			},
			Verification: domain.Verification{
				Command:     fmt.Sprintf("curl -s %s | grep -i 'http://'", target.NormalizedURL),
				Tool:        "curl",
				Description: "Verify no http:// resources present in HTML",
			},
			CreatedAt: time.Now().UTC(),
		})
	}

	res.Duration = time.Since(start)
	return res, nil
}
