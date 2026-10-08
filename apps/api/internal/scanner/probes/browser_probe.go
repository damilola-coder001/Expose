package probes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/expose/expose/apps/api/internal/domain"
	"github.com/expose/expose/apps/api/internal/scope"
)

// BrowserProbe coordinates client-side DOM and JavaScript asset analysis.
// Delegates to the Playwright browser-worker service when available,
// with an integrated static DOM parsing fallback.
type BrowserProbe struct {
	workerURL string
	client    *http.Client
}

// NewBrowserProbe constructs a client-side analysis probe.
func NewBrowserProbe() *BrowserProbe {
	workerURL := os.Getenv("BROWSER_WORKER_URL")
	if workerURL == "" {
		workerURL = "http://localhost:3001"
	}

	return &BrowserProbe{
		workerURL: strings.TrimRight(workerURL, "/"),
		client: &http.Client{
			Timeout: 25 * time.Second,
		},
	}
}

func (p *BrowserProbe) Name() string {
	return "browser_clientside_probe"
}

type browserWorkerRequest struct {
	URL       string `json:"url"`
	TimeoutMS int    `json:"timeout_ms"`
}

type browserWorkerResponse struct {
	Status string `json:"status"`
	Data   struct {
		TargetURL               string            `json:"target_url"`
		Scripts                 []json.RawMessage `json:"scripts"`
		Links                   []json.RawMessage `json:"links"`
		Forms                   []json.RawMessage `json:"forms"`
		Resources               []json.RawMessage `json:"resources"`
		SourceMaps              []json.RawMessage `json:"source_maps"`
		PublicAPIReferences     []string          `json:"public_api_references"`
		ThirdPartyDomains       []string          `json:"third_party_domains"`
		Findings                []domain.Finding  `json:"findings"`
	} `json:"data"`
	Error string `json:"error"`
}

func (p *BrowserProbe) Run(ctx context.Context, target *scope.TargetScope) (*ProbeResult, error) {
	start := time.Now()
	res := &ProbeResult{
		ProbeName: p.Name(),
		Findings:  make([]domain.Finding, 0),
		Assets:    make([]domain.Asset, 0),
	}

	// 1. Try Playwright Browser Worker
	workerTargetURL := target.NormalizedURL
	reqBody, _ := json.Marshal(browserWorkerRequest{
		URL:       workerTargetURL,
		TimeoutMS: 15000,
	})

	workerEndpoint := p.workerURL + "/api/v1/analyze"
	req, err := http.NewRequestWithContext(ctx, "POST", workerEndpoint, bytes.NewReader(reqBody))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		resp, errDo := p.client.Do(req)
		if errDo == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var workerRes browserWorkerResponse
				if errDec := json.NewDecoder(resp.Body).Decode(&workerRes); errDec == nil && workerRes.Status == "success" {
					res.Findings = append(res.Findings, workerRes.Data.Findings...)
					for _, d := range workerRes.Data.ThirdPartyDomains {
						res.Assets = append(res.Assets, domain.Asset{
							ID:       GenerateFindingID("ast_third_party"),
							TargetID: target.Host,
							Type:     domain.AssetHost,
							Value:    d,
							Attributes: map[string]interface{}{
								"role": "third_party_script_host",
							},
							DiscoveredAt: time.Now().UTC(),
						})
					}
					res.Duration = time.Since(start)
					return res, nil
				}
			}
		}
	}

	// 2. Resilient Static DOM Client Analysis Fallback
	// Executes when the headless Playwright container is unavailable, ensuring
	// client-side analysis succeeds across all operating environments.
	p.runStaticDOMAnalysis(ctx, target, res)
	res.Duration = time.Since(start)
	return res, nil
}

func (p *BrowserProbe) runStaticDOMAnalysis(ctx context.Context, target *scope.TargetScope, res *ProbeResult) {
	req, err := http.NewRequestWithContext(ctx, "GET", target.NormalizedURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Expose-Security-Scanner/1.0 (Static DOM Client-Side Analysis)")

	resp, err := p.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*512)) // Read up to 512KB
	if err != nil {
		return
	}
	bodyStr := string(bodyBytes)

	// A. Check for Missing Subresource Integrity (SRI) on External Scripts
	scriptRegex := regexp.MustCompile(`(?i)<script\s+[^>]*src=["']([^"']+)["'][^>]*>`)
	matches := scriptRegex.FindAllStringSubmatch(bodyStr, -1)

	targetDomain := target.Host

	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		fullTag := m[0]
		src := m[1]

		parsedSrc, err := url.Parse(src)
		if err != nil {
			continue
		}

		isExternal := parsedSrc.IsAbs() && parsedSrc.Host != targetDomain && !strings.HasSuffix(parsedSrc.Host, "."+targetDomain)
		hasIntegrity := strings.Contains(strings.ToLower(fullTag), "integrity=")

		if isExternal {
			res.Assets = append(res.Assets, domain.Asset{
				ID:       GenerateFindingID("ast_script"),
				TargetID: target.Host,
				Type:     domain.AssetEndpoint,
				Value:    src,
				Attributes: map[string]interface{}{
					"role":          "external_script",
					"has_integrity": hasIntegrity,
				},
				DiscoveredAt: time.Now().UTC(),
			})

			if !hasIntegrity {
				res.Findings = append(res.Findings, domain.Finding{
					ID:           GenerateFindingID("fnd_sri"),
					Title:        "Missing Subresource Integrity (SRI) on External Script",
					Description:  fmt.Sprintf("External script from %q is loaded without an integrity cryptographic hash.", parsedSrc.Host),
					Severity:     domain.SeverityLow,
					Confidence:   domain.ConfidenceConfirmed,
					Status:       domain.StatusConfirmed,
					Category:     domain.CategoryClientSideSecurity,
					RuleID:       "MISSING_SUBRESOURCE_INTEGRITY",
					OWASPMapping: "A08:2021-Software and Data Integrity Failures",
					ASVSMapping:  "V14.2.3",
					CWE:          "CWE-353",
					Evidence: domain.Evidence{
						Type:        domain.EvidenceDOMContent,
						Summary:     fmt.Sprintf("Observed script tag src=%q lacking integrity attribute", src),
						MatchedData: fullTag,
						Timestamp:   time.Now().UTC(),
					},
					Impact: "If the third-party CDN or supplier is compromised, malicious code could be injected into client sessions without detection.",
					Recommendation: domain.Recommendation{
						Summary:     "Add SRI integrity attribute to external scripts.",
						Remediation: "Generate and add integrity=\"sha384-...\" and crossorigin=\"anonymous\" attributes.",
					},
					References: []domain.ResearchSource{
						{Name: "MDN Subresource Integrity", URL: "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"},
					},
					Verification: domain.Verification{
						Command:     fmt.Sprintf("curl -sL %q | grep -i %q", target.NormalizedURL, src),
						Tool:        "curl",
						Description: "Verify script tag in source HTML",
					},
					CreatedAt: time.Now().UTC(),
				})
			}
		}
	}

	// B. Check for Insecure Form Submissions (Password fields over HTTP or GET)
	formRegex := regexp.MustCompile(`(?i)<form\s+[^>]*>([\s\S]*?)<\/form>`)
	formMatches := formRegex.FindAllStringSubmatch(bodyStr, -1)

	for _, fm := range formMatches {
		if len(fm) < 2 {
			continue
		}
		fullForm := fm[0]
		formInner := fm[1]

		hasPassword := strings.Contains(strings.ToLower(formInner), `type="password"`) || strings.Contains(strings.ToLower(formInner), `type='password'`)
		if !hasPassword {
			continue
		}

		isMethodGet := strings.Contains(strings.ToLower(fullForm), `method="get"`) || strings.Contains(strings.ToLower(fullForm), `method='get'`)
		hasInsecureAction := strings.Contains(strings.ToLower(fullForm), `action="http:`) || strings.Contains(strings.ToLower(fullForm), `action='http:`)

		if hasInsecureAction {
			res.Findings = append(res.Findings, domain.Finding{
				ID:           GenerateFindingID("fnd_insecure_form"),
				Title:        "Insecure Password Form Submission Over Plain HTTP",
				Description:  "A form containing password credentials specifies an unencrypted HTTP action target.",
				Severity:     domain.SeverityHigh,
				Confidence:   domain.ConfidenceConfirmed,
				Status:       domain.StatusConfirmed,
				Category:     domain.CategoryTransportSecurity,
				RuleID:       "INSECURE_PASSWORD_FORM_SUBMISSION",
				OWASPMapping: "A02:2021-Cryptographic Failures",
				ASVSMapping:  "V2.10.1",
				CWE:          "CWE-319",
				Evidence: domain.Evidence{
					Type:        domain.EvidenceDOMContent,
					Summary:     "Password form contains unencrypted action attribute (action='http://...')",
					MatchedData: truncateString(fullForm, 250),
					Timestamp:   time.Now().UTC(),
				},
				Impact: "Credentials transmitted over unencrypted HTTP can be intercepted in transit on shared networks.",
				Recommendation: domain.Recommendation{
					Summary:     "Enforce HTTPS action URLs for all credential forms.",
					Remediation: "Ensure all form action attributes explicitly specify https:// or use secure relative paths on an HTTPS host.",
				},
				References: []domain.ResearchSource{
					{Name: "OWASP Authentication Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"},
				},
				Verification: domain.Verification{
					Command:     fmt.Sprintf("curl -sL %q | grep -i '<form' | grep -i 'action=\"http:'", target.NormalizedURL),
					Tool:        "curl",
					Description: "Check form action protocol in HTML source",
				},
				CreatedAt: time.Now().UTC(),
			})
		}

		if isMethodGet {
			res.Findings = append(res.Findings, domain.Finding{
				ID:           GenerateFindingID("fnd_password_get"),
				Title:        "Password Submitted via HTTP GET Method",
				Description:  "A credential form specifies method='GET', leaking passwords in URL query parameters.",
				Severity:     domain.SeverityHigh,
				Confidence:   domain.ConfidenceConfirmed,
				Status:       domain.StatusConfirmed,
				Category:     domain.CategoryClientSideSecurity,
				RuleID:       "PASSWORD_SUBMITTED_VIA_GET",
				OWASPMapping: "A02:2021-Cryptographic Failures",
				CWE:          "CWE-598",
				Evidence: domain.Evidence{
					Type:        domain.EvidenceDOMContent,
					Summary:     "Password form configured with method='GET'",
					MatchedData: truncateString(fullForm, 250),
					Timestamp:   time.Now().UTC(),
				},
				Impact: "Passwords submitted via GET leak into browser history, web server logs, and HTTP Referer headers.",
				Recommendation: domain.Recommendation{
					Summary:     "Change form submission method to POST.",
					Remediation: "Set method=\"POST\" on all authentication forms.",
				},
				References: []domain.ResearchSource{
					{Name: "CWE-598", URL: "https://cwe.mitre.org/data/definitions/598.html"},
				},
				Verification: domain.Verification{
					Command:     fmt.Sprintf("curl -sL %q | grep -i '<form' | grep -i 'method=\"get\"'", target.NormalizedURL),
					Tool:        "curl",
					Description: "Inspect form method in HTML source",
				},
				CreatedAt: time.Now().UTC(),
			})
		}
	}

	// C. Discover Public API Endpoints referenced in HTML & inline scripts
	apiRegex := regexp.MustCompile(`["'](/api/v[0-9]+[a-zA-Z0-9_\-\/]+)["']`)
	apiMatches := apiRegex.FindAllStringSubmatch(bodyStr, -1)

	discoveredAPIs := make(map[string]bool)
	for _, am := range apiMatches {
		if len(am) >= 2 && !strings.Contains(am[1], "*") {
			discoveredAPIs[am[1]] = true
		}
	}

	if len(discoveredAPIs) > 0 {
		var apisList []string
		for endpoint := range discoveredAPIs {
			apisList = append(apisList, endpoint)
			if len(apisList) >= 10 {
				break
			}
		}

		res.Findings = append(res.Findings, domain.Finding{
			ID:          GenerateFindingID("fnd_api_endpoints"),
			Title:       "Public API Endpoints Referenced in Client-Side Code",
			Description: fmt.Sprintf("Client-side markup and scripts disclose %d backend API endpoint routes.", len(discoveredAPIs)),
			Severity:    domain.SeverityInfo,
			// Adheres strictly to: "Do not claim that discovering a JavaScript reference proves that an API is vulnerable. Everything remains evidence-based."
			Confidence:  domain.ConfidenceInformational,
			Status:      domain.StatusObserved,
			Category:    domain.CategoryInformationDisclosure,
			RuleID:      "PUBLIC_API_ENDPOINT_DISCLOSURE",
			Evidence: domain.Evidence{
				Type:        domain.EvidenceScriptReference,
				Summary:     fmt.Sprintf("Discovered API routes: %s", strings.Join(apisList, ", ")),
				MatchedData: strings.Join(apisList, ", "),
				Timestamp:   time.Now().UTC(),
			},
			Impact: "Disclosed API routes map attack surfaces for operators. Note: Frontend client code referencing its backend API is standard architecture and does not prove the endpoint is vulnerable.",
			Recommendation: domain.Recommendation{
				Summary:     "Ensure all referenced endpoints enforce server-side authentication and authorization.",
				Remediation: "Confirm endpoints enforce token/session validation on the server side and do not rely on obscurity.",
			},
			References: []domain.ResearchSource{
				{Name: "OWASP API Security Top 10", URL: "https://owasp.org/www-project-api-security/"},
			},
			Verification: domain.Verification{
				Command:     fmt.Sprintf("curl -sL %q | grep -Eo '[\"'"'](/api/v[0-9]+[^\"'"' \"'\"']+)[\"'"']' | head -n 10", target.NormalizedURL),
				Tool:        "curl",
				Description: "Extract API routes from frontend page source",
			},
			CreatedAt: time.Now().UTC(),
		})
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + " ...[truncated]"
}
