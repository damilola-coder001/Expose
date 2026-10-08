package probes

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/expose/expose/apps/api/internal/domain"
	"github.com/expose/expose/apps/api/internal/scope"
)

type HTTPPostureProbe struct{}

func NewHTTPPostureProbe() *HTTPPostureProbe {
	return &HTTPPostureProbe{}
}

func (p *HTTPPostureProbe) Name() string {
	return "http_posture"
}

func (p *HTTPPostureProbe) Run(ctx context.Context, target *scope.TargetScope) (*ProbeResult, error) {
	start := time.Now()
	res := &ProbeResult{
		ProbeName: p.Name(),
		Findings:  make([]domain.Finding, 0),
		Assets:    make([]domain.Asset, 0),
	}

	client := scope.NewSafeHTTPClient(8*time.Second, target.AllowPrivate)

	// 1. Check HTTP (Port 80) -> HTTPS Redirect Posture
	httpURL := fmt.Sprintf("http://%s", target.Host)
	if target.Port != 80 && target.Port != 443 {
		httpURL = fmt.Sprintf("http://%s:%d", target.Host, target.Port)
	}

	// Make a non-redirecting request to port 80 to observe the immediate redirect behavior
	noRedirectClient := &http.Client{
		Transport: scope.NewSafeTransport(5*time.Second, target.AllowPrivate),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Stop at first redirect
		},
		Timeout: 6 * time.Second,
	}

	req80, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL, nil)
	if err == nil {
		req80.Header.Set("User-Agent", "Expose-Security-Scanner/1.0")
		resp80, err80 := noRedirectClient.Do(req80)
		if err80 == nil {
			defer resp80.Body.Close()

			headers80 := extractHeaders(resp80.Header)
			statusLine80 := fmt.Sprintf("%s %d %s", resp80.Proto, resp80.StatusCode, http.StatusText(resp80.StatusCode))
			location := resp80.Header.Get("Location")

			if resp80.StatusCode == http.StatusMovedPermanently || resp80.StatusCode == http.StatusPermanentRedirect {
				if strings.HasPrefix(strings.ToLower(location), "https://") {
					res.Findings = append(res.Findings, domain.Finding{
						ID:          GenerateFindingID("fnd_http_redirect"),
						Title:       "HTTP Enforces Permanent Upgrade to HTTPS",
						Description: fmt.Sprintf("Port 80 responds with HTTP %d redirecting to secure HTTPS target (%s).", resp80.StatusCode, location),
						Severity:    domain.SeverityInfo,
						Confidence:  domain.ConfidenceConfirmed,
						Status:      domain.StatusConfirmed,
						Category:    domain.CategoryTransportSecurity,
						RuleID:      "HTTP_REDIRECT_PERMANENT_HTTPS",
						OWASPMapping: "A02:2021-Cryptographic Failures",
						ASVSMapping:  "V14.4.1",
						CWE:         "CWE-319",
						Evidence: domain.Evidence{
							Type:            domain.EvidenceHTTPExchange,
							Summary:         fmt.Sprintf("Observed %s with Location: %s", statusLine80, location),
							Request:         map[string]interface{}{"url": httpURL, "method": "GET"},
							ResponseHeaders: headers80,
							RawData:         map[string]interface{}{"status_code": resp80.StatusCode, "location": location},
							Timestamp:       time.Now().UTC(),
						},
						Impact: "Guarantees plaintext clients are immediately upgraded to encrypted transport before transferring data.",
						Recommendation: domain.Recommendation{
							Summary:     "Maintain permanent 301/308 redirect configuration.",
							Remediation: "Ensure HSTS preload is also enabled so browsers never attempt HTTP connections.",
						},
						Verification: domain.Verification{
							Command:     fmt.Sprintf("curl -sI -o /dev/null -w '%%{http_code} -> %%{redirect_url}\\n' %s", httpURL),
							Tool:        "curl",
							Description: "Inspect immediate redirect response on port 80",
						},
						CreatedAt: time.Now().UTC(),
					})
				}
			} else if resp80.StatusCode == http.StatusFound || resp80.StatusCode == http.StatusTemporaryRedirect {
				res.Findings = append(res.Findings, domain.Finding{
					ID:          GenerateFindingID("fnd_http_temp_redirect"),
					Title:       "HTTP Uses Temporary Redirect to HTTPS",
					Description: fmt.Sprintf("Port 80 responds with temporary redirect HTTP %d instead of permanent 301/308.", resp80.StatusCode),
					Severity:    domain.SeverityLow,
					Confidence:  domain.ConfidenceConfirmed,
					Status:      domain.StatusObserved,
					Category:    domain.CategoryTransportSecurity,
					RuleID:      "HTTP_REDIRECT_TEMPORARY",
					OWASPMapping: "A02:2021-Cryptographic Failures",
					ASVSMapping:  "V14.4.1",
					CWE:         "CWE-319",
					Evidence: domain.Evidence{
						Type:            domain.EvidenceHTTPExchange,
						Summary:         fmt.Sprintf("Observed %s with Location: %s", statusLine80, location),
						Request:         map[string]interface{}{"url": httpURL, "method": "GET"},
						ResponseHeaders: headers80,
						RawData:         map[string]interface{}{"status_code": resp80.StatusCode, "location": location},
						Timestamp:       time.Now().UTC(),
					},
					Impact: "Temporary redirects are not cached by browsers, causing subsequent visits to still attempt plaintext HTTP first.",
					Recommendation: domain.Recommendation{
						Summary:     "Replace 302/307 redirect with permanent 301 or 308 redirect.",
						Remediation: "Configure web server to issue 301 Moved Permanently for all HTTP requests.",
					},
					Verification: domain.Verification{
						Command:     fmt.Sprintf("curl -sI %s | grep -iE 'HTTP/|location'", httpURL),
						Tool:        "curl",
						Description: "Check HTTP redirect status code",
					},
					CreatedAt: time.Now().UTC(),
				})
			} else if resp80.StatusCode == http.StatusOK {
				// Port 80 serves plaintext 200 OK without redirect!
				res.Findings = append(res.Findings, domain.Finding{
					ID:          GenerateFindingID("fnd_plaintext_http"),
					Title:       "Plaintext HTTP Enabled Without HTTPS Redirect",
					Description: fmt.Sprintf("Port 80 responds with HTTP 200 OK and serves content over unencrypted plaintext transport."),
					Severity:    domain.SeverityHigh,
					Confidence:  domain.ConfidenceConfirmed,
					Status:      domain.StatusConfirmed,
					Category:    domain.CategoryTransportSecurity,
					RuleID:      "PLAINTEXT_HTTP_NO_REDIRECT",
					OWASPMapping: "A02:2021-Cryptographic Failures",
					ASVSMapping:  "V14.4.1",
					CWE:         "CWE-319",
					Evidence: domain.Evidence{
						Type:            domain.EvidenceHTTPExchange,
						Summary:         fmt.Sprintf("Observed plaintext %s without redirect", statusLine80),
						Request:         map[string]interface{}{"url": httpURL, "method": "GET"},
						ResponseHeaders: headers80,
						RawData:         map[string]interface{}{"status_code": resp80.StatusCode},
						Timestamp:       time.Now().UTC(),
					},
					Impact: "Allows Man-in-the-Middle (MitM) attackers on the local network path to eavesdrop, tamper with content, or hijack cookies.",
					Recommendation: domain.Recommendation{
						Summary:     "Enforce immediate redirect from HTTP to HTTPS.",
						Remediation: "Configure web server or CDN to redirect all port 80 traffic to https:// with 301 Moved Permanently.",
					},
					Verification: domain.Verification{
						Command:     fmt.Sprintf("curl -sI %s | head -n 1", httpURL),
						Tool:        "curl",
						Description: "Verify plaintext HTTP status",
					},
					CreatedAt: time.Now().UTC(),
				})
			}
		}
	}

	// 2. Query HTTPS Root Endpoint to Inspect Server Disclosure & Behavior
	httpsURL := target.NormalizedURL
	reqHTTPS, err := http.NewRequestWithContext(ctx, http.MethodGet, httpsURL, nil)
	if err == nil {
		reqHTTPS.Header.Set("User-Agent", "Expose-Security-Scanner/1.0")
		respHTTPS, errHTTPS := client.Do(reqHTTPS)
		if errHTTPS == nil {
			defer respHTTPS.Body.Close()

			headers := extractHeaders(respHTTPS.Header)

			// Check Server version disclosure
			if serverHeader := respHTTPS.Header.Get("Server"); serverHeader != "" {
				res.Assets = append(res.Assets, domain.Asset{
					ID:       GenerateFindingID("ast_server"),
					TargetID: target.Host,
					Type:     domain.AssetHeader,
					Value:    serverHeader,
				})

				// Look for explicit version numbers (e.g. Apache/2.4.41, nginx/1.18.0)
				versionRegex := regexp.MustCompile(`[a-zA-Z]+/\d+\.\d+`)
				if versionRegex.MatchString(serverHeader) {
					res.Findings = append(res.Findings, domain.Finding{
						ID:          GenerateFindingID("fnd_server_version"),
						Title:       "Detailed Web Server Version Disclosed",
						Description: fmt.Sprintf("Server header reveals specific software and version banner: %q.", serverHeader),
						Severity:    domain.SeverityLow,
						Confidence:  domain.ConfidenceConfirmed,
						Status:      domain.StatusObserved,
						Category:    domain.CategoryInformationDisclosure,
						RuleID:      "SERVER_BANNER_DISCLOSURE",
						OWASPMapping: "A05:2021-Security Misconfiguration",
						ASVSMapping:  "V14.3.3",
						CWE:         "CWE-200",
						Evidence: domain.Evidence{
							Type:            domain.EvidenceHTTPExchange,
							Summary:         fmt.Sprintf("Observed Server: %s", serverHeader),
							Request:         map[string]interface{}{"url": httpsURL, "method": "GET"},
							ResponseHeaders: headers,
							RawData:         map[string]interface{}{"server": serverHeader},
							Timestamp:       time.Now().UTC(),
						},
						Impact: "Assists attackers in targeting known CVEs specific to the disclosed web server version.",
						Recommendation: domain.Recommendation{
							Summary:     "Suppress or generalize the Server header banner.",
							Remediation: "Set 'server_tokens off;' in nginx, 'ServerTokens Prod' in Apache, or strip header at edge CDN.",
						},
						Verification: domain.Verification{
							Command:     fmt.Sprintf("curl -sI %s | grep -i '^server:'", httpsURL),
							Tool:        "curl",
							Description: "Inspect Server response header",
						},
						CreatedAt: time.Now().UTC(),
					})
				}
			}

			// Check X-Powered-By disclosure
			if poweredBy := respHTTPS.Header.Get("X-Powered-By"); poweredBy != "" {
				res.Findings = append(res.Findings, domain.Finding{
					ID:          GenerateFindingID("fnd_powered_by"),
					Title:       "Application Framework Technology Disclosed (X-Powered-By)",
					Description: fmt.Sprintf("X-Powered-By header discloses underlying backend stack: %q.", poweredBy),
					Severity:    domain.SeverityLow,
					Confidence:  domain.ConfidenceConfirmed,
					Status:      domain.StatusObserved,
					Category:    domain.CategoryInformationDisclosure,
					RuleID:      "X_POWERED_BY_DISCLOSURE",
					OWASPMapping: "A05:2021-Security Misconfiguration",
					ASVSMapping:  "V14.3.3",
					CWE:         "CWE-200",
					Evidence: domain.Evidence{
						Type:            domain.EvidenceHTTPExchange,
						Summary:         fmt.Sprintf("Observed X-Powered-By: %s", poweredBy),
						Request:         map[string]interface{}{"url": httpsURL, "method": "GET"},
						ResponseHeaders: headers,
						RawData:         map[string]interface{}{"x_powered_by": poweredBy},
						Timestamp:       time.Now().UTC(),
					},
					Impact: "Reveals the backend runtime (e.g. Express, PHP, ASP.NET) helping adversaries tailor exploits.",
					Recommendation: domain.Recommendation{
						Summary:     "Disable the X-Powered-By header in application configuration.",
						Remediation: "Disable powered-by in your framework settings (e.g., app.disable('x-powered-by') in Express).",
					},
					Verification: domain.Verification{
						Command:     fmt.Sprintf("curl -sI %s | grep -i '^x-powered-by:'", httpsURL),
						Tool:        "curl",
						Description: "Inspect X-Powered-By header",
					},
					CreatedAt: time.Now().UTC(),
				})
			}
		}
	}

	// 3. Safe OPTIONS Probe for Advertised HTTP Methods
	reqOptions, err := http.NewRequestWithContext(ctx, http.MethodOptions, httpsURL, nil)
	if err == nil {
		reqOptions.Header.Set("User-Agent", "Expose-Security-Scanner/1.0")
		respOptions, errOptions := client.Do(reqOptions)
		if errOptions == nil {
			defer respOptions.Body.Close()

			if allowHeader := respOptions.Header.Get("Allow"); allowHeader != "" {
				upperAllow := strings.ToUpper(allowHeader)
				if strings.Contains(upperAllow, "TRACE") {
					res.Findings = append(res.Findings, domain.Finding{
						ID:          GenerateFindingID("fnd_trace_method"),
						Title:       "HTTP TRACE Method Advertised",
						Description: "The server advertises support for the HTTP TRACE method in its Allow response header.",
						Severity:    domain.SeverityLow,
						Confidence:  domain.ConfidencePotential,
						Status:      domain.StatusObserved,
						Category:    domain.CategoryHTTPHeaders,
						RuleID:      "HTTP_TRACE_ENABLED",
						OWASPMapping: "A05:2021-Security Misconfiguration",
						ASVSMapping:  "V14.3.2",
						CWE:         "CWE-16",
						Evidence: domain.Evidence{
							Type:            domain.EvidenceHTTPExchange,
							Summary:         fmt.Sprintf("OPTIONS response contains Allow: %s", allowHeader),
							Request:         map[string]interface{}{"url": httpsURL, "method": "OPTIONS"},
							ResponseHeaders: extractHeaders(respOptions.Header),
							Timestamp:       time.Now().UTC(),
						},
						Impact: "Can be abused in Cross-Site Tracing (XST) attacks to steal HttpOnly authentication cookies.",
						Recommendation: domain.Recommendation{
							Summary:     "Disable HTTP TRACE on the web server.",
							Remediation: "Set 'TraceEnable off' in Apache, or return 405 Method Not Allowed in Nginx.",
						},
						Verification: domain.Verification{
							Command:     fmt.Sprintf("curl -sI -X OPTIONS %s | grep -i '^allow:'", httpsURL),
							Tool:        "curl",
							Description: "Inspect advertised methods in OPTIONS response",
						},
						CreatedAt: time.Now().UTC(),
					})
				}
			}
		}
	}

	res.Duration = time.Since(start)
	return res, nil
}

func extractHeaders(h http.Header) map[string]string {
	result := make(map[string]string)
	for k, v := range h {
		if len(v) > 0 {
			result[k] = strings.Join(v, ", ")
		}
	}
	return result
}
