package probes

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/expose/expose/apps/api/internal/domain"
	"github.com/expose/expose/apps/api/internal/scope"
)

type CookieProbe struct{}

func NewCookieProbe() *CookieProbe {
	return &CookieProbe{}
}

func (p *CookieProbe) Name() string {
	return "cookie_security"
}

func (p *CookieProbe) Run(ctx context.Context, target *scope.TargetScope) (*ProbeResult, error) {
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
		return res, nil
	}
	req.Header.Set("User-Agent", "Expose-Security-Scanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		res.Duration = time.Since(start)
		return res, nil
	}
	defer resp.Body.Close()

	rawCookies := resp.Header.Values("Set-Cookie")
	if len(rawCookies) == 0 {
		res.Duration = time.Since(start)
		return res, nil
	}

	for _, rawCookie := range rawCookies {
		lowerCookie := strings.ToLower(rawCookie)
		parts := strings.Split(rawCookie, ";")
		cookieName := "unknown"
		if len(parts) > 0 {
			nameVal := strings.SplitN(parts[0], "=", 2)
			cookieName = strings.TrimSpace(nameVal[0])
		}

		isSecure := strings.Contains(lowerCookie, "; secure") || strings.HasSuffix(lowerCookie, ";secure") || strings.HasSuffix(lowerCookie, "; secure") || strings.Contains(lowerCookie, "secure")
		isHttpOnly := strings.Contains(lowerCookie, "httponly")
		hasSameSite := strings.Contains(lowerCookie, "samesite")

		// 1. Missing Secure flag over HTTPS
		if !isSecure && target.Scheme == "https" {
			res.Findings = append(res.Findings, domain.Finding{
				ID:          GenerateFindingID("fnd_cookie_no_secure"),
				Title:       fmt.Sprintf("Cookie %q Missing 'Secure' Attribute", cookieName),
				Description: fmt.Sprintf("Cookie %q was set without the 'Secure' flag over HTTPS. It can be transmitted in unencrypted plaintext if an attacker triggers an HTTP request.", cookieName),
				Severity:    domain.SeverityMedium,
				Confidence:  domain.ConfidenceConfirmed,
				Status:      domain.StatusConfirmed,
				Category:    domain.CategoryCookieSecurity,
				RuleID:      "COOKIE_MISSING_SECURE",
				OWASPMapping: "A05:2021-Security Misconfiguration",
				ASVSMapping:  "V3.4.1",
				CWE:         "CWE-614",
				Evidence: domain.Evidence{
					Type: domain.EvidenceCookieAttribute,
					Summary: fmt.Sprintf("Set-Cookie: %s", rawCookie),
					RawData: map[string]interface{}{"cookie_name": cookieName, "raw_cookie": rawCookie},
					Timestamp: time.Now().UTC(),
				},
				Impact: "Attacker on the same network path can sniff the cookie by injecting a plaintext HTTP request.",
				Recommendation: domain.Recommendation{
					Summary:     "Add the 'Secure' flag to all cookies set over HTTPS.",
					Remediation: fmt.Sprintf("Update cookie configuration: Set-Cookie: %s; Secure", parts[0]),
				},
				Verification: domain.Verification{
					Command:     fmt.Sprintf("curl -sI %s | grep -i '^set-cookie:'", target.NormalizedURL),
					Tool:        "curl",
					Description: "Inspect Set-Cookie flags",
				},
				CreatedAt: time.Now().UTC(),
			})
		}

		// 2. Missing HttpOnly flag on sensitive cookies
		isSensitiveName := strings.Contains(strings.ToLower(cookieName), "session") ||
			strings.Contains(strings.ToLower(cookieName), "token") ||
			strings.Contains(strings.ToLower(cookieName), "auth") ||
			strings.Contains(strings.ToLower(cookieName), "jwt") ||
			strings.Contains(strings.ToLower(cookieName), "id")

		if !isHttpOnly {
			severity := domain.SeverityMedium
			if isSensitiveName {
				severity = domain.SeverityHigh
			}

			res.Findings = append(res.Findings, domain.Finding{
				ID:          GenerateFindingID("fnd_cookie_no_httponly"),
				Title:       fmt.Sprintf("Cookie %q Missing 'HttpOnly' Attribute", cookieName),
				Description: fmt.Sprintf("Cookie %q lacks the 'HttpOnly' attribute, permitting client-side JavaScript access via document.cookie.", cookieName),
				Severity:    severity,
				Confidence:  domain.ConfidenceConfirmed,
				Status:      domain.StatusConfirmed,
				Category:    domain.CategoryCookieSecurity,
				RuleID:      "COOKIE_MISSING_HTTPONLY",
				OWASPMapping: "A05:2021-Security Misconfiguration",
				ASVSMapping:  "V3.4.2",
				CWE:         "CWE-1004",
				Evidence: domain.Evidence{
					Type: domain.EvidenceCookieAttribute,
					Summary: fmt.Sprintf("Set-Cookie: %s", rawCookie),
					RawData: map[string]interface{}{"cookie_name": cookieName, "raw_cookie": rawCookie},
					Timestamp: time.Now().UTC(),
				},
				Impact: "If any XSS vulnerability exists on the application, attackers can immediately exfiltrate this cookie.",
				Recommendation: domain.Recommendation{
					Summary:     "Set HttpOnly flag on authentication and session cookies.",
					Remediation: fmt.Sprintf("Update cookie configuration: Set-Cookie: %s; HttpOnly", parts[0]),
				},
				Verification: domain.Verification{
					Command:     fmt.Sprintf("curl -sI %s | grep -i '^set-cookie:'", target.NormalizedURL),
					Tool:        "curl",
					Description: "Inspect HttpOnly attribute",
				},
				CreatedAt: time.Now().UTC(),
			})
		}

		// 3. Missing or Lax SameSite attribute
		if !hasSameSite {
			res.Findings = append(res.Findings, domain.Finding{
				ID:          GenerateFindingID("fnd_cookie_no_samesite"),
				Title:       fmt.Sprintf("Cookie %q Missing 'SameSite' Attribute", cookieName),
				Description: fmt.Sprintf("Cookie %q does not define a 'SameSite' attribute (Lax, Strict, or None), increasing exposure to Cross-Site Request Forgery (CSRF).", cookieName),
				Severity:    domain.SeverityMedium,
				Confidence:  domain.ConfidenceConfirmed,
				Status:      domain.StatusConfirmed,
				Category:    domain.CategoryCookieSecurity,
				RuleID:      "COOKIE_MISSING_SAMESITE",
				OWASPMapping: "A01:2021-Broken Access Control",
				ASVSMapping:  "V3.4.3",
				CWE:         "CWE-1275",
				Evidence: domain.Evidence{
					Type: domain.EvidenceCookieAttribute,
					Summary: fmt.Sprintf("Set-Cookie: %s", rawCookie),
					RawData: map[string]interface{}{"cookie_name": cookieName, "raw_cookie": rawCookie},
					Timestamp: time.Now().UTC(),
				},
				Impact: "Cross-site requests triggered from external pages may automatically attach this cookie, facilitating CSRF.",
				Recommendation: domain.Recommendation{
					Summary:     "Configure SameSite=Lax or SameSite=Strict.",
					Remediation: fmt.Sprintf("Add SameSite=Lax to cookie: Set-Cookie: %s; SameSite=Lax", parts[0]),
				},
				Verification: domain.Verification{
					Command:     fmt.Sprintf("curl -sI %s | grep -i '^set-cookie:'", target.NormalizedURL),
					Tool:        "curl",
					Description: "Inspect SameSite attribute",
				},
				CreatedAt: time.Now().UTC(),
			})
		}
	}

	res.Duration = time.Since(start)
	return res, nil
}
