package probes

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/expose/expose-backend/internal/models"
)

type CookieProbe struct{}

func NewCookieProbe() *CookieProbe {
	return &CookieProbe{}
}

func (p *CookieProbe) Name() string {
	return "cookie_security"
}

func (p *CookieProbe) Category() models.Category {
	return models.CategoryCookieSecurity
}

func (p *CookieProbe) Execute(ctx context.Context, target *models.TargetScope) ([]models.Finding, error) {
	var findings []models.Finding

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   8 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", target.NormalizedURL, nil)
	if err != nil {
		return findings, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Expose-Security-Intelligence/0.1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return findings, nil
	}
	defer resp.Body.Close()

	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		return findings, nil
	}

	sessionKeywords := []string{"session", "auth", "token", "jwt", "id", "sid", "user", "login", "key"}

	for _, rawCookie := range cookies {
		parts := strings.Split(rawCookie, ";")
		if len(parts) == 0 {
			continue
		}

		nameVal := strings.TrimSpace(parts[0])
		eqIdx := strings.Index(nameVal, "=")
		if eqIdx == -1 {
			continue
		}
		cookieName := nameVal[:eqIdx]

		cookieLower := strings.ToLower(rawCookie)
		isSecure := strings.Contains(cookieLower, "secure")
		isHTTPOnly := strings.Contains(cookieLower, "httponly")
		hasSameSite := strings.Contains(cookieLower, "samesite")

		isLikelySession := false
		for _, kw := range sessionKeywords {
			if strings.Contains(strings.ToLower(cookieName), kw) {
				isLikelySession = true
				break
			}
		}

		// Check 1: Missing Secure Flag on HTTPS
		if target.Scheme == "https" && !isSecure {
			evidence := models.Evidence{
				Type:     models.EvidenceHTTPExchange,
				Summary:  fmt.Sprintf("Cookie '%s' is set over HTTPS without the 'Secure' attribute.", cookieName),
				Response: map[string]interface{}{"set_cookie": rawCookie, "cookie_name": cookieName},
			}
			findings = append(findings, CreateFinding(
				p.Name(), target, models.CategoryCookieSecurity, models.SeverityMedium,
				models.ConfidenceConfirmed, models.StatusConfirmed,
				fmt.Sprintf("Insecure Cookie: Missing 'Secure' Attribute on '%s'", cookieName),
				fmt.Sprintf("Cookie '%s' was transmitted without the 'Secure' flag.", cookieName),
				"Browsers will send this cookie over unencrypted HTTP connections if any asset is requested insecurely.",
				fmt.Sprintf("Append '; Secure' to the Set-Cookie directive for '%s'.", cookieName),
				fmt.Sprintf("curl -sI %s | grep -i Set-Cookie", target.NormalizedURL),
				"CWE-614", "", evidence,
			))
		}

		// Check 2: Missing HttpOnly Flag
		if !isHTTPOnly {
			sev := models.SeverityLow
			if isLikelySession {
				sev = models.SeverityMedium
			}
			evidence := models.Evidence{
				Type:     models.EvidenceHTTPExchange,
				Summary:  fmt.Sprintf("Cookie '%s' lacks the 'HttpOnly' flag.", cookieName),
				Response: map[string]interface{}{"set_cookie": rawCookie, "cookie_name": cookieName},
			}
			findings = append(findings, CreateFinding(
				p.Name(), target, models.CategoryCookieSecurity, sev,
				models.ConfidenceConfirmed, models.StatusConfirmed,
				fmt.Sprintf("Insecure Cookie: Missing 'HttpOnly' Attribute on '%s'", cookieName),
				fmt.Sprintf("Cookie '%s' lacks the 'HttpOnly' attribute.", cookieName),
				"Client-side JavaScript can read this cookie value via document.cookie, exposing it to exfiltration via XSS.",
				fmt.Sprintf("Append '; HttpOnly' to the Set-Cookie directive for '%s'.", cookieName),
				fmt.Sprintf("curl -sI %s | grep -i Set-Cookie", target.NormalizedURL),
				"CWE-1004", "", evidence,
			))
		}

		// Check 3: Missing SameSite Flag
		if !hasSameSite {
			evidence := models.Evidence{
				Type:     models.EvidenceHTTPExchange,
				Summary:  fmt.Sprintf("Cookie '%s' does not define a 'SameSite' attribute.", cookieName),
				Response: map[string]interface{}{"set_cookie": rawCookie, "cookie_name": cookieName},
			}
			findings = append(findings, CreateFinding(
				p.Name(), target, models.CategoryCookieSecurity, models.SeverityLow,
				models.ConfidenceConfirmed, models.StatusConfirmed,
				fmt.Sprintf("Insecure Cookie: Missing 'SameSite' Attribute on '%s'", cookieName),
				fmt.Sprintf("Cookie '%s' does not declare a SameSite attribute.", cookieName),
				"Without SameSite, cookies are attached to cross-origin requests, leaving endpoints vulnerable to CSRF.",
				fmt.Sprintf("Append '; SameSite=Lax' (or SameSite=Strict) to the Set-Cookie directive for '%s'.", cookieName),
				fmt.Sprintf("curl -sI %s | grep -i Set-Cookie", target.NormalizedURL),
				"CWE-1275", "", evidence,
			))
		}
	}

	return findings, nil
}
