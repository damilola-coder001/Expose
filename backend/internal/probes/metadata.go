package probes

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/expose/expose-backend/internal/models"
)

type MetadataProbe struct{}

func NewMetadataProbe() *MetadataProbe {
	return &MetadataProbe{}
}

func (p *MetadataProbe) Name() string {
	return "security_metadata"
}

func (p *MetadataProbe) Category() models.Category {
	return models.CategorySecurityMetadata
}

func (p *MetadataProbe) Execute(ctx context.Context, target *models.TargetScope) ([]models.Finding, error) {
	var findings []models.Finding

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   8 * time.Second,
	}

	// 1. RFC 9116 security.txt
	secURL := fmt.Sprintf("%s/.well-known/security.txt", target.NormalizedURL)
	req, _ := http.NewRequestWithContext(ctx, "GET", secURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Expose-Security-Intelligence/0.1.0)")

	secResp, err := client.Do(req)
	var secBody string
	if err == nil {
		defer secResp.Body.Close()
		if secResp.StatusCode == 200 {
			b, _ := io.ReadAll(io.LimitReader(secResp.Body, 16384))
			secBody = string(b)
		}
	}

	if secBody == "" || !strings.Contains(strings.ToLower(secBody), "contact:") {
		evidence := models.Evidence{
			Type:    models.EvidenceSecurityTxt,
			Summary: fmt.Sprintf("No valid RFC 9116 security.txt found at %s.", secURL),
			Request: map[string]interface{}{"url": secURL},
		}
		findings = append(findings, CreateFinding(
			p.Name(), target, models.CategorySecurityMetadata, models.SeverityInfo,
			models.ConfidenceConfirmed, models.StatusConfirmed,
			"Missing RFC 9116 'security.txt' Policy",
			"The website does not publish a standard 'security.txt' file at '/.well-known/security.txt'.",
			"Security researchers discovering vulnerabilities have no designated reporting channel or PGP key.",
			fmt.Sprintf("Publish '/.well-known/security.txt' with: Contact: mailto:security@%s", target.Host),
			fmt.Sprintf("curl -sL %s", secURL),
			"CWE-358", "", evidence,
		))
	} else {
		evidence := models.Evidence{
			Type:     models.EvidenceSecurityTxt,
			Summary:  fmt.Sprintf("Valid RFC 9116 security.txt published at %s.", secURL),
			Response: map[string]interface{}{"sample": secBody[:min(len(secBody), 300)]},
		}
		findings = append(findings, CreateFinding(
			p.Name(), target, models.CategorySecurityMetadata, models.SeverityInfo,
			models.ConfidenceConfirmed, models.StatusObserved,
			"RFC 9116 'security.txt' Policy Published",
			"The website publishes a standard security contact file facilitating responsible vulnerability disclosure.",
			"Maintains clear communication channels for security researchers.",
			"Review security.txt directives and PGP keys annually.",
			fmt.Sprintf("curl -sL %s", secURL),
			"", "", evidence,
		))
	}

	// 2. robots.txt
	robotsURL := fmt.Sprintf("%s/robots.txt", target.NormalizedURL)
	rReq, _ := http.NewRequestWithContext(ctx, "GET", robotsURL, nil)
	rReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Expose-Security-Intelligence/0.1.0)")

	rResp, err := client.Do(rReq)
	if err == nil {
		defer rResp.Body.Close()
		if rResp.StatusCode == 200 {
			scanner := bufio.NewScanner(io.LimitReader(rResp.Body, 32768))
			sensitivePats := []*regexp.Regexp{
				regexp.MustCompile(`(?i)/admin`),
				regexp.MustCompile(`(?i)/internal`),
				regexp.MustCompile(`(?i)/private`),
				regexp.MustCompile(`(?i)/staging`),
				regexp.MustCompile(`(?i)/backup`),
				regexp.MustCompile(`(?i)/\.git`),
			}

			var matchedPaths []string
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(strings.ToLower(line), "disallow:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) > 1 {
						path := strings.TrimSpace(parts[1])
						for _, pat := range sensitivePats {
							if pat.MatchString(path) {
								matchedPaths = append(matchedPaths, path)
								break
							}
						}
					}
				}
			}

			if len(matchedPaths) > 0 {
				evidence := models.Evidence{
					Type:     models.EvidenceHTTPExchange,
					Summary:  fmt.Sprintf("robots.txt disallows sensitive routes: %s", strings.Join(matchedPaths[:min(len(matchedPaths), 4)], ", ")),
					Response: map[string]interface{}{"disallowed_routes": matchedPaths},
				}
				findings = append(findings, CreateFinding(
					p.Name(), target, models.CategoryInformationDisclosure, models.SeverityLow,
					models.ConfidenceConfirmed, models.StatusConfirmed,
					"Sensitive Internal Path Disclosure in robots.txt",
					fmt.Sprintf("The robots.txt file explicitly publicizes internal or administrative routes: %s.", strings.Join(matchedPaths, ", ")),
					"Adversaries inspect robots.txt to discover unauthenticated admin interfaces, staging routes, or forgotten backup scripts.",
					"Protect internal routes using authentication and IP restrictions; do not rely on robots.txt for security.",
					fmt.Sprintf("curl -sL %s | grep -i Disallow", robotsURL),
					"CWE-200", "", evidence,
				))
			}
		}
	}

	return findings, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
