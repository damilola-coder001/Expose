package probes

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/expose/expose/apps/api/internal/domain"
	"github.com/expose/expose/apps/api/internal/scope"
)

// AttackSurfaceProbe maps and catalogs what a target website exposes publicly.
type AttackSurfaceProbe struct{}

// NewAttackSurfaceProbe creates a new attack surface discovery probe.
func NewAttackSurfaceProbe() *AttackSurfaceProbe {
	return &AttackSurfaceProbe{}
}

func (p *AttackSurfaceProbe) Name() string {
	return "attack_surface"
}

func (p *AttackSurfaceProbe) Run(ctx context.Context, target *scope.TargetScope) (*ProbeResult, error) {
	start := time.Now()
	res := &ProbeResult{
		ProbeName: p.Name(),
		Findings:  make([]domain.Finding, 0),
		Assets:    make([]domain.Asset, 0),
	}

	client := scope.NewSafeHTTPClient(8*time.Second, target.AllowPrivate)
	baseURL := target.NormalizedURL
	rootHost := strings.ToLower(target.Host)

	pages := make([]domain.PageAsset, 0)
	apis := make([]domain.APIAsset, 0)
	assets := make([]domain.StaticAsset, 0)
	scripts := make([]domain.ScriptAsset, 0)
	forms := make([]domain.FormAsset, 0)
	externalMap := make(map[string]*extDepAccumulator)
	sitemapsList := make([]string, 0)

	// 1. Fetch Root Page
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		res.Duration = time.Since(start)
		return res, nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Expose-Security-Intelligence/1.0 (Attack Surface Mapper)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	var rootHTML string
	statusCode := 0
	if err == nil {
		statusCode = resp.StatusCode
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		rootHTML = string(bodyBytes)
		_ = resp.Body.Close()

		pages = append(pages, domain.PageAsset{
			URL:           resp.Request.URL.String(),
			Path:          resp.Request.URL.Path,
			Title:         extractHTMLTitle(rootHTML),
			StatusCode:    statusCode,
			IsInternal:    true,
			DiscoveredVia: "root_crawl",
		})
	}

	// 2. Fetch robots.txt
	robotsURL := resolveURL(baseURL, "/robots.txt")
	robotsAsset := &domain.RobotsTxtAsset{
		DisallowedPaths: make([]string, 0),
		AllowedPaths:    make([]string, 0),
		Sitemaps:        make([]string, 0),
	}

	rReq, rErr := http.NewRequestWithContext(ctx, http.MethodGet, robotsURL, nil)
	if rErr == nil {
		rReq.Header.Set("User-Agent", req.Header.Get("User-Agent"))
		if rResp, err := client.Do(rReq); err == nil {
			if rResp.StatusCode == 200 {
				rBytes, _ := io.ReadAll(io.LimitReader(rResp.Body, 64*1024))
				_ = rResp.Body.Close()
				rText := string(rBytes)
				if strings.Contains(strings.ToLower(rText), "user-agent") {
					robotsAsset.IsPresent = true
					lines := strings.Split(rText, "\n")
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if line == "" || strings.HasPrefix(line, "#") {
							continue
						}
						lower := strings.ToLower(line)
						if strings.HasPrefix(lower, "disallow:") {
							parts := strings.SplitN(line, ":", 2)
							if len(parts) > 1 && strings.TrimSpace(parts[1]) != "" {
								robotsAsset.DisallowedPaths = append(robotsAsset.DisallowedPaths, strings.TrimSpace(parts[1]))
							}
						} else if strings.HasPrefix(lower, "allow:") {
							parts := strings.SplitN(line, ":", 2)
							if len(parts) > 1 && strings.TrimSpace(parts[1]) != "" {
								robotsAsset.AllowedPaths = append(robotsAsset.AllowedPaths, strings.TrimSpace(parts[1]))
							}
						} else if strings.HasPrefix(lower, "sitemap:") {
							parts := strings.SplitN(line, ":", 2)
							if len(parts) > 1 && strings.TrimSpace(parts[1]) != "" {
								sm := strings.TrimSpace(parts[1])
								robotsAsset.Sitemaps = append(robotsAsset.Sitemaps, sm)
								sitemapsList = append(sitemapsList, sm)
							}
						}
					}

					// Flag sensitive disallowed paths
					sensitiveDisallowed := make([]string, 0)
					for _, p := range robotsAsset.DisallowedPaths {
						pLower := strings.ToLower(p)
						for _, sens := range []string{"admin", "backup", "secret", "private", "internal", "config", "debug"} {
							if strings.Contains(pLower, sens) {
								sensitiveDisallowed = append(sensitiveDisallowed, p)
								break
							}
						}
					}

					if len(sensitiveDisallowed) > 0 {
						sample := sensitiveDisallowed
						if len(sample) > 3 {
							sample = sample[:3]
						}
						res.Findings = append(res.Findings, domain.Finding{
							ID:          GenerateFindingID("fnd_robots_sensitive_paths"),
							Title:       fmt.Sprintf("Sensitive Paths Disclosed in robots.txt (%s)", strings.Join(sample, ", ")),
							Description: fmt.Sprintf("robots.txt explicitly lists sensitive internal paths: %s.", strings.Join(sensitiveDisallowed, ", ")),
							Severity:    domain.SeverityLow,
							Confidence:  domain.ConfidenceConfirmed,
							Status:      domain.StatusObserved,
							Category:    domain.CategoryInformationExposure,
							RuleID:      "ROBOTS_TXT_SENSITIVE_DISCLOSURE",
							Evidence: domain.Evidence{
								Type:    domain.EvidenceHTTPExchange,
								Summary: fmt.Sprintf("Disallowed sensitive paths found in robots.txt: %s", strings.Join(sensitiveDisallowed, ", ")),
								RawData: map[string]interface{}{"sensitive_disallowed": sensitiveDisallowed},
								Command: fmt.Sprintf("curl -sL %s | grep -i Disallow", robotsURL),
								Timestamp: time.Now().UTC(),
							},
							Impact: "Search engines respect Disallow rules, but adversaries use robots.txt as an attack map to locate unlinked admin consoles and internal endpoints.",
							Recommendation: domain.Recommendation{
								Summary:     "Do not rely on robots.txt for access control. Enforce server-side authentication and restrict administrative consoles at the reverse proxy.",
								Remediation: "Remove internal paths from robots.txt and protect administrative consoles with network access control and multi-factor authentication.",
							},
							Verification: domain.Verification{
								Command:     fmt.Sprintf("curl -sL %s | grep -i Disallow", robotsURL),
								Tool:        "curl",
								Description: "Inspect robots.txt for sensitive disallowed routes",
							},
							CreatedAt: time.Now().UTC(),
						})
					}
				}
			} else {
				_ = rResp.Body.Close()
			}
		}
	}

	// 3. Inspect sitemaps
	if len(sitemapsList) == 0 {
		sitemapsList = append(sitemapsList, resolveURL(baseURL, "/sitemap.xml"))
	}

	locRegex := regexp.MustCompile(`(?i)<loc>([^<]+)</loc>`)
	for _, smURL := range sitemapsList {
		if len(pages) >= 50 {
			break
		}
		smReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, smURL, nil)
		if smReq != nil {
			smReq.Header.Set("User-Agent", req.Header.Get("User-Agent"))
			if smResp, err := client.Do(smReq); err == nil {
				if smResp.StatusCode == 200 {
					smBytes, _ := io.ReadAll(io.LimitReader(smResp.Body, 128*1024))
					_ = smResp.Body.Close()
					locMatches := locRegex.FindAllStringSubmatch(string(smBytes), 25)
					for _, m := range locMatches {
						if len(m) > 1 {
							u := strings.TrimSpace(m[1])
							parsedU, pErr := url.Parse(u)
							if pErr == nil {
								isExisting := false
								for _, existing := range pages {
									if existing.URL == u {
										isExisting = true
										break
									}
								}
								if !isExisting {
									pages = append(pages, domain.PageAsset{
										URL:           u,
										Path:          parsedU.Path,
										IsInternal:    strings.EqualFold(parsedU.Host, rootHost),
										DiscoveredVia: "sitemap",
									})
								}
							}
						}
					}
				} else {
					_ = smResp.Body.Close()
				}
			}
		}
	}

	// 4. Parse Root DOM
	if rootHTML != "" {
		// A. Anchor Links
		aRegex := regexp.MustCompile(`(?i)<a\s+[^>]*href=["']([^"'#\s]+)["']`)
		for _, m := range aRegex.FindAllStringSubmatch(rootHTML, -1) {
			if len(m) > 1 {
				rawHref := m[1]
				absURL := resolveURL(baseURL, rawHref)
				parsed, pErr := url.Parse(absURL)
				if pErr == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") {
					isInt := strings.EqualFold(parsed.Host, rootHost)
					isExisting := false
					for _, existing := range pages {
						if existing.URL == absURL {
							isExisting = true
							break
						}
					}
					if !isExisting && len(pages) < 100 {
						pages = append(pages, domain.PageAsset{
							URL:           absURL,
							Path:          parsed.Path,
							IsInternal:    isInt,
							DiscoveredVia: "html_anchor",
						})
					}
					if !isInt && parsed.Host != "" {
						registerExternal(externalMap, parsed.Host, absURL)
					}
				}
			}
		}

		// B. Scripts
		scriptRegex := regexp.MustCompile(`(?i)<script\s+([^>]*)>(.*?)</script>`)
		srcRegex := regexp.MustCompile(`(?i)src=["']([^"']+)["']`)
		integrityRegex := regexp.MustCompile(`(?i)integrity=["']([^"']+)["']`)

		for _, m := range scriptRegex.FindAllStringSubmatch(rootHTML, -1) {
			if len(m) > 1 {
				attrs := m[1]
				srcMatches := srcRegex.FindStringSubmatch(attrs)
				hasSRI := strings.Contains(strings.ToLower(attrs), "integrity=")
				var sriHash string
				if intMatches := integrityRegex.FindStringSubmatch(attrs); len(intMatches) > 1 {
					sriHash = intMatches[1]
				}

				if len(srcMatches) > 1 {
					srcURL := resolveURL(baseURL, srcMatches[1])
					parsedSrc, pErr := url.Parse(srcURL)
					if pErr == nil {
						isExt := !strings.EqualFold(parsedSrc.Host, rootHost)
						var cdn string
						if isExt {
							cdn = classifyCDN(parsedSrc.Host)
							registerExternal(externalMap, parsedSrc.Host, srcURL)
						}
						scripts = append(scripts, domain.ScriptAsset{
							URL:         srcURL,
							IsExternal:  isExt,
							CDNProvider: cdn,
							HasSRI:      hasSRI,
							SRIHash:     sriHash,
						})
					}
				}
			}
		}

		// C. Stylesheets and static assets
		linkRegex := regexp.MustCompile(`(?i)<link\s+[^>]+>`)
		hrefRegex := regexp.MustCompile(`(?i)href=["']([^"']+)["']`)
		relRegex := regexp.MustCompile(`(?i)rel=["']([^"']+)["']`)

		for _, tag := range linkRegex.FindAllString(rootHTML, -1) {
			hrefMatch := hrefRegex.FindStringSubmatch(tag)
			relMatch := relRegex.FindStringSubmatch(tag)
			if len(hrefMatch) > 1 {
				aURL := resolveURL(baseURL, hrefMatch[1])
				rel := "stylesheet"
				if len(relMatch) > 1 {
					rel = strings.ToLower(relMatch[1])
				}
				aType := "stylesheet"
				if strings.Contains(rel, "icon") {
					aType = "icon"
				} else if strings.Contains(rel, "manifest") {
					aType = "manifest"
				}

				parsedA, pErr := url.Parse(aURL)
				if pErr == nil {
					isExt := !strings.EqualFold(parsedA.Host, rootHost)
					assets = append(assets, domain.StaticAsset{
						URL:        aURL,
						AssetType:  aType,
						IsExternal: isExt,
					})
					if isExt && parsedA.Host != "" {
						registerExternal(externalMap, parsedA.Host, aURL)
					}
				}
			}
		}

		// Images
		imgRegex := regexp.MustCompile(`(?i)<img\s+[^>]*src=["']([^"']+)["']`)
		for _, m := range imgRegex.FindAllStringSubmatch(rootHTML, -1) {
			if len(m) > 1 {
				imgURL := resolveURL(baseURL, m[1])
				parsedImg, pErr := url.Parse(imgURL)
				if pErr == nil {
					isExt := !strings.EqualFold(parsedImg.Host, rootHost)
					assets = append(assets, domain.StaticAsset{
						URL:        imgURL,
						AssetType:  "image",
						IsExternal: isExt,
					})
					if isExt && parsedImg.Host != "" {
						registerExternal(externalMap, parsedImg.Host, imgURL)
					}
				}
			}
		}

		// D. Forms
		formRegex := regexp.MustCompile(`(?is)<form\s+([^>]*)>(.*?)</form>`)
		actionRegex := regexp.MustCompile(`(?i)action=["']([^"']*)["']`)
		methodRegex := regexp.MustCompile(`(?i)method=["']([^"']*)["']`)
		inputRegex := regexp.MustCompile(`(?i)<input\s+([^>]+)>`)
		typeRegex := regexp.MustCompile(`(?i)type=["']([^"']*)["']`)
		nameRegex := regexp.MustCompile(`(?i)name=["']([^"']*)["']`)

		for _, formMatch := range formRegex.FindAllStringSubmatch(rootHTML, -1) {
			if len(formMatch) > 2 {
				fAttrs := formMatch[1]
				fInner := formMatch[2]

				act := ""
				if actMatch := actionRegex.FindStringSubmatch(fAttrs); len(actMatch) > 1 {
					act = actMatch[1]
				}
				actURL := resolveURL(baseURL, act)

				method := "GET"
				if methMatch := methodRegex.FindStringSubmatch(fAttrs); len(methMatch) > 1 {
					method = strings.ToUpper(methMatch[1])
				}

				inputs := make([]domain.FormInput, 0)
				hasPW := false
				for _, inpMatch := range inputRegex.FindAllStringSubmatch(fInner, -1) {
					if len(inpMatch) > 1 {
						iAttrs := inpMatch[1]
						iType := "text"
						if tMatch := typeRegex.FindStringSubmatch(iAttrs); len(tMatch) > 1 {
							iType = strings.ToLower(tMatch[1])
						}
						iName := "unnamed"
						if nMatch := nameRegex.FindStringSubmatch(iAttrs); len(nMatch) > 1 {
							iName = nMatch[1]
						}

						isSens := iType == "password" || iType == "token" || iType == "ssn"
						if strings.Contains(strings.ToLower(iName), "password") || strings.Contains(strings.ToLower(iName), "token") || strings.Contains(strings.ToLower(iName), "secret") {
							isSens = true
						}
						if iType == "password" {
							hasPW = true
						}

						inputs = append(inputs, domain.FormInput{
							Name:        iName,
							InputType:   iType,
							IsSensitive: isSens,
						})
					}
				}

				isSec := !strings.HasPrefix(strings.ToLower(actURL), "http://")
				forms = append(forms, domain.FormAsset{
					Action:         actURL,
					Method:         method,
					Inputs:         inputs,
					HasPassword:    hasPW,
					IsSecureAction: isSec,
				})
			}
		}

		// E. API Endpoints Referenced in HTML
		apiPatterns := []*regexp.Regexp{
			regexp.MustCompile(`["'](/api/v[0-9]+/[a-zA-Z0-9_\-/]+)["']`),
			regexp.MustCompile(`["'](/api/[a-zA-Z0-9_\-/]+)["']`),
			regexp.MustCompile(`["'](/v[0-9]+/[a-zA-Z0-9_\-/]+)["']`),
		}
		seenAPIs := make(map[string]bool)
		for _, pat := range apiPatterns {
			for _, m := range pat.FindAllStringSubmatch(rootHTML, -1) {
				if len(m) > 1 {
					endpoint := m[1]
					if !seenAPIs[endpoint] && !strings.HasSuffix(endpoint, ".js") && !strings.HasSuffix(endpoint, ".css") {
						seenAPIs[endpoint] = true
						apis = append(apis, domain.APIAsset{
							Path:     endpoint,
							Method:   "ANY",
							IsPublic: true,
						})
					}
				}
			}
		}
	}

	// Build External Dependencies list
	externalDeps := make([]domain.ExternalDependency, 0, len(externalMap))
	for origin, acc := range externalMap {
		samples := acc.samples
		if len(samples) > 3 {
			samples = samples[:3]
		}
		externalDeps = append(externalDeps, domain.ExternalDependency{
			Origin:        origin,
			Category:      acc.category,
			ResourceCount: acc.count,
			SampleURLs:    samples,
		})
	}

	summary := fmt.Sprintf("Website exposes %d Page(s), %d API Endpoint(s), %d Static Resource(s), %d JavaScript Bundle(s), %d Submission Form(s), and relies on %d External Third-Party Origin(s).",
		len(pages), len(apis), len(assets), len(scripts), len(forms), len(externalDeps))

	attackSurface := &domain.AttackSurface{
		Target:               baseURL,
		Pages:                pages,
		APIs:                 apis,
		Assets:               assets,
		Scripts:              scripts,
		Forms:                forms,
		ExternalDependencies: externalDeps,
		RobotsTxt:            robotsAsset,
		Sitemaps:             sitemapsList,
		ExposureSummary:      summary,
		DiscoveredAt:         time.Now().UTC(),
	}

	res.AttackSurface = attackSurface

	// Neutral catalog finding
	res.Findings = append(res.Findings, domain.Finding{
		ID:          GenerateFindingID("fnd_attack_surface_inventory"),
		Title:       "Public Attack Surface Inventory Completed",
		Description: summary,
		Severity:    domain.SeverityInfo,
		Confidence:  domain.ConfidenceInformational,
		Status:      domain.StatusObserved,
		Category:    domain.CategoryAttackSurface,
		RuleID:      "ATTACK_SURFACE_INVENTORY",
		Evidence: domain.Evidence{
			Type:    domain.EvidenceDOMContent,
			Summary: summary,
			RawData: map[string]interface{}{
				"pages_count":   len(pages),
				"apis_count":    len(apis),
				"assets_count":  len(assets),
				"scripts_count": len(scripts),
				"forms_count":   len(forms),
			},
			Timestamp: time.Now().UTC(),
		},
		Impact: "Cataloging publicly exposed pages, APIs, forms, and external dependencies defines the security perimeter for defense-in-depth reviews.",
		Recommendation: domain.Recommendation{
			Summary:     "Ensure all exposed endpoints enforce proper access controls and external dependencies are pinned with Subresource Integrity.",
			Remediation: "Review all exposed routes and external script origins against your organization's approved vendor inventory.",
		},
		Verification: domain.Verification{
			Command:     fmt.Sprintf("curl -sL %s | grep -Eo '(href|src)=\"[^\"]+\"' | head -n 20", baseURL),
			Tool:        "curl",
			Description: "Verify exposed public resources and endpoints",
		},
		CreatedAt: time.Now().UTC(),
	})

	res.Duration = time.Since(start)
	return res, nil
}

type extDepAccumulator struct {
	category string
	count    int
	samples  []string
}

func registerExternal(m map[string]*extDepAccumulator, origin, url string) {
	clean := strings.ToLower(origin)
	acc, exists := m[clean]
	if !exists {
		acc = &extDepAccumulator{
			category: classifyExternalOrigin(clean),
			count:    0,
			samples:  make([]string, 0),
		}
		m[clean] = acc
	}
	acc.count++
	hasURL := false
	for _, s := range acc.samples {
		if s == url {
			hasURL = true
			break
		}
	}
	if !hasURL {
		acc.samples = append(acc.samples, url)
	}
}

func classifyExternalOrigin(origin string) string {
	for _, c := range []string{"cdn", "unpkg", "jsdelivr", "cloudflare", "static"} {
		if strings.Contains(origin, c) {
			return "CDN"
		}
	}
	for _, a := range []string{"analytics", "segment", "mixpanel", "hotjar", "clarity", "sentry"} {
		if strings.Contains(origin, a) {
			return "Analytics"
		}
	}
	for _, f := range []string{"fonts", "typekit"} {
		if strings.Contains(origin, f) {
			return "Fonts"
		}
	}
	for _, s := range []string{"facebook", "twitter", "linkedin", "instagram", "tiktok"} {
		if strings.Contains(origin, s) {
			return "Social"
		}
	}
	for _, ad := range []string{"doubleclick", "adservice", "googleadservices", "ads"} {
		if strings.Contains(origin, ad) {
			return "Advertising"
		}
	}
	for _, auth := range []string{"firebase", "auth0", "okta", "cognito"} {
		if strings.Contains(origin, auth) {
			return "Authentication"
		}
	}
	return "Third-Party Service"
}

func classifyCDN(host string) string {
	lower := strings.ToLower(host)
	switch {
	case strings.Contains(lower, "cloudflare"):
		return "Cloudflare"
	case strings.Contains(lower, "jsdelivr"):
		return "jsDelivr"
	case strings.Contains(lower, "unpkg"):
		return "unpkg"
	case strings.Contains(lower, "cdnjs"):
		return "cdnjs"
	case strings.Contains(lower, "googleapis"):
		return "Google Hosted Libraries"
	default:
		return "External CDN"
	}
}

func extractHTMLTitle(html string) string {
	re := regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	m := re.FindStringSubmatch(html)
	if len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return "Untitled Document"
}

func resolveURL(base, ref string) string {
	if ref == "" {
		return base
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return ref
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return baseURL.ResolveReference(refURL).String()
}
