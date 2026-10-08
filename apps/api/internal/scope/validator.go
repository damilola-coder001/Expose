package scope

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TargetScope defines the validated, safe target attributes.
type TargetScope struct {
	RawTarget     string   `json:"raw_target"`
	NormalizedURL string   `json:"normalized_url"`
	Scheme        string   `json:"scheme"`
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	ResolvedIPs   []string `json:"resolved_ips"`
	IsPrivate     bool     `json:"is_private"`
	AllowPrivate  bool     `json:"allow_private"`
}

// ValidateTarget normalizes, validates protocol, checks SSRF blocklists, and builds a TargetScope.
func ValidateTarget(rawTarget string, allowPrivate bool) (*TargetScope, error) {
	cleaned := strings.TrimSpace(rawTarget)
	if cleaned == "" {
		return nil, fmt.Errorf("target URL cannot be empty")
	}

	// Default to https if no scheme provided
	targetURL := cleaned
	if !strings.Contains(targetURL, "://") {
		targetURL = "https://" + targetURL
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("malformed target URL: %w", err)
	}

	// 1. Strict protocol validation
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported protocol scheme %q: only http and https are permitted", scheme)
	}

	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return nil, fmt.Errorf("target URL does not contain a valid hostname")
	}

	// 2. Reject internal/metadata hostnames
	if !allowPrivate && IsRestrictedHostname(hostname) {
		return nil, fmt.Errorf("SSRF Protection: target %q is an internal or restricted hostname", hostname)
	}

	// 3. Port determination & validation
	port := 443
	if parsed.Port() != "" {
		p, pErr := strconv.Atoi(parsed.Port())
		if pErr != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q: must be an integer between 1 and 65535", parsed.Port())
		}
		port = p
	} else if scheme == "http" {
		port = 80
	}

	normalizedURL := fmt.Sprintf("%s://%s", scheme, hostname)
	if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
		normalizedURL = fmt.Sprintf("%s://%s:%d", scheme, hostname, port)
	}

	// 4. DNS Resolution & Private IP check
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	resolver := net.DefaultResolver
	ips, err := resolver.LookupIP(ctx, "ip", hostname)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %q: %w", hostname, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("DNS resolution for %q returned 0 IP addresses", hostname)
	}

	var ipStrings []string
	isPrivate := false
	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.String())
		if IsRestrictedIP(ip) {
			isPrivate = true
		}
	}

	if isPrivate && !allowPrivate {
		return nil, fmt.Errorf("SSRF Protection: destination %q resolves to restricted/private IP addresses: %s", hostname, strings.Join(ipStrings, ", "))
	}

	return &TargetScope{
		RawTarget:     rawTarget,
		NormalizedURL: normalizedURL,
		Scheme:        scheme,
		Host:          hostname,
		Port:          port,
		ResolvedIPs:   ipStrings,
		IsPrivate:     isPrivate,
		AllowPrivate:  allowPrivate,
	}, nil
}
