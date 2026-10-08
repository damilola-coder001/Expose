package scope

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const MaxRedirectHops = 5

// SafeRedirectChecker returns an http.Client CheckRedirect function enforcing hop limits and SSRF validation.
func SafeRedirectChecker(allowPrivate bool) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		// 1. Enforce max redirect hops
		if len(via) >= MaxRedirectHops {
			return fmt.Errorf("stopped after %d redirect hops (limit exceeded)", MaxRedirectHops)
		}

		// 2. Validate scheme
		scheme := strings.ToLower(req.URL.Scheme)
		if scheme != "http" && scheme != "https" {
			return fmt.Errorf("SSRF Protection: redirect to disallowed scheme %q", scheme)
		}

		// 3. Inspect destination host
		destHost := strings.ToLower(req.URL.Hostname())
		if !allowPrivate && IsRestrictedHostname(destHost) {
			return fmt.Errorf("SSRF Protection: redirect to restricted host %q blocked", destHost)
		}

		// 4. Resolve destination IP and check against restricted CIDRs
		if !allowPrivate {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", destHost)
			if err != nil {
				return fmt.Errorf("DNS resolution failed for redirect host %q: %w", destHost, err)
			}

			for _, ip := range ips {
				if IsRestrictedIP(ip) {
					return fmt.Errorf("SSRF Protection: redirect destination %q resolves to restricted IP %s", destHost, ip.String())
				}
			}
		}

		return nil
	}
}

// NewSafeHTTPClient creates a pre-configured http.Client with SafeTransport and SafeRedirectChecker.
func NewSafeHTTPClient(timeout time.Duration, allowPrivate bool) *http.Client {
	return &http.Client{
		Transport:     NewSafeTransport(timeout, allowPrivate),
		CheckRedirect: SafeRedirectChecker(allowPrivate),
		Timeout:       timeout,
	}
}
