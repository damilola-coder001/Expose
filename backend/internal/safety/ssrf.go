package safety

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/expose/expose-backend/internal/models"
)

// Private/restricted IP networks
var privateCIDRs = []string{
	"127.0.0.0/8",      // Loopback
	"10.0.0.0/8",       // RFC 1918 Class A
	"172.16.0.0/12",    // RFC 1918 Class B
	"192.168.0.0/16",   // RFC 1918 Class C
	"169.254.0.0/16",   // Link-Local / Cloud Metadata
	"0.0.0.0/8",        // Current Network
	"224.0.0.0/4",      // Multicast
	"240.0.0.0/4",      // Reserved
	"::1/128",          // IPv6 Loopback
	"fc00::/7",         // IPv6 Unique Local Address
	"fe80::/10",        // IPv6 Link-Local
}

var parsedPrivateNets []*net.IPNet

func init() {
	for _, cidr := range privateCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			parsedPrivateNets = append(parsedPrivateNets, ipNet)
		}
	}
}

// IsPrivateIP checks if an IP belongs to a private/loopback/link-local subnet.
func IsPrivateIP(ip net.IP) bool {
	for _, ipNet := range parsedPrivateNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateTarget parses, normalizes, and applies SSRF security boundaries to a target.
func ValidateTarget(rawTarget string, allowPrivate bool) (*models.TargetScope, error) {
	cleaned := strings.TrimSpace(rawTarget)
	if cleaned == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	targetURL := cleaned
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme '%s' (only http and https are permitted)", scheme)
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return nil, fmt.Errorf("target must contain a valid hostname or IP address")
	}

	port := 443
	if parsed.Port() != "" {
		p, err := strconv.Atoi(parsed.Port())
		if err == nil && p > 0 && p <= 65535 {
			port = p
		}
	} else if scheme == "http" {
		port = 80
	}

	normalizedURL := fmt.Sprintf("%s://%s", scheme, hostname)
	if parsed.Port() != "" {
		normalizedURL = fmt.Sprintf("%s://%s:%d", scheme, hostname, port)
	}

	// Resolve IPs for target
	resolvedIPs, err := net.LookupIP(hostname)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for host '%s': %w", hostname, err)
	}

	var ipStrings []string
	hasPrivateIP := false
	var privateMatches []string

	for _, ip := range resolvedIPs {
		ipStr := ip.String()
		ipStrings = append(ipStrings, ipStr)
		if IsPrivateIP(ip) {
			hasPrivateIP = true
			privateMatches = append(privateMatches, ipStr)
		}
	}

	sort.Strings(ipStrings)

	if hasPrivateIP && !allowPrivate {
		return nil, fmt.Errorf(
			"SSRF Safety Guard: Target '%s' resolves to restricted IP(s): %s. "+
				"Public scanning forbids private/internal infrastructure. Pass allow_private=true for authorized internal testing.",
			hostname, strings.Join(privateMatches, ", "),
		)
	}

	return &models.TargetScope{
		RawTarget:     rawTarget,
		NormalizedURL: normalizedURL,
		Scheme:        scheme,
		Host:          hostname,
		Port:          port,
		ResolvedIPs:   ipStrings,
		IsPrivate:     hasPrivateIP,
		AllowPrivate:  allowPrivate,
	}, nil
}

// NewSafeDialer creates a net.Dialer that intercepts the remote socket address
// immediately prior to connecting (Control hook), preventing TOCTOU DNS rebinding attacks.
func NewSafeDialer(allowPrivate bool) *net.Dialer {
	return &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			if allowPrivate {
				return nil
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}
			ip := net.ParseIP(host)
			if ip != nil && IsPrivateIP(ip) {
				return fmt.Errorf("SSRF safety guard: connection blocked to private/restricted IP: %s", ip.String())
			}
			return nil
		},
	}
}

// NewSafeHTTPClient creates a production-grade http.Client with anti-DNS-rebinding
// socket-level enforcement and strict timeouts.
func NewSafeHTTPClient(allowPrivate bool, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	transport := &http.Transport{
		DialContext:         NewSafeDialer(allowPrivate).DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

