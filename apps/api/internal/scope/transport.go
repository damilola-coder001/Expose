package scope

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// SafeTransport provides dial-time IP validation and socket pinning to defeat DNS rebinding attacks.
type SafeTransport struct {
	allowPrivate bool
	dialer       *net.Dialer
	transport    *http.Transport
}

// NewSafeTransport constructs an http.Transport fortified against SSRF and DNS rebinding.
func NewSafeTransport(timeout time.Duration, allowPrivate bool) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 15 * time.Second,
	}

	st := &SafeTransport{
		allowPrivate: allowPrivate,
		dialer:       dialer,
	}

	st.transport = &http.Transport{
		DialContext:           st.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false, // Enforce strict certificate validation by default
			MinVersion:         tls.VersionTLS12,
		},
	}

	return st.transport
}

// DialContext resolves DNS at dial time, checks against restricted CIDRs, and connects directly to the pinned IP.
func (st *SafeTransport) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address format %q: %w", addr, err)
	}

	// 1. Hostname sanity check
	if !st.allowPrivate && IsRestrictedHostname(host) {
		return nil, fmt.Errorf("SSRF Protection: blocked connection to restricted host %q", host)
	}

	// 2. Dial-time DNS resolution
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed at dial time for %q: %w", host, err)
	}

	// 3. Dial-time IP validation (Anti-DNS Rebinding)
	var targetIP net.IP
	for _, ip := range ips {
		if !st.allowPrivate && IsRestrictedIP(ip) {
			continue // Skip restricted IPs
		}
		targetIP = ip
		break
	}

	if targetIP == nil {
		return nil, fmt.Errorf("SSRF / Rebinding Protection: no permitted public IP address resolved for %q", host)
	}

	// 4. Connect directly to the pinned validated IP address
	pinnedAddr := net.JoinHostPort(targetIP.String(), port)
	return st.dialer.DialContext(ctx, network, pinnedAddr)
}
