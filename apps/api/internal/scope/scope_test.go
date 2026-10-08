package scope

import (
	"net"
	"net/http"
	"net/url"
	"testing"
)

func TestIsRestrictedIP(t *testing.T) {
	testCases := []struct {
		ip       string
		expected bool
		desc     string
	}{
		{"127.0.0.1", true, "IPv4 loopback"},
		{"127.10.20.30", true, "IPv4 loopback range"},
		{"10.0.0.1", true, "RFC 1918 Class A"},
		{"172.16.0.1", true, "RFC 1918 Class B"},
		{"172.31.255.255", true, "RFC 1918 Class B upper boundary"},
		{"192.168.1.1", true, "RFC 1918 Class C"},
		{"169.254.169.254", true, "Cloud metadata IP"},
		{"169.254.1.1", true, "Link local IPv4"},
		{"100.64.0.1", true, "Carrier-grade NAT"},
		{"0.0.0.0", true, "Current network"},
		{"::1", true, "IPv6 loopback"},
		{"fe80::1", true, "IPv6 link local"},
		{"fc00::1", true, "IPv6 unique local"},
		{"::ffff:127.0.0.1", true, "IPv4-mapped IPv6 loopback"},
		{"::ffff:169.254.169.254", true, "IPv4-mapped IPv6 cloud metadata"},
		{"::ffff:10.0.0.1", true, "IPv4-mapped IPv6 RFC 1918"},
		{"8.8.8.8", false, "Google public DNS"},
		{"1.1.1.1", false, "Cloudflare public DNS"},
		{"93.184.216.34", false, "example.com public IP"},
		{"2606:4700:4700::1111", false, "Cloudflare public IPv6"},
	}

	for _, tc := range testCases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("failed to parse IP string: %s", tc.ip)
		}
		actual := IsRestrictedIP(ip)
		if actual != tc.expected {
			t.Errorf("[%s] IP %s: expected restricted=%v, got %v", tc.desc, tc.ip, tc.expected, actual)
		}
	}
}

func TestIsRestrictedHostname(t *testing.T) {
	blocked := []string{
		"localhost",
		"LOCALHOST",
		"metadata.google.internal",
		"instance-data",
		"169.254.169.254",
		"server.local",
		"api.internal",
		"database.lan",
		"dc.corp",
	}

	for _, host := range blocked {
		if !IsRestrictedHostname(host) {
			t.Errorf("expected hostname %q to be restricted", host)
		}
	}

	allowed := []string{
		"example.com",
		"api.github.com",
		"google.com",
		"securityheaders.com",
	}

	for _, host := range allowed {
		if IsRestrictedHostname(host) {
			t.Errorf("expected hostname %q to be permitted", host)
		}
	}
}

func TestValidateTarget_DisallowedSchemes(t *testing.T) {
	disallowed := []string{
		"ftp://example.com",
		"file:///etc/passwd",
		"gopher://example.com",
		"javascript:alert(1)",
		"ws://example.com",
	}

	for _, target := range disallowed {
		_, err := ValidateTarget(target, false)
		if err == nil {
			t.Errorf("expected target %q to be rejected for invalid scheme", target)
		}
	}
}

func TestValidateTarget_Normalization(t *testing.T) {
	scope, err := ValidateTarget("example.com", false)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if scope.Scheme != "https" {
		t.Errorf("expected scheme https, got %s", scope.Scheme)
	}
	if scope.Host != "example.com" {
		t.Errorf("expected host example.com, got %s", scope.Host)
	}
	if scope.Port != 443 {
		t.Errorf("expected port 443, got %d", scope.Port)
	}
	if len(scope.ResolvedIPs) == 0 {
		t.Errorf("expected resolved IPs, got none")
	}
}

func TestSafeRedirectChecker(t *testing.T) {
	checker := SafeRedirectChecker(false)

	// Test max hops
	via := make([]*http.Request, 5)
	dummyReq, _ := http.NewRequest(http.MethodGet, "https://example.com/hop5", nil)
	err := checker(dummyReq, via)
	if err == nil {
		t.Error("expected error when redirect hops exceed 5")
	}

	// Test redirect to restricted IP/host
	badReq, _ := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	err = checker(badReq, []*http.Request{})
	if err == nil {
		t.Error("expected error for redirect to cloud metadata")
	}

	// Test redirect to invalid scheme
	fileReq, _ := http.NewRequest(http.MethodGet, "file:///etc/passwd", nil)
	err = checker(fileReq, []*http.Request{})
	if err == nil {
		t.Error("expected error for redirect to file:// scheme")
	}
}
