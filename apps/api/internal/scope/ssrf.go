package scope

import (
	"fmt"
	"net"
	"strings"
)

// Restricted IPv4 and IPv6 subnets (SSRF blocklist)
var restrictedCIDRs = []string{
	// IPv4 Special/Private Ranges
	"0.0.0.0/8",          // Current network (RFC 1122)
	"10.0.0.0/8",         // Private-Use Class A (RFC 1918)
	"100.64.0.0/10",      // Shared Address Space / Carrier-grade NAT (RFC 6598)
	"127.0.0.0/8",        // Loopback (RFC 1122)
	"169.254.0.0/16",     // Link-Local / Cloud Metadata (AWS, Azure, GCP, DigitalOcean)
	"172.16.0.0/12",      // Private-Use Class B (RFC 1918)
	"192.0.0.0/24",       // IETF Protocol Assignments (RFC 6890)
	"192.0.2.0/24",       // TEST-NET-1 Documentation (RFC 5737)
	"192.88.99.0/24",     // 6to4 Relay Anycast (RFC 7526)
	"192.168.0.0/16",     // Private-Use Class C (RFC 1918)
	"198.18.0.0/15",      // Network Interconnect Benchmark (RFC 2544)
	"198.51.100.0/24",    // TEST-NET-2 Documentation (RFC 5737)
	"203.0.113.0/24",     // TEST-NET-3 Documentation (RFC 5737)
	"224.0.0.0/4",        // Multicast (RFC 5771)
	"240.0.0.0/4",        // Reserved for Future Use (RFC 1112)
	"255.255.255.255/32", // Limited Broadcast (RFC 919)

	// IPv6 Special/Private Ranges
	"::/128",          // Unspecified
	"::1/128",         // Loopback
	"::ffff:0:0/96",   // IPv4-mapped IPv6 (RFC 4291)
	"64:ff9b::/96",    // IPv4-IPv6 Translation (RFC 6052)
	"100::/64",        // Discard-Only (RFC 6666)
	"2001:db8::/32",   // Documentation (RFC 3849)
	"fc00::/7",        // Unique Local Address (RFC 4193)
	"fe80::/10",       // Link-Local Unicast (RFC 4291)
	"ff00::/8",        // Multicast
}

// Explicit cloud metadata and internal hostnames
var blockedHostnames = []string{
	"localhost",
	"metadata.google.internal",
	"metadata.google",
	"instance-data",
	"169.254.169.254",
	"100.100.100.200", // Alibaba Cloud metadata
}

var parsedRestrictedNets []*net.IPNet

func init() {
	for _, cidr := range restrictedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			parsedRestrictedNets = append(parsedRestrictedNets, ipNet)
		}
	}
}

// IsRestrictedIP checks if an IP belongs to private, loopback, link-local, or cloud metadata subnets.
// Handles IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) by unwrapping to IPv4.
func IsRestrictedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	// Unmask IPv4-mapped IPv6 addresses
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}

	for _, ipNet := range parsedRestrictedNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// IsRestrictedHostname checks if a hostname matches known loopbacks or internal cloud endpoints.
func IsRestrictedHostname(host string) bool {
	clean := strings.ToLower(strings.TrimSpace(host))

	for _, blocked := range blockedHostnames {
		if clean == blocked || strings.HasSuffix(clean, "."+blocked) {
			return true
		}
	}

	// Reject internal TLDs
	if strings.HasSuffix(clean, ".local") ||
		strings.HasSuffix(clean, ".internal") ||
		strings.HasSuffix(clean, ".lan") ||
		strings.HasSuffix(clean, ".corp") ||
		strings.HasSuffix(clean, ".home") {
		return true
	}

	return false
}

// ValidateIPs inspects a list of resolved IPs and returns an error if any IP is restricted.
func ValidateIPs(ips []net.IP) error {
	if len(ips) == 0 {
		return fmt.Errorf("no IP addresses could be resolved for target")
	}

	for _, ip := range ips {
		if IsRestrictedIP(ip) {
			return fmt.Errorf("SSRF Protection: destination IP %s resolves to restricted/private network", ip.String())
		}
	}
	return nil
}
