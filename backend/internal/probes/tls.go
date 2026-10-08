package probes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/expose/expose-backend/internal/models"
)

type TLSProbe struct{}

func NewTLSProbe() *TLSProbe {
	return &TLSProbe{}
}

func (p *TLSProbe) Name() string {
	return "tls_posture"
}

func (p *TLSProbe) Category() models.Category {
	return models.CategoryCryptography
}

func (p *TLSProbe) Execute(ctx context.Context, target *models.TargetScope) ([]models.Finding, error) {
	var findings []models.Finding
	host := target.Host
	port := target.Port
	if port == 80 {
		port = 443
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	dialer := &net.Dialer{Timeout: 6 * time.Second}
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // Allow retrieving certificate even if expired/self-signed to analyze it!
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		if target.Scheme == "https" {
			evidence := models.Evidence{
				Type:    models.EvidenceRawSocket,
				Summary: fmt.Sprintf("TLS connection failed to %s: %v", addr, err),
				RawData: map[string]interface{}{"address": addr, "error": err.Error()},
			}
			findings = append(findings, CreateFinding(
				p.Name(), target, models.CategoryTransportSecurity, models.SeverityHigh,
				models.ConfidenceConfirmed, models.StatusConfirmed,
				"TLS Handshake Failed or Port Unreachable",
				fmt.Sprintf("Failed to establish secure TLS handshake with '%s'.", addr),
				"Web service is not reachable over HTTPS or rejects TLS handshakes.",
				"Ensure port 443 is open and valid TLS listeners are running.",
				fmt.Sprintf("openssl s_client -connect %s -servername %s", addr, host),
				"CWE-295", "", evidence,
			))
		}
		return findings, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return findings, nil
	}

	cert := state.PeerCertificates[0]
	now := time.Now().UTC()

	certMetadata := map[string]interface{}{
		"subject":            cert.Subject.CommonName,
		"issuer":             cert.Issuer.CommonName,
		"not_before":         cert.NotBefore.Format(time.RFC3339),
		"not_after":          cert.NotAfter.Format(time.RFC3339),
		"dns_names":          cert.DNSNames,
		"negotiated_version": tlsVersionName(state.Version),
		"cipher_suite":       tls.CipherSuiteName(state.CipherSuite),
	}

	// 1. Expiration Check
	if now.After(cert.NotAfter) {
		daysExpired := int(now.Sub(cert.NotAfter).Hours() / 24)
		evidence := models.Evidence{
			Type:    models.EvidenceCertificateMetadata,
			Summary: fmt.Sprintf("Certificate expired on %s (%d days ago).", cert.NotAfter.Format("2006-01-02"), daysExpired),
			RawData: certMetadata,
		}
		findings = append(findings, CreateFinding(
			p.Name(), target, models.CategoryCryptography, models.SeverityCritical,
			models.ConfidenceConfirmed, models.StatusConfirmed,
			"Expired SSL/TLS Certificate",
			fmt.Sprintf("The certificate presented by '%s' expired on %s.", host, cert.NotAfter.Format("2006-01-02 15:04:05 UTC")),
			"Browsers block visitors with prominent security interstitials; API integrations fail immediately.",
			"Renew and deploy an active SSL/TLS certificate immediately.",
			fmt.Sprintf("openssl s_client -connect %s -servername %s 2>&1 | openssl x509 -noout -dates", addr, host),
			"CWE-295", "", evidence,
		))
	} else if daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24); daysLeft <= 14 {
		evidence := models.Evidence{
			Type:    models.EvidenceCertificateMetadata,
			Summary: fmt.Sprintf("Certificate expires in %d days (%s).", daysLeft, cert.NotAfter.Format("2006-01-02")),
			RawData: certMetadata,
		}
		findings = append(findings, CreateFinding(
			p.Name(), target, models.CategoryCryptography, models.SeverityMedium,
			models.ConfidenceConfirmed, models.StatusConfirmed,
			"SSL/TLS Certificate Expiring Soon",
			fmt.Sprintf("The certificate presented by '%s' will expire in %d days.", host, daysLeft),
			"Certificate expiry will cause unexpected downtime and security errors for all users.",
			"Ensure automated certificate renewal (ACME / Certbot) is operating properly.",
			fmt.Sprintf("openssl s_client -connect %s -servername %s 2>&1 | openssl x509 -noout -enddate", addr, host),
			"CWE-295", "", evidence,
		))
	} else {
		daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
		evidence := models.Evidence{
			Type:    models.EvidenceCertificateMetadata,
			Summary: fmt.Sprintf("Valid TLS certificate from '%s' (%d days remaining).", cert.Issuer.CommonName, daysLeft),
			RawData: certMetadata,
		}
		findings = append(findings, CreateFinding(
			p.Name(), target, models.CategoryCryptography, models.SeverityInfo,
			models.ConfidenceConfirmed, models.StatusObserved,
			"Valid SSL/TLS Certificate",
			fmt.Sprintf("Certificate presented by '%s' is valid until %s (%d days left).", host, cert.NotAfter.Format("2006-01-02"), daysLeft),
			"Enforces encryption and standard trust establishment across browsers and HTTP clients.",
			"Maintain certificate renewal schedules.",
			fmt.Sprintf("openssl s_client -connect %s -servername %s 2>&1 | openssl x509 -noout -dates", addr, host),
			"", "", evidence,
		))
	}

	// 2. SAN Match
	hostMatched := false
	for _, san := range cert.DNSNames {
		if strings.EqualFold(san, host) || matchWildcard(san, host) {
			hostMatched = true
			break
		}
	}

	if !hostMatched && len(cert.DNSNames) > 0 {
		evidence := models.Evidence{
			Type:    models.EvidenceCertificateMetadata,
			Summary: fmt.Sprintf("Host '%s' does not match any SAN in certificate: %v", host, cert.DNSNames),
			RawData: certMetadata,
		}
		findings = append(findings, CreateFinding(
			p.Name(), target, models.CategoryCryptography, models.SeverityHigh,
			models.ConfidenceConfirmed, models.StatusConfirmed,
			"SSL/TLS Certificate Name Mismatch",
			fmt.Sprintf("The certificate does not list hostname '%s' in its Subject Alternative Names.", host),
			"Clients will fail hostname verification, rejecting secure connections.",
			"Reissue the certificate ensuring all domain aliases and subdomains are included.",
			fmt.Sprintf("openssl s_client -connect %s -servername %s 2>&1 | openssl x509 -noout -text | grep -A1 'Subject Alternative Name'", addr, host),
			"CWE-297", "", evidence,
		))
	}

	// 3. Self-Signed Check
	if cert.Issuer.CommonName == cert.Subject.CommonName && cert.CheckSignatureFrom(cert) == nil {
		evidence := models.Evidence{
			Type:    models.EvidenceCertificateMetadata,
			Summary: fmt.Sprintf("Certificate is self-signed (Issuer: %s).", cert.Issuer.CommonName),
			RawData: certMetadata,
		}
		findings = append(findings, CreateFinding(
			p.Name(), target, models.CategoryCryptography, models.SeverityHigh,
			models.ConfidenceConfirmed, models.StatusConfirmed,
			"Self-Signed SSL/TLS Certificate in Use",
			fmt.Sprintf("Certificate presented by '%s' is self-signed and lacks a trusted root CA chain.", host),
			"Untrusted by public browsers and standard HTTPS clients.",
			"Replace with a publicly trusted certificate issued by Let's Encrypt or another CA.",
			fmt.Sprintf("openssl s_client -connect %s -servername %s 2>&1 | openssl x509 -noout -issuer -subject", addr, host),
			"CWE-295", "", evidence,
		))
	}

	// 4. Negotiated Protocol
	protoName := tlsVersionName(state.Version)
	evidence := models.Evidence{
		Type:    models.EvidenceTLSHandshake,
		Summary: fmt.Sprintf("Negotiated protocol: %s with cipher: %s", protoName, tls.CipherSuiteName(state.CipherSuite)),
		RawData: certMetadata,
	}
	findings = append(findings, CreateFinding(
		p.Name(), target, models.CategoryTransportSecurity, models.SeverityInfo,
		models.ConfidenceConfirmed, models.StatusObserved,
		fmt.Sprintf("Modern TLS Protocol Active (%s)", protoName),
		fmt.Sprintf("Server negotiated secure connection using %s.", protoName),
		"Provides modern forward secrecy and robust encryption.",
		"Continue maintaining modern TLS baseline.",
		fmt.Sprintf("openssl s_client -connect %s -servername %s", addr, host),
		"", "", evidence,
	))

	return findings, nil
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS10:
		return "TLSv1.0"
	default:
		return "Unknown"
	}
}

func matchWildcard(pattern, host string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := pattern[1:] // e.g. .example.com
	if strings.HasSuffix(strings.ToLower(host), strings.ToLower(suffix)) {
		prefix := host[:len(host)-len(suffix)]
		return !strings.Contains(prefix, ".")
	}
	return false
}
