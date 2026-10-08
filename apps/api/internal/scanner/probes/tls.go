package probes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/expose/expose/apps/api/internal/domain"
	"github.com/expose/expose/apps/api/internal/scope"
)

type TLSProbe struct{}

func NewTLSProbe() *TLSProbe {
	return &TLSProbe{}
}

func (p *TLSProbe) Name() string {
	return "tls_security"
}

func (p *TLSProbe) Run(ctx context.Context, target *scope.TargetScope) (*ProbeResult, error) {
	start := time.Now()
	res := &ProbeResult{
		ProbeName: p.Name(),
		Findings:  make([]domain.Finding, 0),
		Assets:    make([]domain.Asset, 0),
	}

	addr := fmt.Sprintf("%s:%d", target.Host, target.Port)
	dialer := &net.Dialer{Timeout: 6 * time.Second}

	// 1. Standard TLS handshake with full verification
	tlsConfig := &tls.Config{
		ServerName:         target.Host,
		InsecureSkipVerify: false,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	var untrustedCert bool
	var certErr error

	if err != nil {
		certErr = err
		// Check if error is due to certificate authority / self-signed
		if _, ok := err.(x509.UnknownAuthorityError); ok || strings.Contains(err.Error(), "certificate signed by unknown authority") {
			untrustedCert = true
		} else if _, ok := err.(x509.CertificateInvalidError); ok {
			untrustedCert = true
		}

		// Re-dial with InsecureSkipVerify so we can inspect the peer certificates even if untrusted
		insecureConfig := &tls.Config{
			ServerName:         target.Host,
			InsecureSkipVerify: true,
		}
		insecureConn, iErr := tls.DialWithDialer(dialer, "tcp", addr, insecureConfig)
		if iErr != nil {
			// TLS is completely unavailable on this port
			res.Findings = append(res.Findings, domain.Finding{
				ID:          GenerateFindingID("fnd_tls_unavailable"),
				Title:       "TLS Handshake Failed (HTTPS Unavailable)",
				Description: fmt.Sprintf("Unable to establish TLS connection on %s: %v", addr, iErr),
				Severity:    domain.SeverityCritical,
				Confidence:  domain.ConfidenceConfirmed,
				Status:      domain.StatusConfirmed,
				Category:    domain.CategoryTransportSecurity,
				RuleID:      "TLS_HANDSHAKE_FAILED",
				OWASPMapping: "A02:2021-Cryptographic Failures",
				ASVSMapping:  "V14.4.1",
				CWE:         "CWE-319",
				Evidence: domain.Evidence{
					Type:      domain.EvidenceTLSHandshake,
					Summary:   fmt.Sprintf("Handshake failure: %v", iErr),
					Timestamp: time.Now().UTC(),
				},
				Impact: "Clients cannot communicate over an encrypted HTTPS connection, leaving all traffic exposed.",
				Recommendation: domain.Recommendation{
					Summary:     "Deploy and configure a valid TLS certificate on port 443.",
					Remediation: "Provision an automated Let's Encrypt or commercial certificate and bind it to the listener.",
				},
				Verification: domain.Verification{
					Command:     fmt.Sprintf("openssl s_client -connect %s -servername %s", addr, target.Host),
					Tool:        "openssl",
					Description: "Test raw TLS handshake",
				},
				CreatedAt: time.Now().UTC(),
			})
			res.Duration = time.Since(start)
			return res, nil
		}
		conn = insecureConn
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates

	if len(certs) > 0 {
		leaf := certs[0]

		// Record certificate asset
		res.Assets = append(res.Assets, domain.Asset{
			ID:       GenerateFindingID("ast_cert"),
			TargetID: target.Host,
			Type:     domain.AssetCertificate,
			Value:    leaf.Subject.CommonName,
			Attributes: map[string]interface{}{
				"issuer":     leaf.Issuer.CommonName,
				"not_before": leaf.NotBefore.Format(time.RFC3339),
				"not_after":  leaf.NotAfter.Format(time.RFC3339),
				"sans":       leaf.DNSNames,
				"serial":     leaf.SerialNumber.String(),
			},
		})

		// 2. Untrusted / Self-signed certificate check
		if untrustedCert {
			res.Findings = append(res.Findings, domain.Finding{
				ID:          GenerateFindingID("fnd_tls_untrusted"),
				Title:       "Untrusted or Self-Signed TLS Certificate",
				Description: fmt.Sprintf("Certificate is not signed by a recognized Certificate Authority: %v", certErr),
				Severity:    domain.SeverityHigh,
				Confidence:  domain.ConfidenceConfirmed,
				Status:      domain.StatusConfirmed,
				Category:    domain.CategoryCryptography,
				RuleID:      "TLS_CERTIFICATE_UNTRUSTED",
				OWASPMapping: "A02:2021-Cryptographic Failures",
				ASVSMapping:  "V14.4.1",
				CWE:         "CWE-295",
				Evidence: domain.Evidence{
					Type: domain.EvidenceCertificateMetadata,
					Summary: fmt.Sprintf("Subject: %s | Issuer: %s", leaf.Subject.CommonName, leaf.Issuer.CommonName),
					RawData: map[string]interface{}{
						"subject": leaf.Subject.CommonName,
						"issuer":  leaf.Issuer.CommonName,
						"error":   certErr.Error(),
					},
					Timestamp: time.Now().UTC(),
				},
				Impact: "Web browsers will display severe security warnings, blocking normal users and exposing visitors to interception.",
				Recommendation: domain.Recommendation{
					Summary:     "Install a certificate signed by a trusted Public CA.",
					Remediation: "Obtain a free automated certificate from Let's Encrypt or your cloud provider.",
				},
				Verification: domain.Verification{
					Command:     fmt.Sprintf("openssl s_client -connect %s -servername %s 2>&1 | grep -i 'verify error'", addr, target.Host),
					Tool:        "openssl",
					Description: "Check TLS certificate trust chain",
				},
				CreatedAt: time.Now().UTC(),
			})
		}

		// 3. Expiration Check
		now := time.Now()
		if now.After(leaf.NotAfter) {
			res.Findings = append(res.Findings, domain.Finding{
				ID:          GenerateFindingID("fnd_cert_expired"),
				Title:       "TLS Certificate Is Expired",
				Description: fmt.Sprintf("Certificate expired on %s (%d days ago).", leaf.NotAfter.Format("2006-01-02"), int(now.Sub(leaf.NotAfter).Hours()/24)),
				Severity:    domain.SeverityCritical,
				Confidence:  domain.ConfidenceConfirmed,
				Status:      domain.StatusConfirmed,
				Category:    domain.CategoryCryptography,
				RuleID:      "TLS_CERTIFICATE_EXPIRED",
				OWASPMapping: "A02:2021-Cryptographic Failures",
				ASVSMapping:  "V14.4.1",
				CWE:         "CWE-295",
				Evidence: domain.Evidence{
					Type:      domain.EvidenceCertificateMetadata,
					Summary:   fmt.Sprintf("Expired at %s", leaf.NotAfter.Format(time.RFC3339)),
					RawData:   map[string]interface{}{"not_after": leaf.NotAfter.Format(time.RFC3339)},
					Timestamp: time.Now().UTC(),
				},
				Impact: "Browser connections will be blocked by major browsers with fatal cryptographic warnings.",
				Recommendation: domain.Recommendation{
					Summary:     "Renew the expired TLS certificate immediately.",
					Remediation: "Issue a new certificate and verify automated renewal daemons (e.g. certbot).",
				},
				Verification: domain.Verification{
					Command:     fmt.Sprintf("openssl s_client -connect %s -servername %s -showcerts 2>/dev/null | openssl x509 -noout -enddate", addr, target.Host),
					Tool:        "openssl",
					Description: "Inspect certificate expiration date",
				},
				CreatedAt: time.Now().UTC(),
			})
		} else if leaf.NotAfter.Sub(now) < 30*24*time.Hour {
			daysLeft := int(leaf.NotAfter.Sub(now).Hours() / 24)
			res.Findings = append(res.Findings, domain.Finding{
				ID:          GenerateFindingID("fnd_cert_expiring_soon"),
				Title:       "TLS Certificate Expiring Soon",
				Description: fmt.Sprintf("Certificate will expire in %d days (%s).", daysLeft, leaf.NotAfter.Format("2006-01-02")),
				Severity:    domain.SeverityHigh,
				Confidence:  domain.ConfidenceConfirmed,
				Status:      domain.StatusConfirmed,
				Category:    domain.CategoryCryptography,
				RuleID:      "TLS_CERTIFICATE_EXPIRING_SOON",
				OWASPMapping: "A02:2021-Cryptographic Failures",
				ASVSMapping:  "V14.4.1",
				CWE:         "CWE-295",
				Evidence: domain.Evidence{
					Type:      domain.EvidenceCertificateMetadata,
					Summary:   fmt.Sprintf("Expires in %d days at %s", daysLeft, leaf.NotAfter.Format(time.RFC3339)),
					RawData:   map[string]interface{}{"days_left": daysLeft, "not_after": leaf.NotAfter.Format(time.RFC3339)},
					Timestamp: time.Now().UTC(),
				},
				Impact: "If not renewed before expiration, users will experience complete service outage.",
				Recommendation: domain.Recommendation{
					Summary:     "Trigger certificate renewal before expiration date.",
					Remediation: "Check automated ACME renewal cron jobs or manually renew certificate.",
				},
				Verification: domain.Verification{
					Command:     fmt.Sprintf("openssl s_client -connect %s -servername %s -showcerts 2>/dev/null | openssl x509 -noout -dates", addr, target.Host),
					Tool:        "openssl",
					Description: "Check days remaining until certificate expiration",
				},
				CreatedAt: time.Now().UTC(),
			})
		} else {
			// Certificate is active and valid
			daysLeft := int(leaf.NotAfter.Sub(now).Hours() / 24)
			res.Findings = append(res.Findings, domain.Finding{
				ID:          GenerateFindingID("fnd_cert_valid"),
				Title:       "TLS Certificate Is Valid",
				Description: fmt.Sprintf("Valid certificate issued by %q (expires in %d days).", leaf.Issuer.CommonName, daysLeft),
				Severity:    domain.SeverityInfo,
				Confidence:  domain.ConfidenceConfirmed,
				Status:      domain.StatusObserved,
				Category:    domain.CategoryCryptography,
				RuleID:      "TLS_CERTIFICATE_VALID",
				OWASPMapping: "A02:2021-Cryptographic Failures",
				ASVSMapping:  "V14.4.1",
				CWE:         "CWE-295",
				Evidence: domain.Evidence{
					Type:      domain.EvidenceCertificateMetadata,
					Summary:   fmt.Sprintf("Issuer: %s | Valid until %s (%d days left)", leaf.Issuer.CommonName, leaf.NotAfter.Format("2006-01-02"), daysLeft),
					RawData:   map[string]interface{}{"issuer": leaf.Issuer.CommonName, "days_left": daysLeft},
					Timestamp: time.Now().UTC(),
				},
				Impact: "Ensures encrypted transit and verified identity for connecting clients.",
				Recommendation: domain.Recommendation{
					Summary:     "Keep automated renewal active.",
					Remediation: "Maintain existing ACME renewal configuration.",
				},
				Verification: domain.Verification{
					Command:     fmt.Sprintf("openssl s_client -connect %s -servername %s -showcerts 2>/dev/null | openssl x509 -noout -issuer -dates", addr, target.Host),
					Tool:        "openssl",
					Description: "View certificate details",
				},
				CreatedAt: time.Now().UTC(),
			})
		}

		// 4. Hostname Mismatch Check (SANs)
		hostMatches := false
		lowerTarget := strings.ToLower(target.Host)
		if strings.EqualFold(leaf.Subject.CommonName, lowerTarget) {
			hostMatches = true
		}
		for _, san := range leaf.DNSNames {
			lowerSAN := strings.ToLower(san)
			if lowerSAN == lowerTarget {
				hostMatches = true
				break
			}
			if strings.HasPrefix(lowerSAN, "*.") {
				suffix := lowerSAN[2:]
				if strings.HasSuffix(lowerTarget, suffix) && !strings.Contains(lowerTarget[:len(lowerTarget)-len(suffix)], ".") {
					hostMatches = true
					break
				}
			}
		}

		if !hostMatches {
			res.Findings = append(res.Findings, domain.Finding{
				ID:          GenerateFindingID("fnd_cert_mismatch"),
				Title:       "TLS Certificate Hostname Mismatch",
				Description: fmt.Sprintf("Certificate does not cover requested hostname %q. Covered SANs: %s", target.Host, strings.Join(leaf.DNSNames, ", ")),
				Severity:    domain.SeverityHigh,
				Confidence:  domain.ConfidenceConfirmed,
				Status:      domain.StatusConfirmed,
				Category:    domain.CategoryCryptography,
				RuleID:      "TLS_HOSTNAME_MISMATCH",
				OWASPMapping: "A02:2021-Cryptographic Failures",
				ASVSMapping:  "V14.4.1",
				CWE:         "CWE-295",
				Evidence: domain.Evidence{
					Type: domain.EvidenceCertificateMetadata,
					Summary: fmt.Sprintf("Target host %s not in SAN list [%s]", target.Host, strings.Join(leaf.DNSNames, ", ")),
					RawData: map[string]interface{}{"target_host": target.Host, "sans": leaf.DNSNames},
					Timestamp: time.Now().UTC(),
				},
				Impact: "Browsers reject the connection with ERR_CERT_COMMON_NAME_INVALID warning.",
				Recommendation: domain.Recommendation{
					Summary:     "Issue a certificate matching this exact domain name or wildcard.",
					Remediation: "Add the domain name to the certificate's Subject Alternative Names (SAN) list.",
				},
				Verification: domain.Verification{
					Command:     fmt.Sprintf("openssl s_client -connect %s -servername %s 2>/dev/null | openssl x509 -noout -ext subjectAltName", addr, target.Host),
					Tool:        "openssl",
					Description: "Inspect Subject Alternative Names",
				},
				CreatedAt: time.Now().UTC(),
			})
		}

		// 5. Negotiated Protocol Observation
		protoVersion := tlsVersionString(state.Version)
		if state.Version == tls.VersionTLS13 {
			res.Findings = append(res.Findings, domain.Finding{
				ID:          GenerateFindingID("fnd_tls_13"),
				Title:       "Modern TLS 1.3 Protocol Negotiated",
				Description: "The server successfully negotiated TLS 1.3, providing optimal cryptographic security and 1-RTT handshake speed.",
				Severity:    domain.SeverityInfo,
				Confidence:  domain.ConfidenceConfirmed,
				Status:      domain.StatusObserved,
				Category:    domain.CategoryCryptography,
				RuleID:      "TLS_13_SUPPORTED",
				OWASPMapping: "A02:2021-Cryptographic Failures",
				ASVSMapping:  "V14.4.2",
				CWE:         "CWE-326",
				Evidence: domain.Evidence{
					Type:      domain.EvidenceTLSHandshake,
					Summary:   fmt.Sprintf("Negotiated Version: %s | CipherSuite: %s", protoVersion, tls.CipherSuiteName(state.CipherSuite)),
					Timestamp: time.Now().UTC(),
				},
				Impact: "Delivers maximum forward secrecy, modern authenticated ciphers (AEAD), and fast handshakes.",
				Recommendation: domain.Recommendation{
					Summary:     "Maintain TLS 1.3 as standard protocol.",
					Remediation: "Keep modern cipher suites enabled.",
				},
				Verification: domain.Verification{
					Command:     fmt.Sprintf("openssl s_client -connect %s -servername %s -tls1_3", addr, target.Host),
					Tool:        "openssl",
					Description: "Verify TLS 1.3 handshake",
				},
				CreatedAt: time.Now().UTC(),
			})
		}
	}

	// 6. Test Obsolete TLS 1.0 Support
	legacyConfig := &tls.Config{
		ServerName:         target.Host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS10,
	}
	legacyConn, lErr := tls.DialWithDialer(dialer, "tcp", addr, legacyConfig)
	if lErr == nil {
		defer legacyConn.Close()
		res.Findings = append(res.Findings, domain.Finding{
			ID:          GenerateFindingID("fnd_obsolete_tls10"),
			Title:       "Obsolete TLS 1.0 Protocol Supported",
			Description: "The server accepted a connection using deprecated and vulnerable TLS 1.0 protocol.",
			Severity:    domain.SeverityHigh,
			Confidence:  domain.ConfidenceConfirmed,
			Status:      domain.StatusConfirmed,
			Category:    domain.CategoryCryptography,
			RuleID:      "OBSOLETE_TLS_10",
			OWASPMapping: "A02:2021-Cryptographic Failures",
			ASVSMapping:  "V14.4.2",
			CWE:         "CWE-326",
			Evidence: domain.Evidence{
				Type:      domain.EvidenceTLSHandshake,
				Summary:   "Successfully completed handshake with TLS 1.0",
				Timestamp: time.Now().UTC(),
			},
			Impact: "TLS 1.0 is vulnerable to known cryptographic weaknesses (e.g. BEAST) and violates PCI-DSS compliance.",
			Recommendation: domain.Recommendation{
				Summary:     "Disable TLS 1.0 and TLS 1.1 across all web server listeners.",
				Remediation: "Configure 'ssl_protocols TLSv1.2 TLSv1.3;' in Nginx or 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1' in Apache.",
			},
			Verification: domain.Verification{
				Command:     fmt.Sprintf("openssl s_client -connect %s -servername %s -tls1", addr, target.Host),
				Tool:        "openssl",
				Description: "Test if TLS 1.0 handshake succeeds",
			},
			CreatedAt: time.Now().UTC(),
		})
	}

	res.Duration = time.Since(start)
	return res, nil
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%x)", v)
	}
}
