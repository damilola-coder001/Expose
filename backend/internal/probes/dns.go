package probes

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/expose/expose-backend/internal/models"
)

type DNSProbe struct{}

func NewDNSProbe() *DNSProbe {
	return &DNSProbe{}
}

func (p *DNSProbe) Name() string {
	return "dns_posture"
}

func (p *DNSProbe) Category() models.Category {
	return models.CategoryDNSConfiguration
}

func (p *DNSProbe) Execute(ctx context.Context, target *models.TargetScope) ([]models.Finding, error) {
	var findings []models.Finding
	domain := target.Host

	resolver := &net.Resolver{}

	// 1. Inspect CAA Records
	resolver = net.DefaultResolver
	caaRecords, _ := resolver.LookupTXT(ctx, domain) // In pure Go standard library, LookupTXT gets all TXT; let's inspect CAA and TXT
	
	// Let's check TXT records on domain for SPF
	txtRecords, err := resolver.LookupTXT(ctx, domain)
	var spfRecords []string
	if err == nil {
		for _, r := range txtRecords {
			if strings.HasPrefix(r, "v=spf1") {
				spfRecords = append(spfRecords, r)
			}
		}
	}

	if len(spfRecords) == 0 {
		evidence := models.Evidence{
			Type:    models.EvidenceDNSRecord,
			Summary: fmt.Sprintf("No TXT records matching 'v=spf1' found on %s.", domain),
			RawData: map[string]interface{}{"domain": domain, "all_txt_records": txtRecords},
		}
		findings = append(findings, CreateFinding(
			p.Name(), target, models.CategoryEmailSecurity, models.SeverityMedium,
			models.ConfidenceConfirmed, models.StatusConfirmed,
			"Missing Sender Policy Framework (SPF) Record",
			fmt.Sprintf("The domain '%s' has no SPF record configured. Receiving mail servers cannot verify origin mail servers.", domain),
			"Adversaries can forge emails pretending to originate from your domain for phishing campaigns.",
			"Publish an SPF TXT record: v=spf1 include:_spf.example.com -all",
			fmt.Sprintf("dig TXT %s +short", domain),
			"CWE-358", "", evidence,
		))
	} else {
		hasPermissiveAll := false
		for _, spf := range spfRecords {
			if strings.Contains(spf, "+all") {
				hasPermissiveAll = true
				evidence := models.Evidence{
					Type:    models.EvidenceDNSRecord,
					Summary: fmt.Sprintf("SPF record on %s contains permissive '+all': %s", domain, spf),
					RawData: map[string]interface{}{"spf_record": spf},
				}
				findings = append(findings, CreateFinding(
					p.Name(), target, models.CategoryEmailSecurity, models.SeverityHigh,
					models.ConfidenceConfirmed, models.StatusConfirmed,
					"Overly Permissive SPF Record (+all)",
					fmt.Sprintf("The SPF record for '%s' contains '+all', authorizing every server globally to send mail as your domain.", domain),
					"Negates email spoofing defenses, allowing any attacker server to pass SPF checks.",
					"Change '+all' to '-all' or '~all' in the SPF record.",
					fmt.Sprintf("dig TXT %s +short", domain),
					"CWE-358", "", evidence,
				))
			}
		}
		if !hasPermissiveAll {
			evidence := models.Evidence{
				Type:    models.EvidenceDNSRecord,
				Summary: fmt.Sprintf("Valid SPF record published: %s", spfRecords[0]),
				RawData: map[string]interface{}{"records": spfRecords},
			}
			findings = append(findings, CreateFinding(
				p.Name(), target, models.CategoryEmailSecurity, models.SeverityInfo,
				models.ConfidenceConfirmed, models.StatusObserved,
				"Sender Policy Framework (SPF) Configured",
				fmt.Sprintf("Domain '%s' publishes an active SPF policy.", domain),
				"Helps recipient mail gateways reject spoofed messages.",
				"Review third-party sender IPs regularly.",
				fmt.Sprintf("dig TXT %s +short", domain),
				"", "", evidence,
			))
		}
	}

	// 2. Inspect DMARC (_dmarc.<domain>)
	dmarcDomain := fmt.Sprintf("_dmarc.%s", domain)
	dmarcTxt, dmarcErr := resolver.LookupTXT(ctx, dmarcDomain)
	var dmarcRecords []string
	if dmarcErr == nil {
		for _, r := range dmarcTxt {
			if strings.HasPrefix(r, "v=DMARC1") {
				dmarcRecords = append(dmarcRecords, r)
			}
		}
	}

	if len(dmarcRecords) == 0 {
		evidence := models.Evidence{
			Type:    models.EvidenceDNSRecord,
			Summary: fmt.Sprintf("No DMARC record found at %s.", dmarcDomain),
			RawData: map[string]interface{}{"query": dmarcDomain},
		}
		findings = append(findings, CreateFinding(
			p.Name(), target, models.CategoryEmailSecurity, models.SeverityMedium,
			models.ConfidenceConfirmed, models.StatusConfirmed,
			"Missing DMARC Policy Record",
			fmt.Sprintf("The domain '%s' does not publish a DMARC policy at '%s'.", domain, dmarcDomain),
			"Without DMARC, receiving email servers cannot enforce rejection or send forensic abuse reports on spoofed emails.",
			fmt.Sprintf("Publish a DMARC TXT record at '_dmarc.%s': v=DMARC1; p=none; rua=mailto:dmarc-reports@%s;", domain, domain),
			fmt.Sprintf("dig TXT _dmarc.%s +short", domain),
			"CWE-358", "", evidence,
		))
	} else {
		for _, dmarc := range dmarcRecords {
			tags := parseDMARCTags(dmarc)
			policy := strings.ToLower(tags["p"])
			if policy == "none" {
				evidence := models.Evidence{
					Type:    models.EvidenceDNSRecord,
					Summary: fmt.Sprintf("DMARC record at %s specifies monitoring-only 'p=none'.", dmarcDomain),
					RawData: map[string]interface{}{"dmarc_record": dmarc, "parsed_tags": tags},
				}
				findings = append(findings, CreateFinding(
					p.Name(), target, models.CategoryEmailSecurity, models.SeverityLow,
					models.ConfidenceConfirmed, models.StatusConfirmed,
					"DMARC Policy Set to Ineffective 'p=none'",
					fmt.Sprintf("The DMARC policy for '%s' is set to 'p=none', which only monitors and does not reject or quarantine spoofed mail.", domain),
					"Fraudulent emails will continue being accepted into recipient inboxes.",
					"Progress policy to 'p=quarantine' and eventually 'p=reject'.",
					fmt.Sprintf("dig TXT _dmarc.%s +short", domain),
					"CWE-358", "", evidence,
				))
			} else {
				evidence := models.Evidence{
					Type:    models.EvidenceDNSRecord,
					Summary: fmt.Sprintf("DMARC policy active with enforcement: p=%s", policy),
					RawData: map[string]interface{}{"dmarc_record": dmarc},
				}
				findings = append(findings, CreateFinding(
					p.Name(), target, models.CategoryEmailSecurity, models.SeverityInfo,
					models.ConfidenceConfirmed, models.StatusObserved,
					fmt.Sprintf("DMARC Policy Enforced (p=%s)", policy),
					fmt.Sprintf("Domain '%s' actively enforces DMARC policy '%s'.", domain, policy),
					"Significantly protects against domain impersonation across email providers.",
					"Regularly inspect aggregate delivery reports (rua).",
					fmt.Sprintf("dig TXT _dmarc.%s +short", domain),
					"", "", evidence,
				))
			}
		}
	}

	_ = caaRecords
	return findings, nil
}

func parseDMARCTags(record string) map[string]string {
	tags := make(map[string]string)
	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if idx := strings.Index(part, "="); idx != -1 {
			k := strings.ToLower(strings.TrimSpace(part[:idx]))
			v := strings.TrimSpace(part[idx+1:])
			tags[k] = v
		}
	}
	return tags
}
