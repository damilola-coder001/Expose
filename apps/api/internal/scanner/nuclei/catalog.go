package nuclei

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrArbitraryTemplateNotAllowed = errors.New("arbitrary user-supplied templates are prohibited in public scans")
	ErrTemplateNotFound            = errors.New("requested template is not in approved catalog")
	ErrEmptyTemplateSelection      = errors.New("no approved templates selected for scan job")
)

// VersionMetadata tracks scanner and template versions for auditability.
type VersionMetadata struct {
	ScannerVersion        string    `json:"scanner_version"`
	TemplatesVersion      string    `json:"templates_version"`
	CatalogApprovedAt     time.Time `json:"catalog_approved_at"`
	SupportedCategories   []string  `json:"supported_categories"`
}

// CurrentVersion provides active version information.
var CurrentVersion = VersionMetadata{
	ScannerVersion:    "v3.3.0",
	TemplatesVersion:  "v10.1.2",
	CatalogApprovedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
	SupportedCategories: []string{
		"exposures",
		"misconfigurations",
		"technologies",
		"ssl-dns",
	},
}

// ApprovedTemplate represents a vetted, strictly non-destructive scanner template.
type ApprovedTemplate struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Path        string `json:"path"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	IsSafe      bool   `json:"is_safe"`
}

// ApprovedCatalog is the authoritative whitelist of permissible Nuclei templates.
// Strictly non-intrusive: only passive exposures, header/config checks, and technology fingerprinting.
// Exploit payloads, brute-forcing, and destructive injection templates are completely omitted.
var ApprovedCatalog = map[string]ApprovedTemplate{
	"git-config-exposure": {
		ID:          "git-config-exposure",
		Name:        "Git Configuration File Exposure",
		Category:    "exposures",
		Path:        "http/exposures/tokens/git-config-exposure.yaml",
		Description: "Detects exposed .git/config files leaking internal repository structure and credentials.",
		Severity:    "medium",
		IsSafe:      true,
	},
	"env-file-exposure": {
		ID:          "env-file-exposure",
		Name:        "Environment (.env) File Exposure",
		Category:    "exposures",
		Path:        "http/exposures/tokens/env-file-exposure.yaml",
		Description: "Detects publicly accessible .env configuration files containing application secrets.",
		Severity:    "high",
		IsSafe:      true,
	},
	"backup-file-exposure": {
		ID:          "backup-file-exposure",
		Name:        "Database / Web Archive Backup Exposure",
		Category:    "exposures",
		Path:        "http/exposures/backups/backup-files.yaml",
		Description: "Detects exposed backup files (.sql.bak, .zip, .tar.gz) left in web server root.",
		Severity:    "high",
		IsSafe:      true,
	},
	"cors-misconfiguration": {
		ID:          "cors-misconfiguration",
		Name:        "Insecure CORS Wildcard / Origin Reflection",
		Category:    "misconfigurations",
		Path:        "http/misconfigurations/cors-misconfiguration.yaml",
		Description: "Detects Cross-Origin Resource Sharing misconfigurations that reflect arbitrary origins.",
		Severity:    "medium",
		IsSafe:      true,
	},
	"server-status-exposure": {
		ID:          "server-status-exposure",
		Name:        "Apache / Nginx Server Status Page Exposed",
		Category:    "misconfigurations",
		Path:        "http/misconfigurations/server-status.yaml",
		Description: "Detects publicly accessible server-status or server-info metrics endpoints.",
		Severity:    "low",
		IsSafe:      true,
	},
	"tech-detect": {
		ID:          "tech-detect",
		Name:        "Technology Fingerprint Detection",
		Category:    "technologies",
		Path:        "http/technologies/tech-detect.yaml",
		Description: "Passive fingerprinting of CMS, CDN, and framework versions via HTTP headers and HTML markers.",
		Severity:    "info",
		IsSafe:      true,
	},
	"dns-zone-transfer": {
		ID:          "dns-zone-transfer",
		Name:        "DNS AXFR Zone Transfer Disclosure",
		Category:    "ssl-dns",
		Path:        "dns/zone-transfer.yaml",
		Description: "Checks if authoritative nameservers allow unrestricted zone transfers (AXFR).",
		Severity:    "medium",
		IsSafe:      true,
	},
}

// ValidateTemplates validates a user or pipeline request against the approved catalog.
// Returns an error if any requested template is arbitrary or unauthorized.
func ValidateTemplates(requested []string) ([]ApprovedTemplate, error) {
	if len(requested) == 0 {
		// Default to all approved safe templates
		all := make([]ApprovedTemplate, 0, len(ApprovedCatalog))
		for _, t := range ApprovedCatalog {
			all = append(all, t)
		}
		return all, nil
	}

	var approved []ApprovedTemplate
	for _, req := range requested {
		cleaned := strings.TrimSpace(strings.ToLower(req))
		// Disallow directory traversals, arbitrary URLs, and local paths
		if strings.Contains(cleaned, "/") || strings.Contains(cleaned, "\\") || strings.Contains(cleaned, "..") || strings.HasPrefix(cleaned, "http") {
			return nil, fmt.Errorf("%w: path %q", ErrArbitraryTemplateNotAllowed, req)
		}

		tpl, exists := ApprovedCatalog[cleaned]
		if !exists {
			return nil, fmt.Errorf("%w: %q", ErrTemplateNotFound, req)
		}
		approved = append(approved, tpl)
	}

	return approved, nil
}
