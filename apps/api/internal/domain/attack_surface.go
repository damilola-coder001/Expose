package domain

import "time"

// PageAsset represents a discovered page or navigation URL.
type PageAsset struct {
	URL           string `json:"url"`
	Path          string `json:"path"`
	Title         string `json:"title,omitempty"`
	StatusCode    int    `json:"status_code,omitempty"`
	IsInternal    bool   `json:"is_internal"`
	DiscoveredVia string `json:"discovered_via"` // html_anchor, sitemap, robots_txt
}

// APIAsset represents an exposed or referenced backend API endpoint.
type APIAsset struct {
	Path         string   `json:"path"`
	Method       string   `json:"method"`
	SourceScript string   `json:"source_script,omitempty"`
	Parameters   []string `json:"parameters,omitempty"`
	IsPublic     bool     `json:"is_public"`
}

// StaticAsset represents an observable static resource (stylesheet, image, font, manifest).
type StaticAsset struct {
	URL        string `json:"url"`
	AssetType  string `json:"asset_type"` // stylesheet, image, font, media, manifest, icon
	MimeType   string `json:"mime_type,omitempty"`
	IsExternal bool   `json:"is_external"`
}

// ScriptAsset represents a discovered JavaScript file.
type ScriptAsset struct {
	URL         string `json:"url"`
	IsExternal  bool   `json:"is_external"`
	CDNProvider string `json:"cdn_provider,omitempty"`
	HasSRI      bool   `json:"has_sri"`
	SRIHash     string `json:"sri_hash,omitempty"`
}

// FormInput represents an input field inside an HTML form.
type FormInput struct {
	Name        string `json:"name"`
	InputType   string `json:"input_type"`
	IsSensitive bool   `json:"is_sensitive"`
}

// FormAsset represents a discovered HTML form.
type FormAsset struct {
	Action         string      `json:"action"`
	Method         string      `json:"method"`
	Inputs         []FormInput `json:"inputs"`
	HasPassword    bool        `json:"has_password"`
	IsSecureAction bool        `json:"is_secure_action"`
}

// ExternalDependency represents a third-party domain or origin referenced by the target.
type ExternalDependency struct {
	Origin        string   `json:"origin"`
	Category      string   `json:"category"` // CDN, Analytics, Fonts, Social, Ads, Auth, Unknown
	ResourceCount int      `json:"resource_count"`
	SampleURLs    []string `json:"sample_urls,omitempty"`
}

// RobotsTxtAsset represents parsed rules from robots.txt.
type RobotsTxtAsset struct {
	IsPresent       bool     `json:"is_present"`
	DisallowedPaths []string `json:"disallowed_paths"`
	AllowedPaths    []string `json:"allowed_paths"`
	Sitemaps        []string `json:"sitemaps"`
}

// AttackSurface models what a website exposes publicly (Phase 8).
// Target
//  ├── Pages
//  ├── APIs
//  ├── Assets
//  ├── Scripts
//  └── External dependencies
type AttackSurface struct {
	Target               string               `json:"target"`
	Pages                []PageAsset          `json:"pages"`
	APIs                 []APIAsset           `json:"apis"`
	Assets               []StaticAsset        `json:"assets"`
	Scripts              []ScriptAsset        `json:"scripts"`
	Forms                []FormAsset          `json:"forms"`
	ExternalDependencies []ExternalDependency `json:"external_dependencies"`
	RobotsTxt            *RobotsTxtAsset      `json:"robots_txt,omitempty"`
	Sitemaps             []string             `json:"sitemaps,omitempty"`
	ExposureSummary      string               `json:"exposure_summary"`
	DiscoveredAt         time.Time            `json:"discovered_at"`
}
