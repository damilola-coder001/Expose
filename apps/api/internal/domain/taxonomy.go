package domain

// Severity level of a security finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Confidence indicates empirical certainty.
// Do not use severity as a substitute for confidence.
// A theoretical weakness should not be presented as a confirmed vulnerability.
type Confidence string

const (
	ConfidenceConfirmed     Confidence = "CONFIRMED"
	ConfidenceLikely        Confidence = "LIKELY"
	ConfidencePotential     Confidence = "POTENTIAL"
	ConfidenceInformational Confidence = "INFORMATIONAL"
)

// ObservationStatus defines the empirical distinction for report integrity.
type ObservationStatus string

const (
	StatusConfirmed   ObservationStatus = "CONFIRMED"
	StatusObserved    ObservationStatus = "OBSERVED"
	StatusInferred    ObservationStatus = "INFERRED"
	StatusNotAssessed ObservationStatus = "NOT_ASSESSED"
	StatusFixed       ObservationStatus = "FIXED"
)

// Category groups findings by security domain.
type Category string

const (
	// Phase 9 Canonical Categories
	CategoryTransportSecurity     Category = "TRANSPORT_SECURITY"
	CategoryBrowserSecurity       Category = "BROWSER_SECURITY"
	CategoryCookieSessionSecurity Category = "COOKIE_SESSION_SECURITY"
	CategoryConfiguration         Category = "CONFIGURATION"
	CategoryAttackSurface         Category = "ATTACK_SURFACE"
	CategoryInformationExposure   Category = "INFORMATION_EXPOSURE"
	CategoryAPISecurity           Category = "API_SECURITY"
	CategoryThirdPartyResources   Category = "THIRD_PARTY_RESOURCES"
	CategoryAuthentication        Category = "AUTHENTICATION"

	// Compatibility aliases
	CategoryCryptography          Category = "CRYPTOGRAPHY"
	CategoryHTTPHeaders           Category = "HTTP_HEADERS"
	CategoryCookieSecurity        Category = "COOKIE_SECURITY"
	CategorySecurityMetadata      Category = "SECURITY_METADATA"
	CategoryInformationDisclosure Category = "INFORMATION_DISCLOSURE"
	CategoryMixedContent          Category = "MIXED_CONTENT"
	CategoryNetworkPosture        Category = "NETWORK_POSTURE"
	CategoryClientSideSecurity    Category = "CLIENT_SIDE_SECURITY"
	CategoryExternalExposure      Category = "EXTERNAL_EXPOSURE"
)

// EvidenceType represents the origin of the verifiable proof.
type EvidenceType string

const (
	EvidenceHTTPExchange        EvidenceType = "HTTP_EXCHANGE"
	EvidenceDNSRecord           EvidenceType = "DNS_RECORD"
	EvidenceTLSHandshake        EvidenceType = "TLS_HANDSHAKE"
	EvidenceCertificateMetadata EvidenceType = "CERTIFICATE_METADATA"
	EvidenceCookieAttribute     EvidenceType = "COOKIE_ATTRIBUTE"
	EvidenceDOMContent          EvidenceType = "DOM_CONTENT"
	EvidenceRawSocket           EvidenceType = "RAW_SOCKET"
	EvidenceSourceMap           EvidenceType = "SOURCE_MAP"
	EvidenceClientConfig        EvidenceType = "CLIENT_CONFIG"
	EvidenceNucleiMatch         EvidenceType = "NUCLEI_MATCH"
	EvidenceScriptReference     EvidenceType = "SCRIPT_REFERENCE"
)

// AssetType categorizes observable target infrastructure artifacts.
type AssetType string

const (
	AssetHost        AssetType = "HOST"
	AssetIPAddress   AssetType = "IP_ADDRESS"
	AssetCertificate AssetType = "CERTIFICATE"
	AssetEndpoint    AssetType = "ENDPOINT"
	AssetHeader      AssetType = "HEADER"
)

// ScanStatus tracks the lifecycle of an assessment.
type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "PENDING"
	ScanStatusRunning   ScanStatus = "RUNNING"
	ScanStatusCompleted ScanStatus = "COMPLETED"
	ScanStatusFailed    ScanStatus = "FAILED"
	ScanStatusCancelled ScanStatus = "CANCELLED"
)
