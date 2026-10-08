package probes

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/expose/expose-backend/internal/models"
)

// Probe defines the interface for all native Go security probes.
type Probe interface {
	Name() string
	Category() models.Category
	Execute(ctx context.Context, target *models.TargetScope) ([]models.Finding, error)
}

// GenerateFindingID generates a deterministic ID for reproducibility.
func GenerateFindingID(probeName, host, title, cweID string) string {
	raw := fmt.Sprintf("%s:%s:%s:%s", probeName, host, title, cweID)
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("EXP-%X", hash[:6])
}

// CreateFinding constructs a typed Finding object.
func CreateFinding(
	probeName string,
	target *models.TargetScope,
	category models.Category,
	severity models.Severity,
	confidence models.Confidence,
	status models.ObservationStatus,
	title string,
	description string,
	impactExplanation string,
	remediation string,
	verificationCommand string,
	cweID string,
	cveID string,
	evidence models.Evidence,
) models.Finding {
	evidence.Timestamp = time.Now().UTC()
	return models.Finding{
		ID:                  GenerateFindingID(probeName, target.Host, title, cweID),
		Probe:               probeName,
		Target:              target.NormalizedURL,
		Category:            category,
		Severity:            severity,
		Confidence:          confidence,
		Status:              status,
		Title:               title,
		Description:         description,
		ImpactExplanation:   impactExplanation,
		Remediation:         remediation,
		VerificationCommand: verificationCommand,
		CWEID:               cweID,
		CVEID:               cveID,
		Evidence:            evidence,
		Timestamp:           time.Now().UTC(),
	}
}

// Helper string normalization
func CleanStr(s string) string {
	return strings.TrimSpace(s)
}
