package probes

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/expose/expose/apps/api/internal/domain"
	"github.com/expose/expose/apps/api/internal/scope"
)

// ProbeResult encapsulates findings and assets discovered by a probe.
type ProbeResult struct {
	ProbeName     string
	Findings      []domain.Finding
	Assets        []domain.Asset
	AttackSurface *domain.AttackSurface
	Duration      time.Duration
	Error         error
}

// Probe defines the interface for security auditing components.
type Probe interface {
	Name() string
	Run(ctx context.Context, target *scope.TargetScope) (*ProbeResult, error)
}

// GenerateFindingID produces a unique prefixed finding ID.
func GenerateFindingID(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}
