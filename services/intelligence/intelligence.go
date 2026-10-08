package intelligence

import "context"

// ImpactAssessment describes the risk narrative derived from empirical findings.
type ImpactAssessment struct {
	Summary            string   `json:"summary"`
	ThreatNarrative    string   `json:"threat_narrative"`
	RecommendedActions []string `json:"recommended_actions"`
}

// Engine defines the intelligence layer interface for synthesizing findings.
type Engine interface {
	AssessRisk(ctx context.Context, findingIDs []string) (*ImpactAssessment, error)
}
