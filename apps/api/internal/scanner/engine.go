package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/expose/expose/apps/api/internal/domain"
	"github.com/expose/expose/apps/api/internal/scanner/probes"
	"github.com/expose/expose/apps/api/internal/scanner/scoring"
	"github.com/expose/expose/apps/api/internal/scope"
)

// Engine coordinates security auditing probes across a validated target.
type Engine struct {
	probes []probes.Probe
}

// NewEngine initializes the core HTTP/TLS, Nuclei, Browser, and Attack Surface security scanner.
func NewEngine() *Engine {
	return &Engine{
		probes: []probes.Probe{
			probes.NewHTTPPostureProbe(),
			probes.NewTLSProbe(),
			probes.NewHeadersProbe(),
			probes.NewCookieProbe(),
			probes.NewMixedContentProbe(),
			probes.NewNucleiProbe(),
			probes.NewBrowserProbe(),
			probes.NewAttackSurfaceProbe(),
		},
	}
}

func generateScanID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "scn_" + hex.EncodeToString(b)
}

// ExecuteScan validates the target scope and runs all probes concurrently.
func (e *Engine) ExecuteScan(ctx context.Context, rawTarget string, allowPrivate bool) (*domain.Scan, error) {
	startTime := time.Now().UTC()

	// 1. Phase 3: Scope and Target Validation (Pre-flight SSRF & Protocol Checks)
	targetScope, err := scope.ValidateTarget(rawTarget, allowPrivate)
	if err != nil {
		return nil, fmt.Errorf("scope validation failed: %w", err)
	}

	scanID := generateScanID()

	scan := &domain.Scan{
		ID:             scanID,
		TargetID:       targetScope.Host,
		RawTarget:      rawTarget,
		NormalizedURL:  targetScope.NormalizedURL,
		Status:         domain.ScanStatusRunning,
		Findings:       make([]domain.Finding, 0),
		Assets:         make([]domain.Asset, 0),
		SeverityCounts: make(map[domain.Severity]int),
		StartedAt:      startTime,
	}

	// 2. Execute Probes Concurrently
	var wg sync.WaitGroup
	resultChan := make(chan *probes.ProbeResult, len(e.probes))

	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for _, p := range e.probes {
		wg.Add(1)
		go func(probe probes.Probe) {
			defer wg.Done()
			res, pErr := probe.Run(probeCtx, targetScope)
			if pErr != nil {
				resultChan <- &probes.ProbeResult{
					ProbeName: probe.Name(),
					Error:     pErr,
				}
				return
			}
			resultChan <- res
		}(p)
	}

	wg.Wait()
	close(resultChan)

	// 3. Aggregate Probe Findings and Assets
	for res := range resultChan {
		if res == nil {
			continue
		}
		for _, f := range res.Findings {
			f.ScanID = scanID
			scan.Findings = append(scan.Findings, f)
			scan.SeverityCounts[f.Severity]++
		}
		for _, a := range res.Assets {
			a.TargetID = targetScope.Host
			scan.Assets = append(scan.Assets, a)
		}
		if res.AttackSurface != nil {
			scan.AttackSurface = res.AttackSurface
		}
	}

	// 4. Calculate Deterministic 0-100 ScoreCard
	scoreCard := scoring.CalculateScoreCard(scan.Findings)
	scan.ScoreCard = scoreCard

	// 5. Generate Evidence-Driven Risk Assessment Narrative
	riskAssessment := generateRiskAssessment(scan.Findings, scoreCard)
	scan.RiskAssessment = riskAssessment

	completedTime := time.Now().UTC()
	scan.CompletedAt = &completedTime
	scan.DurationSeconds = completedTime.Sub(startTime).Seconds()
	scan.Status = domain.ScanStatusCompleted

	return scan, nil
}

func generateRiskAssessment(findings []domain.Finding, card *domain.ScoreCard) *domain.RiskAssessment {
	criticals := make([]string, 0)
	positives := make([]string, 0)

	for _, f := range findings {
		if f.Severity == domain.SeverityCritical || f.Severity == domain.SeverityHigh {
			criticals = append(criticals, fmt.Sprintf("%s: %s", f.Title, f.Impact))
		}
		if f.Severity == domain.SeverityInfo && f.Status == domain.StatusObserved {
			positives = append(positives, f.Title)
		}
	}

	summary := fmt.Sprintf("Observed security posture scored at %d/100 (Grade %s). Verified %d confirmed flaws and %d positive security controls.",
		card.OverallScore, card.LetterGrade, card.ConfirmedFlawsCount, card.ObservedPropertiesCount)

	if len(criticals) == 0 {
		summary += " No critical or high-severity vulnerabilities were externally observable."
	} else {
		summary += fmt.Sprintf(" %d urgent issues require immediate remediation.", len(criticals))
	}

	return &domain.RiskAssessment{
		PostureSummary: summary,
		CriticalRisks:  criticals,
		PositiveNotes:  positives,
		GeneratedAt:    time.Now().UTC(),
	}
}
