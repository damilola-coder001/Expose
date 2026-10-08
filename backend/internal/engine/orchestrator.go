package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/expose/expose-backend/internal/integrations/nuclei"
	"github.com/expose/expose-backend/internal/models"
	"github.com/expose/expose-backend/internal/probes"
	"github.com/expose/expose-backend/internal/safety"
	"github.com/expose/expose-backend/internal/scoring"
)

type Orchestrator struct {
	nativeProbes []probes.Probe
	nucleiRunner *nuclei.Runner
	rateLimiter  *safety.DomainRateLimiter
}

func NewOrchestrator() *Orchestrator {
	return &Orchestrator{
		nativeProbes: []probes.Probe{
			probes.NewDNSProbe(),
			probes.NewTLSProbe(),
			probes.NewHTTPProbe(),
			probes.NewCookieProbe(),
			probes.NewMetadataProbe(),
		},
		nucleiRunner: nuclei.NewRunner(),
		rateLimiter:  safety.NewDomainRateLimiter(5), // 5 reqs/sec per safety model
	}
}

func generateScanID() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return fmt.Sprintf("scn_%s", hex.EncodeToString(b))
}

// Scan executes an end-to-end security posture assessment.
func (o *Orchestrator) Scan(ctx context.Context, rawTarget string, allowPrivate bool) (*models.ScanResult, error) {
	// 1. Validate Target and Enforce Pre-Flight SSRF Guard
	targetScope, err := safety.ValidateTarget(rawTarget, allowPrivate)
	if err != nil {
		return nil, err
	}

	scanID := generateScanID()
	startTime := time.Now().UTC()

	// Register emergency cancellation hook
	scanCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	safety.GlobalCanceler.Register(scanID, cancel)
	defer safety.GlobalCanceler.Unregister(scanID)

	var (
		findingsLock  sync.Mutex
		allFindings   []models.Finding
		statusLock    sync.Mutex
		probeStatuses []models.ProbeStatus
		wg            sync.WaitGroup
	)

	// Concurrency semaphore (max 4 concurrent probe executions per scan)
	semaphore := make(chan struct{}, 4)

	// Execute Native Go Probes concurrently
	for _, p := range o.nativeProbes {
		wg.Add(1)
		go func(probe probes.Probe) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			t0 := time.Now()
			probeName := probe.Name()

			// Apply rate limiter per domain
			o.rateLimiter.Wait(targetScope.Host)

			findings, pErr := probe.Execute(scanCtx, targetScope)
			elapsed := time.Since(t0).Seconds()

			statusLock.Lock()
			if pErr != nil {
				probeStatuses = append(probeStatuses, models.ProbeStatus{
					ProbeName:       probeName,
					Status:          "failed",
					DurationSeconds: elapsed,
					ErrorMessage:    pErr.Error(),
				})
			} else {
				probeStatuses = append(probeStatuses, models.ProbeStatus{
					ProbeName:       probeName,
					Status:          "completed",
					DurationSeconds: elapsed,
				})
			}
			statusLock.Unlock()

			if len(findings) > 0 {
				findingsLock.Lock()
				allFindings = append(allFindings, findings...)
				findingsLock.Unlock()
			}
		}(p)
	}

	// Execute Nuclei Component if available
	if o.nucleiRunner.IsAvailable() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			t0 := time.Now()
			findings, nErr := o.nucleiRunner.ExecuteSafeRun(scanCtx, targetScope)
			elapsed := time.Since(t0).Seconds()

			statusLock.Lock()
			if nErr != nil {
				probeStatuses = append(probeStatuses, models.ProbeStatus{
					ProbeName:       "nuclei_component",
					Status:          "failed",
					DurationSeconds: elapsed,
					ErrorMessage:    nErr.Error(),
				})
			} else {
				probeStatuses = append(probeStatuses, models.ProbeStatus{
					ProbeName:       "nuclei_component",
					Status:          "completed",
					DurationSeconds: elapsed,
				})
			}
			statusLock.Unlock()

			if len(findings) > 0 {
				findingsLock.Lock()
				allFindings = append(allFindings, findings...)
				findingsLock.Unlock()
			}
		}()
	}

	wg.Wait()

	// Sort findings by severity then title
	sevOrder := map[models.Severity]int{
		models.SeverityCritical: 0,
		models.SeverityHigh:     1,
		models.SeverityMedium:   2,
		models.SeverityLow:      3,
		models.SeverityInfo:     4,
	}

	sort.SliceStable(allFindings, func(i, j int) bool {
		si := sevOrder[allFindings[i].Severity]
		sj := sevOrder[allFindings[j].Severity]
		if si != sj {
			return si < sj
		}
		return allFindings[i].Title < allFindings[j].Title
	})

	endTime := time.Now().UTC()
	totalDuration := endTime.Sub(startTime).Seconds()

	// Compute Deterministic ScoreCard
	scoreCard := scoring.CalculateScoreCard(allFindings)

	// Calculate severity counts
	counts := map[string]int{
		"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
	}
	for _, f := range allFindings {
		if f.Status == models.StatusConfirmed {
			counts[string(f.Severity)]++
		}
	}

	return &models.ScanResult{
		ScanID:          scanID,
		Target:          *targetScope,
		StartTime:       startTime,
		EndTime:         &endTime,
		DurationSeconds: totalDuration,
		ScoreCard:       scoreCard,
		ProbeStatuses:   probeStatuses,
		Findings:        allFindings,
		SeverityCounts:  counts,
	}, nil
}
