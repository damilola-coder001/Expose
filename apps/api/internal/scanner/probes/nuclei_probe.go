package probes

import (
	"context"
	"time"

	"github.com/expose/expose/apps/api/internal/scanner/nuclei"
	"github.com/expose/expose/apps/api/internal/scope"
)

// NucleiProbe integrates the isolated Nuclei worker into the Expose probe pipeline.
type NucleiProbe struct {
	worker *nuclei.Worker
}

// NewNucleiProbe constructs a probe backed by the Nuclei worker pool.
func NewNucleiProbe() *NucleiProbe {
	return &NucleiProbe{
		worker: nuclei.NewWorker(nuclei.DefaultConfig()),
	}
}

func (p *NucleiProbe) Name() string {
	return "nuclei_exposure_probe"
}

func (p *NucleiProbe) Run(ctx context.Context, target *scope.TargetScope) (*ProbeResult, error) {
	start := time.Now()
	res := &ProbeResult{
		ProbeName: p.Name(),
	}

	job := nuclei.ScanJob{
		ScanID:      GenerateFindingID("job_nuc"),
		TargetURL:   target.NormalizedURL,
		TemplateIDs: nil, // nil triggers default approved catalog
	}

	findings, err := p.worker.ExecuteScan(ctx, job)
	if err != nil {
		res.Error = err
		res.Duration = time.Since(start)
		// Non-fatal probe failure to ensure overall scan completes
		return res, nil
	}

	res.Findings = findings
	res.Duration = time.Since(start)
	return res, nil
}
