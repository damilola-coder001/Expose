package orchestrator

import (
	"context"

	"github.com/expose/expose-backend/services/scanner"
)

// OrchestrationStatus represents the current state of a pipeline.
type OrchestrationStatus string

const (
	StatusPending   OrchestrationStatus = "PENDING"
	StatusRunning   OrchestrationStatus = "RUNNING"
	StatusCompleted OrchestrationStatus = "COMPLETED"
	StatusFailed    OrchestrationStatus = "FAILED"
)

// PipelineOrchestrator coordinates probes and workers across scanner services.
type PipelineOrchestrator interface {
	ScheduleScan(ctx context.Context, target scanner.Target) (string, error)
	CancelScan(ctx context.Context, scanID string) error
	GetStatus(ctx context.Context, scanID string) (OrchestrationStatus, error)
}
