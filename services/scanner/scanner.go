package scanner

import (
	"context"
	"time"
)

// Target defines a validated target to scan.
type Target struct {
	URL          string
	Host         string
	Port         int
	AllowPrivate bool
}

// Result represents the raw observation from a scanner probe.
type Result struct {
	ProbeName string
	Findings  []interface{}
	Duration  time.Duration
	Error     error
}

// Scanner defines the interface for modular probes in upcoming phases.
type Scanner interface {
	Name() string
	Run(ctx context.Context, target Target) (*Result, error)
}
