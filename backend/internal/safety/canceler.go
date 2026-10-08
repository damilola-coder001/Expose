package safety

import (
	"context"
	"fmt"
	"sync"
)

// ScanCanceler manages emergency cancellation handles for active scans.
type ScanCanceler struct {
	mu     sync.RWMutex
	cancels map[string]context.CancelFunc
}

var GlobalCanceler = &ScanCanceler{
	cancels: make(map[string]context.CancelFunc),
}

// Register registers a cancellation function for a scan ID.
func (c *ScanCanceler) Register(scanID string, cancel context.CancelFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cancels[scanID] = cancel
}

// Unregister removes the cancellation function when a scan completes.
func (c *ScanCanceler) Unregister(scanID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cancels, scanID)
}

// Cancel triggers emergency cancellation of an in-flight scan.
func (c *ScanCanceler) Cancel(scanID string) error {
	c.mu.RLock()
	cancel, exists := c.cancels[scanID]
	c.mu.RUnlock()

	if !exists {
		return fmt.Errorf("scan ID '%s' is not actively running or cannot be cancelled", scanID)
	}

	cancel()
	c.Unregister(scanID)
	return nil
}
