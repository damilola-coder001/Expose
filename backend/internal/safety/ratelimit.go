package safety

import (
	"sync"
	"time"
)

// DomainRateLimiter enforces maximum requests per second per target host.
type DomainRateLimiter struct {
	mu          sync.Mutex
	lastRequest map[string]time.Time
	minInterval time.Duration
}

// NewDomainRateLimiter creates a limiter with rate (e.g. 5 requests/sec => 200ms interval).
func NewDomainRateLimiter(reqsPerSecond int) *DomainRateLimiter {
	interval := time.Second / time.Duration(reqsPerSecond)
	return &DomainRateLimiter{
		lastRequest: make(map[string]time.Time),
		minInterval: interval,
	}
}

// Wait blocks until the domain is clear to receive another request.
func (r *DomainRateLimiter) Wait(domain string) {
	r.mu.Lock()
	last, exists := r.lastRequest[domain]
	now := time.Now()

	var sleepDuration time.Duration
	if exists {
		elapsed := now.Sub(last)
		if elapsed < r.minInterval {
			sleepDuration = r.minInterval - elapsed
		}
	}
	r.lastRequest[domain] = now.Add(sleepDuration)
	r.mu.Unlock()

	if sleepDuration > 0 {
		time.Sleep(sleepDuration)
	}
}
