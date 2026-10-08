package storage

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/expose/expose-backend/internal/models"
)

var (
	ErrNotFound = errors.New("record not found")
)

// AuditLogEntry represents an audit record for tracking user consent and operations.
type AuditLogEntry struct {
	ID                  string    `json:"id"`
	ScanID              string    `json:"scan_id,omitempty"`
	TargetURL           string    `json:"target_url"`
	ClientIP            string    `json:"client_ip"`
	UserAgent           string    `json:"user_agent,omitempty"`
	Action              string    `json:"action"`
	AuthorizedConfirmed bool      `json:"authorized_confirmed"`
	Details             string    `json:"details,omitempty"`
	Timestamp           time.Time `json:"timestamp"`
}

// Store defines persistence operations for scans and audit trails.
type Store interface {
	SaveScan(ctx context.Context, scan *models.ScanResult) error
	GetScan(ctx context.Context, scanID string) (*models.ScanResult, error)
	ListScans(ctx context.Context, limit, offset int) ([]*models.ScanResult, error)
	RecordAudit(ctx context.Context, entry *AuditLogEntry) error
}

// MemoryStore provides in-memory concurrent persistence for scans and audits.
type MemoryStore struct {
	mu        sync.RWMutex
	scans     map[string]*models.ScanResult
	scanOrder []string
	audits    []*AuditLogEntry
}

// NewMemoryStore initializes a new in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		scans:     make(map[string]*models.ScanResult),
		scanOrder: make([]string, 0),
		audits:    make([]*AuditLogEntry, 0),
	}
}

func (m *MemoryStore) SaveScan(ctx context.Context, scan *models.ScanResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.scans[scan.ScanID]; !exists {
		m.scanOrder = append([]string{scan.ScanID}, m.scanOrder...) // Prepend for recency
	}
	m.scans[scan.ScanID] = scan
	return nil
}

func (m *MemoryStore) GetScan(ctx context.Context, scanID string) (*models.ScanResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scan, exists := m.scans[scanID]
	if !exists {
		return nil, ErrNotFound
	}
	return scan, nil
}

func (m *MemoryStore) ListScans(ctx context.Context, limit, offset int) ([]*models.ScanResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if offset >= len(m.scanOrder) {
		return []*models.ScanResult{}, nil
	}

	end := offset + limit
	if end > len(m.scanOrder) {
		end = len(m.scanOrder)
	}

	results := make([]*models.ScanResult, 0, end-offset)
	for i := offset; i < end; i++ {
		id := m.scanOrder[i]
		if s, ok := m.scans[id]; ok {
			results = append(results, s)
		}
	}
	return results, nil
}

func (m *MemoryStore) RecordAudit(ctx context.Context, entry *AuditLogEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	m.audits = append(m.audits, entry)
	return nil
}
