package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/expose/expose/apps/api/internal/domain"
)

// MemoryRepository provides thread-safe in-memory persistence.
type MemoryRepository struct {
	mu          sync.RWMutex
	targets     map[string]*domain.Target // id -> Target
	targetByDom map[string]string         // domain -> id
	scans       map[string]*domain.Scan   // id -> Scan
	scanOrder   []string                  // scan IDs ordered by recency
	assets      map[string][]domain.Asset // target_id -> []Asset
}

// NewMemoryRepository initializes an empty in-memory repository.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		targets:     make(map[string]*domain.Target),
		targetByDom: make(map[string]string),
		scans:       make(map[string]*domain.Scan),
		scanOrder:   make([]string, 0),
		assets:      make(map[string][]domain.Asset),
	}
}

func generateID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func (m *MemoryRepository) GetOrCreateTarget(ctx context.Context, domainName string) (*domain.Target, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cleanDom := strings.ToLower(strings.TrimSpace(domainName))
	if id, exists := m.targetByDom[cleanDom]; exists {
		return m.targets[id], nil
	}

	target := &domain.Target{
		ID:          generateID("tgt"),
		Domain:      cleanDom,
		DefaultPort: 443,
		IsVerified:  false,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}

	m.targets[target.ID] = target
	m.targetByDom[cleanDom] = target.ID
	return target, nil
}

func (m *MemoryRepository) GetTarget(ctx context.Context, id string) (*domain.Target, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	t, exists := m.targets[id]
	if !exists {
		return nil, ErrNotFound
	}
	return t, nil
}

func (m *MemoryRepository) GetTargetByDomain(ctx context.Context, domainName string) (*domain.Target, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cleanDom := strings.ToLower(strings.TrimSpace(domainName))
	id, exists := m.targetByDom[cleanDom]
	if !exists {
		return nil, ErrNotFound
	}
	return m.targets[id], nil
}

func (m *MemoryRepository) SaveScan(ctx context.Context, scan *domain.Scan) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.scans[scan.ID]; !exists {
		m.scanOrder = append([]string{scan.ID}, m.scanOrder...)
	}
	m.scans[scan.ID] = scan
	return nil
}

func (m *MemoryRepository) GetScan(ctx context.Context, scanID string) (*domain.Scan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, exists := m.scans[scanID]
	if !exists {
		return nil, ErrNotFound
	}
	return s, nil
}

func (m *MemoryRepository) ListRecentScans(ctx context.Context, limit, offset int) ([]*domain.Scan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if offset >= len(m.scanOrder) {
		return []*domain.Scan{}, nil
	}

	end := offset + limit
	if end > len(m.scanOrder) {
		end = len(m.scanOrder)
	}

	results := make([]*domain.Scan, 0, end-offset)
	for i := offset; i < end; i++ {
		id := m.scanOrder[i]
		if s, ok := m.scans[id]; ok {
			results = append(results, s)
		}
	}
	return results, nil
}

func (m *MemoryRepository) ListScansForTarget(ctx context.Context, targetID string, limit int) ([]*domain.Scan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	results := make([]*domain.Scan, 0)
	for _, id := range m.scanOrder {
		if s, ok := m.scans[id]; ok && s.TargetID == targetID {
			results = append(results, s)
			if len(results) >= limit {
				break
			}
		}
	}
	return results, nil
}

func (m *MemoryRepository) GetScanHistory(ctx context.Context, targetID string) ([]domain.ScanHistory, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	history := make([]domain.ScanHistory, 0)
	for _, id := range m.scanOrder {
		if s, ok := m.scans[id]; ok && s.TargetID == targetID && s.Status == domain.ScanStatusCompleted {
			score := 0
			grade := "N/A"
			if s.ScoreCard != nil {
				score = s.ScoreCard.OverallScore
				grade = s.ScoreCard.LetterGrade
			}
			history = append(history, domain.ScanHistory{
				TargetID:      targetID,
				ScanID:        s.ID,
				Score:         score,
				Grade:         grade,
				FindingsCount: len(s.Findings),
				Timestamp:     s.StartedAt,
			})
		}
	}
	return history, nil
}

func (m *MemoryRepository) SaveAssets(ctx context.Context, assets []domain.Asset) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, a := range assets {
		if a.ID == "" {
			a.ID = generateID("ast")
		}
		if a.DiscoveredAt.IsZero() {
			a.DiscoveredAt = time.Now().UTC()
		}
		m.assets[a.TargetID] = append(m.assets[a.TargetID], a)
	}
	return nil
}

func (m *MemoryRepository) GetAssetsForTarget(ctx context.Context, targetID string) ([]domain.Asset, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if assets, exists := m.assets[targetID]; exists {
		return assets, nil
	}
	return []domain.Asset{}, nil
}
