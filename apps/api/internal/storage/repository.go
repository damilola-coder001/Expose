package storage

import (
	"context"
	"errors"

	"github.com/expose/expose/apps/api/internal/domain"
)

var (
	ErrNotFound      = errors.New("entity not found")
	ErrAlreadyExists = errors.New("entity already exists")
)

// Repository defines persistence operations across the domain model.
type Repository interface {
	// Target operations
	GetOrCreateTarget(ctx context.Context, domainName string) (*domain.Target, error)
	GetTarget(ctx context.Context, id string) (*domain.Target, error)
	GetTargetByDomain(ctx context.Context, domainName string) (*domain.Target, error)

	// Scan operations
	SaveScan(ctx context.Context, scan *domain.Scan) error
	GetScan(ctx context.Context, scanID string) (*domain.Scan, error)
	ListRecentScans(ctx context.Context, limit, offset int) ([]*domain.Scan, error)
	ListScansForTarget(ctx context.Context, targetID string, limit int) ([]*domain.Scan, error)

	// History & Assets
	GetScanHistory(ctx context.Context, targetID string) ([]domain.ScanHistory, error)
	SaveAssets(ctx context.Context, assets []domain.Asset) error
	GetAssetsForTarget(ctx context.Context, targetID string) ([]domain.Asset, error)
}
