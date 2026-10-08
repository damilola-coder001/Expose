package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/expose/expose/apps/api/internal/cache"
	"github.com/expose/expose/apps/api/internal/config"
	"github.com/expose/expose/apps/api/internal/database"
)

// HealthHandler manages liveness and readiness probe requests.
type HealthHandler struct {
	cfg       *config.Config
	startTime time.Time
	dbClient  *database.Client
	rcClient  *cache.Client
}

// NewHealthHandler constructs a HealthHandler instance with dependencies.
func NewHealthHandler(cfg *config.Config, dbClient *database.Client, rcClient *cache.Client) *HealthHandler {
	return &HealthHandler{
		cfg:       cfg,
		startTime: time.Now(),
		dbClient:  dbClient,
		rcClient:  rcClient,
	}
}

// Health checks liveness (GET /health).
// Always returns 200 OK while the server process is responsive.
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET method is supported on /health")
		return
	}

	uptime := time.Since(h.startTime).Seconds()
	resp := map[string]interface{}{
		"status":         "healthy",
		"service":        h.cfg.ServiceName,
		"version":        h.cfg.Version,
		"uptime_seconds": uptime,
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
	}

	WriteJSON(w, http.StatusOK, resp)
}

// Ready checks readiness (GET /ready).
// Actively verifies downstream dependencies (PostgreSQL and Redis).
// Returns 200 OK if all dependencies are UP, or 503 Service Unavailable if any dependency is DOWN.
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET method is supported on /ready")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	pgStatus := h.dbClient.Ping(ctx)
	redisStatus := h.rcClient.Ping(ctx)

	isReady := pgStatus.State == "UP" && redisStatus.State == "UP"

	statusText := "ready"
	httpCode := http.StatusOK

	if !isReady {
		statusText = "not_ready"
		httpCode = http.StatusServiceUnavailable
	}

	resp := map[string]interface{}{
		"status":    statusText,
		"service":   h.cfg.ServiceName,
		"version":   h.cfg.Version,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"dependencies": map[string]interface{}{
			"postgres": pgStatus,
			"redis":    redisStatus,
		},
	}

	WriteJSON(w, httpCode, resp)
}
