package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/expose/expose/apps/api/internal/cache"
	"github.com/expose/expose/apps/api/internal/config"
	"github.com/expose/expose/apps/api/internal/database"
)

func TestHealthHandler_Health(t *testing.T) {
	cfg := &config.Config{
		ServiceName: "expose-api-test",
		Version:     "0.1.0",
	}

	dbClient, _ := database.NewClient("postgres://localhost:5432/expose")
	rcClient, _ := cache.NewClient("redis://localhost:6379")

	handler := NewHealthHandler(cfg, dbClient, rcClient)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	handler.Health(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode json response: %v", err)
	}

	if resp["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got %v", resp["status"])
	}

	if resp["service"] != "expose-api-test" {
		t.Errorf("expected service 'expose-api-test', got %v", resp["service"])
	}
}

func TestHealthHandler_Ready_Disconnected(t *testing.T) {
	cfg := &config.Config{
		ServiceName: "expose-api-test",
		Version:     "0.1.0",
	}

	// Use an unroutable port to guarantee disconnected state in unit test
	dbClient, _ := database.NewClient("postgres://127.0.0.1:59999/expose")
	rcClient, _ := cache.NewClient("redis://127.0.0.1:59998")

	handler := NewHealthHandler(cfg, dbClient, rcClient)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rr := httptest.NewRecorder()

	handler.Ready(rr, req)

	// When dependencies are down, ready check must return 503 Service Unavailable
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503 Service Unavailable, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode json response: %v", err)
	}

	if resp["status"] != "not_ready" {
		t.Errorf("expected status 'not_ready', got %v", resp["status"])
	}
}
