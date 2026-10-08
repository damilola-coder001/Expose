package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/expose/expose-backend/internal/engine"
	"github.com/expose/expose-backend/internal/models"
	"github.com/expose/expose-backend/internal/safety"
)

type APIHandler struct {
	orchestrator *engine.Orchestrator
	scansLock    sync.RWMutex
	scans        map[string]*models.ScanResult
	activeScans  map[string]string // scan_id -> "running", "completed", "failed", "cancelled"
}

func NewAPIHandler() *APIHandler {
	return &APIHandler{
		orchestrator: engine.NewOrchestrator(),
		scans:        make(map[string]*models.ScanResult),
		activeScans:  make(map[string]string),
	}
}

type ScanRequest struct {
	Target       string `json:"target"`
	AllowPrivate bool   `json:"allow_private"`
}

type ScanStatusResponse struct {
	ScanID string `json:"scan_id"`
	Target string `json:"target"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

func (h *APIHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := map[string]interface{}{
		"status":    "healthy",
		"version":   "0.2.0",
		"product":   "EXPOSE",
		"tagline":   "See what your website exposes.",
		"principle": "Evidence first. Intelligence second.",
		"backend":   "Go (High Concurrency Security Engine)",
		"safety_model": map[string]string{
			"policy":   "Only scan websites you own or are authorized to test.",
			"baseline": "Non-destructive, externally observable checks.",
		},
		"probes": []string{
			"dns_posture",
			"tls_posture",
			"http_headers",
			"cookie_security",
			"security_metadata",
			"nuclei_component",
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *APIHandler) HandleScans(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		result, err := h.orchestrator.Scan(r.Context(), req.Target, req.AllowPrivate)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		h.scansLock.Lock()
		h.scans[result.ScanID] = result
		h.activeScans[result.ScanID] = "completed"
		h.scansLock.Unlock()

		writeJSON(w, http.StatusCreated, result)

	case http.MethodGet:
		h.scansLock.RLock()
		defer h.scansLock.RUnlock()
		var list []*models.ScanResult
		for _, s := range h.scans {
			list = append(list, s)
		}
		writeJSON(w, http.StatusOK, list)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *APIHandler) HandleScanAsync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Validate target pre-flight before backgrounding
	scope, err := safety.ValidateTarget(req.Target, req.AllowPrivate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	scanID := "scn_async_" + scope.Host

	h.scansLock.Lock()
	h.activeScans[scanID] = "running"
	h.scansLock.Unlock()

	go func() {
		res, sErr := h.orchestrator.Scan(context.Background(), req.Target, req.AllowPrivate)
		h.scansLock.Lock()
		defer h.scansLock.Unlock()
		if sErr != nil {
			h.activeScans[scanID] = "failed: " + sErr.Error()
		} else {
			h.scans[res.ScanID] = res
			h.activeScans[res.ScanID] = "completed"
		}
	}()

	writeJSON(w, http.StatusAccepted, ScanStatusResponse{
		ScanID: scanID,
		Target: req.Target,
		Status: "running",
	})
}

func (h *APIHandler) HandleScanByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/scans/")
	parts := strings.Split(path, "/")
	scanID := parts[0]

	if scanID == "" {
		http.Error(w, "Scan ID required", http.StatusBadRequest)
		return
	}

	// Check if this is a cancel request: /api/v1/scans/{id}/cancel
	if len(parts) >= 2 && parts[1] == "cancel" && r.Method == http.MethodPost {
		if err := safety.GlobalCanceler.Cancel(scanID); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		h.scansLock.Lock()
		h.activeScans[scanID] = "cancelled"
		h.scansLock.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{
			"scan_id": scanID,
			"status":  "cancelled",
			"message": "Emergency cancellation signal dispatched successfully.",
		})
		return
	}

	// Check if this is an evidence request: /api/v1/scans/{id}/evidence/{finding_id}
	if len(parts) >= 3 && parts[1] == "evidence" && r.Method == http.MethodGet {
		findingID := parts[2]
		h.scansLock.RLock()
		scan, exists := h.scans[scanID]
		h.scansLock.RUnlock()

		if !exists {
			http.Error(w, "Scan not found", http.StatusNotFound)
			return
		}

		for _, f := range scan.Findings {
			if strings.EqualFold(f.ID, findingID) {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"finding_id":           f.ID,
					"title":                f.Title,
					"status":               f.Status,
					"severity":             f.Severity,
					"confidence":           f.Confidence,
					"verification_command": f.VerificationCommand,
					"impact_explanation":   f.ImpactExplanation,
					"evidence":             f.Evidence,
				})
				return
			}
		}
		http.Error(w, "Finding ID not found", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.scansLock.RLock()
	scan, exists := h.scans[scanID]
	status, active := h.activeScans[scanID]
	h.scansLock.RUnlock()

	if exists {
		writeJSON(w, http.StatusOK, scan)
		return
	}

	if active {
		writeJSON(w, http.StatusAccepted, map[string]string{
			"scan_id": scanID,
			"status":  status,
		})
		return
	}

	http.Error(w, "Scan not found", http.StatusNotFound)
}

func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}
