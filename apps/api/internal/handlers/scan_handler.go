package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/expose/expose/apps/api/internal/scanner"
	"github.com/expose/expose/apps/api/internal/storage"
)

type ScanHandler struct {
	scanner *scanner.Engine
	repo    storage.Repository
}

func NewScanHandler(scanner *scanner.Engine, repo storage.Repository) *ScanHandler {
	return &ScanHandler{
		scanner: scanner,
		repo:    repo,
	}
}

type CreateScanRequest struct {
	Target       string `json:"target"`
	Authorized   bool   `json:"authorized"`
	AllowPrivate bool   `json:"allow_private"`
}

// HandleScans routes /api/v1/scans for POST (create scan) and GET (list recent scans).
func (h *ScanHandler) HandleScans(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req CreateScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteError(w, http.StatusBadRequest, "INVALID_JSON", "Request body must be valid JSON")
			return
		}

		if strings.TrimSpace(req.Target) == "" {
			WriteError(w, http.StatusBadRequest, "EMPTY_TARGET", "Target URL cannot be empty")
			return
		}

		// Enforce product safety stance
		if !req.Authorized {
			WriteError(w, http.StatusForbidden, "UNAUTHORIZED_SCAN_POLICY",
				"Mandatory authorization consent required: 'Only scan websites you own or are authorized to test.' Set 'authorized': true to confirm.")
			return
		}

		// Execute scan through real HTTP/TLS security engine
		scan, err := h.scanner.ExecuteScan(r.Context(), req.Target, req.AllowPrivate)
		if err != nil {
			if strings.Contains(err.Error(), "SSRF Protection") {
				WriteError(w, http.StatusForbidden, "SSRF_VIOLATION", err.Error())
				return
			}
			WriteError(w, http.StatusBadRequest, "SCAN_FAILED", err.Error())
			return
		}

		// Register target and persist scan + assets
		_, _ = h.repo.GetOrCreateTarget(r.Context(), scan.TargetID)
		_ = h.repo.SaveScan(r.Context(), scan)
		if len(scan.Assets) > 0 {
			_ = h.repo.SaveAssets(r.Context(), scan.Assets)
		}

		WriteJSON(w, http.StatusCreated, scan)

	case http.MethodGet:
		limit := 20
		offset := 0
		if lStr := r.URL.Query().Get("limit"); lStr != "" {
			if l, err := strconv.Atoi(lStr); err == nil && l > 0 && l <= 100 {
				limit = l
			}
		}
		if oStr := r.URL.Query().Get("offset"); oStr != "" {
			if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
				offset = o
			}
		}

		scans, err := h.repo.ListRecentScans(r.Context(), limit, offset)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, "STORAGE_ERROR", err.Error())
			return
		}

		WriteJSON(w, http.StatusOK, scans)

	default:
		WriteError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// HandleScanByID routes /api/v1/scans/{id}.
func (h *ScanHandler) HandleScanByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		WriteError(w, http.StatusBadRequest, "INVALID_PATH", "Scan ID missing from URL path")
		return
	}
	scanID := parts[3]

	scan, err := h.repo.GetScan(r.Context(), scanID)
	if err != nil {
		WriteError(w, http.StatusNotFound, "SCAN_NOT_FOUND", "No scan found with ID: "+scanID)
		return
	}

	WriteJSON(w, http.StatusOK, scan)
}

// HandleTargetByDomain routes /api/v1/targets/{domain}.
func (h *ScanHandler) HandleTargetByDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		WriteError(w, http.StatusBadRequest, "INVALID_PATH", "Target domain missing from URL path")
		return
	}
	domainName := parts[3]

	target, err := h.repo.GetTargetByDomain(r.Context(), domainName)
	if err != nil {
		WriteError(w, http.StatusNotFound, "TARGET_NOT_FOUND", "No target found for domain: "+domainName)
		return
	}

	history, _ := h.repo.GetScanHistory(r.Context(), target.Domain)
	assets, _ := h.repo.GetAssetsForTarget(r.Context(), target.Domain)

	resp := map[string]interface{}{
		"target":  target,
		"history": history,
		"assets":  assets,
	}

	WriteJSON(w, http.StatusOK, resp)
}
