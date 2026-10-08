package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/expose/expose/apps/api/internal/domain"
	"github.com/expose/expose/apps/api/internal/scanner"
	"github.com/expose/expose/apps/api/internal/storage"
)

func TestScanHandler_UnauthorizedConsent(t *testing.T) {
	repo := storage.NewMemoryRepository()
	scannerEngine := scanner.NewEngine()
	handler := NewScanHandler(scannerEngine, repo)

	reqBody := map[string]interface{}{
		"target":     "https://example.com",
		"authorized": false, // did not consent
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewReader(bodyBytes))
	rr := httptest.NewRecorder()

	handler.HandleScans(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for missing authorization, got %d", rr.Code)
	}

	var errResp ErrorResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &errResp)
	if errResp.Error.Code != "UNAUTHORIZED_SCAN_POLICY" {
		t.Errorf("expected error code UNAUTHORIZED_SCAN_POLICY, got %s", errResp.Error.Code)
	}
}

func TestScanHandler_SSRFBlocked(t *testing.T) {
	repo := storage.NewMemoryRepository()
	scannerEngine := scanner.NewEngine()
	handler := NewScanHandler(scannerEngine, repo)

	// Attempt scanning loopback address
	reqBody := map[string]interface{}{
		"target":        "http://127.0.0.1:8080",
		"authorized":    true,
		"allow_private": false,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewReader(bodyBytes))
	rr := httptest.NewRecorder()

	handler.HandleScans(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for SSRF target, got %d", rr.Code)
	}

	var errResp ErrorResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &errResp)
	if errResp.Error.Code != "SSRF_VIOLATION" {
		t.Errorf("expected error code SSRF_VIOLATION, got %s", errResp.Error.Code)
	}
}

func TestScanHandler_EndToEndMockScan(t *testing.T) {
	// Create mock HTTP server simulating a target with security misconfigurations
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Deliberately disclose Server version and omit HSTS and CSP
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.Header().Set("Set-Cookie", "session_id=xyz123; Path=/") // Missing Secure and HttpOnly!
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>Test App</title></head><body><h1>Hello World</h1></body></html>"))
	}))
	defer mockServer.Close()

	repo := storage.NewMemoryRepository()
	scannerEngine := scanner.NewEngine()
	handler := NewScanHandler(scannerEngine, repo)

	// Scan mock server with allow_private: true (since mock runs on 127.0.0.1)
	reqBody := map[string]interface{}{
		"target":        mockServer.URL,
		"authorized":    true,
		"allow_private": true,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", bytes.NewReader(bodyBytes))
	rr := httptest.NewRecorder()

	handler.HandleScans(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rr.Code, rr.Body.String())
	}

	var scan domain.Scan
	if err := json.Unmarshal(rr.Body.Bytes(), &scan); err != nil {
		t.Fatalf("failed to decode scan response: %v", err)
	}

	if scan.ID == "" {
		t.Errorf("expected non-empty scan ID")
	}

	if scan.ScoreCard == nil {
		t.Fatalf("expected score card, got nil")
	}

	t.Logf("Scan completed with Score: %d (Grade %s), %d Findings",
		scan.ScoreCard.OverallScore, scan.ScoreCard.LetterGrade, len(scan.Findings))

	// Verify specific findings were detected
	foundServerBanner := false
	foundMissingHSTS := false
	foundInsecureCookie := false

	for _, f := range scan.Findings {
		// Validate that evidence is populated
		if f.Evidence.Type == "" {
			t.Errorf("finding %q is missing evidence type", f.Title)
		}
		if f.Verification.Command == "" {
			t.Errorf("finding %q is missing CLI verification command", f.Title)
		}

		if f.RuleID == "SERVER_BANNER_DISCLOSURE" {
			foundServerBanner = true
		}
		if f.RuleID == "HSTS_MISSING" {
			foundMissingHSTS = true
		}
		if f.RuleID == "COOKIE_MISSING_HTTPONLY" {
			foundInsecureCookie = true
		}
	}

	if !foundServerBanner {
		t.Errorf("expected SERVER_BANNER_DISCLOSURE finding to be detected")
	}
	if !foundMissingHSTS {
		t.Errorf("expected HSTS_MISSING finding to be detected")
	}
	if !foundInsecureCookie {
		t.Errorf("expected COOKIE_MISSING_HTTPONLY finding to be detected")
	}

	// Test GET /api/v1/scans/{id}
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+scan.ID, nil)
	getRR := httptest.NewRecorder()
	handler.HandleScanByID(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from GET /api/v1/scans/%s, got %d", scan.ID, getRR.Code)
	}

	// Test GET /api/v1/targets/{domain}
	tgtReq := httptest.NewRequest(http.MethodGet, "/api/v1/targets/"+scan.TargetID, nil)
	tgtRR := httptest.NewRecorder()
	handler.HandleTargetByDomain(tgtRR, tgtReq)

	if tgtRR.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from GET /api/v1/targets/%s, got %d", scan.TargetID, tgtRR.Code)
	}
}
