package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestExportWAFBlocked(t *testing.T) {
	scanResult := &types.ScanResult{
		ScanID: "test-scan-001",
		Target: "https://example.com",
		Findings: []types.Finding{
			{
				ID:        "f1",
				Type:      "xss",
				Endpoint:  "https://example.com/api/users",
				Method:    "GET",
				Parameter: "q",
				Payload:   "<script>alert(1)</script>",
				Evidence: &types.Evidence{
					Response: &types.HTTPResponse{
						StatusCode: 403,
						Status:     "Forbidden",
						Headers:    map[string]string{},
					},
				},
				Timestamp: time.Now(),
			},
			{
				ID:        "f2",
				Type:      "sqli",
				Endpoint:  "https://example.com/api/search",
				Method:    "POST",
				Parameter: "id",
				Payload:   "' OR 1=1--",
				Evidence: &types.Evidence{
					Response: &types.HTTPResponse{
						StatusCode: 200,
						Status:     "OK",
						Headers:    map[string]string{},
					},
				},
				Timestamp: time.Now(),
			},
		},
	}

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "waf-blocked.json")

	err := ExportWAFBlocked(scanResult, outPath)
	if err != nil {
		t.Fatalf("ExportWAFBlocked failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("Failed to read output: %v", err)
	}

	var export types.WAFBlockedExport
	if err := json.Unmarshal(data, &export); err != nil {
		t.Fatalf("Failed to parse output: %v", err)
	}

	if export.ExportSource != "indago" {
		t.Errorf("expected export_source 'indago', got '%s'", export.ExportSource)
	}

	if export.ScanID != "test-scan-001" {
		t.Errorf("expected scan_id 'test-scan-001', got '%s'", export.ScanID)
	}

	if export.TotalBlocked != 1 {
		t.Errorf("expected 1 blocked, got %d", export.TotalBlocked)
	}

	if len(export.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(export.Targets))
	}

	if export.Targets[0].WAFResponseCode != 403 {
		t.Errorf("expected WAF code 403, got %d", export.Targets[0].WAFResponseCode)
	}

	if export.Targets[0].OriginalFindingID != "f1" {
		t.Errorf("expected finding ID 'f1', got '%s'", export.Targets[0].OriginalFindingID)
	}

	if export.Targets[0].VulnerabilityType != "xss" {
		t.Errorf("expected vulnerability type 'xss', got '%s'", export.Targets[0].VulnerabilityType)
	}
}

func TestExportWAFBlockedEmpty(t *testing.T) {
	scanResult := &types.ScanResult{
		ScanID:   "test-scan-002",
		Target:   "https://example.com",
		Findings: []types.Finding{},
	}

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "waf-blocked-empty.json")

	err := ExportWAFBlocked(scanResult, outPath)
	if err != nil {
		t.Fatalf("ExportWAFBlocked failed: %v", err)
	}

	data, _ := os.ReadFile(outPath)
	var export types.WAFBlockedExport
	json.Unmarshal(data, &export)

	if export.TotalBlocked != 0 {
		t.Errorf("expected 0 blocked, got %d", export.TotalBlocked)
	}
}

func TestExportWAFBlockedByHeader(t *testing.T) {
	scanResult := &types.ScanResult{
		ScanID: "test-scan-003",
		Target: "https://example.com",
		Findings: []types.Finding{
			{
				ID:       "f1",
				Type:     "xss",
				Endpoint: "https://example.com/api/test",
				Method:   "GET",
				Evidence: &types.Evidence{
					Response: &types.HTTPResponse{
						StatusCode: 200,
						Status:     "OK",
						Headers:    map[string]string{"X-WAF-Status": "blocked"},
					},
				},
				Timestamp: time.Now(),
			},
		},
	}

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "waf-blocked-header.json")

	err := ExportWAFBlocked(scanResult, outPath)
	if err != nil {
		t.Fatalf("ExportWAFBlocked failed: %v", err)
	}

	data, _ := os.ReadFile(outPath)
	var export types.WAFBlockedExport
	json.Unmarshal(data, &export)

	if export.TotalBlocked != 1 {
		t.Errorf("expected 1 blocked (by header), got %d", export.TotalBlocked)
	}
}

func TestExportWAFBlockedCloudflare(t *testing.T) {
	scanResult := &types.ScanResult{
		ScanID: "test-scan-004",
		Target: "https://example.com",
		Findings: []types.Finding{
			{
				ID:       "f1",
				Type:     "sqli",
				Endpoint: "https://example.com/api/data",
				Method:   "POST",
				Evidence: &types.Evidence{
					Response: &types.HTTPResponse{
						StatusCode: 200,
						Status:     "OK",
						Headers:    map[string]string{"CF-Cloudflare-Status": "challenged"},
					},
				},
				Timestamp: time.Now(),
			},
		},
	}

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "waf-blocked-cf.json")

	err := ExportWAFBlocked(scanResult, outPath)
	if err != nil {
		t.Fatalf("ExportWAFBlocked failed: %v", err)
	}

	data, _ := os.ReadFile(outPath)
	var export types.WAFBlockedExport
	json.Unmarshal(data, &export)

	if export.TotalBlocked != 1 {
		t.Errorf("expected 1 blocked (cloudflare header), got %d", export.TotalBlocked)
	}
}

func TestExportWAFBlockedNoEvidence(t *testing.T) {
	scanResult := &types.ScanResult{
		ScanID: "test-scan-005",
		Target: "https://example.com",
		Findings: []types.Finding{
			{
				ID:       "f1",
				Type:     "xss",
				Endpoint: "https://example.com/api/test",
				Method:   "GET",
				// No evidence
			},
		},
	}

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "waf-blocked-no-evidence.json")

	err := ExportWAFBlocked(scanResult, outPath)
	if err != nil {
		t.Fatalf("ExportWAFBlocked failed: %v", err)
	}

	data, _ := os.ReadFile(outPath)
	var export types.WAFBlockedExport
	json.Unmarshal(data, &export)

	if export.TotalBlocked != 0 {
		t.Errorf("expected 0 blocked (no evidence), got %d", export.TotalBlocked)
	}
}

func TestExportWAFBlockedAllCodes(t *testing.T) {
	// Test all WAF status codes: 403, 406, 429, 418
	scanResult := &types.ScanResult{
		ScanID: "test-scan-006",
		Target: "https://example.com",
		Findings: []types.Finding{
			{
				ID: "f1", Type: "xss", Endpoint: "/test1", Method: "GET",
				Evidence: &types.Evidence{Response: &types.HTTPResponse{StatusCode: 403, Headers: map[string]string{}}},
			},
			{
				ID: "f2", Type: "xss", Endpoint: "/test2", Method: "GET",
				Evidence: &types.Evidence{Response: &types.HTTPResponse{StatusCode: 406, Headers: map[string]string{}}},
			},
			{
				ID: "f3", Type: "xss", Endpoint: "/test3", Method: "GET",
				Evidence: &types.Evidence{Response: &types.HTTPResponse{StatusCode: 429, Headers: map[string]string{}}},
			},
			{
				ID: "f4", Type: "xss", Endpoint: "/test4", Method: "GET",
				Evidence: &types.Evidence{Response: &types.HTTPResponse{StatusCode: 418, Headers: map[string]string{}}},
			},
			{
				ID: "f5", Type: "xss", Endpoint: "/test5", Method: "GET",
				Evidence: &types.Evidence{Response: &types.HTTPResponse{StatusCode: 200, Headers: map[string]string{}}},
			},
		},
	}

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "waf-blocked-all-codes.json")

	err := ExportWAFBlocked(scanResult, outPath)
	if err != nil {
		t.Fatalf("ExportWAFBlocked failed: %v", err)
	}

	data, _ := os.ReadFile(outPath)
	var export types.WAFBlockedExport
	json.Unmarshal(data, &export)

	if export.TotalBlocked != 4 {
		t.Errorf("expected 4 blocked (all WAF codes), got %d", export.TotalBlocked)
	}
}
