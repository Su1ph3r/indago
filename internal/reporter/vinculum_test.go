package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestExportVinculum(t *testing.T) {
	scanResult := &types.ScanResult{
		ScanID: "test-scan-001",
		Target: "https://example.com",
		Findings: []types.Finding{
			{
				ID:          "f1",
				Type:        "xss",
				Severity:    types.SeverityHigh,
				Confidence:  types.ConfidenceHigh,
				Title:       "Reflected XSS",
				Description: "XSS in query parameter",
				Endpoint:    "https://example.com/api/search",
				Method:      "GET",
				Parameter:   "q",
				CWE:         "CWE-79",
				Evidence: &types.Evidence{
					Request: &types.HTTPRequest{
						Method:  "GET",
						URL:     "https://example.com/api/search?q=<script>",
						Headers: map[string]string{"Host": "example.com"},
					},
					Response: &types.HTTPResponse{
						StatusCode: 200,
						Status:     "200 OK",
						Headers:    map[string]string{"Content-Type": "text/html"},
						Body:       "<html><script>alert(1)</script></html>",
					},
				},
				Timestamp: time.Now(),
			},
			{
				ID:          "f2",
				Type:        "sqli",
				Severity:    types.SeverityCritical,
				Confidence:  types.ConfidenceMedium,
				Title:       "SQL Injection",
				Description: "SQL injection in id parameter",
				Endpoint:    "https://example.com/api/users",
				Method:      "POST",
				Parameter:   "id",
				CWE:         "CWE-89",
				Timestamp:   time.Now(),
			},
		},
	}

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "vinculum.json")

	err := ExportVinculum(scanResult, outPath)
	if err != nil {
		t.Fatalf("ExportVinculum failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	var export types.VinculumExport
	if err := json.Unmarshal(data, &export); err != nil {
		t.Fatalf("failed to parse output JSON: %v", err)
	}

	if export.ToolSource != "indago" {
		t.Errorf("ToolSource = %q, want %q", export.ToolSource, "indago")
	}

	if export.ScanID != "test-scan-001" {
		t.Errorf("ScanID = %q, want %q", export.ScanID, "test-scan-001")
	}

	if export.Target != "https://example.com" {
		t.Errorf("Target = %q, want %q", export.Target, "https://example.com")
	}

	if export.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}

	if len(export.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(export.Findings))
	}

	// Verify first finding
	vf0 := export.Findings[0]
	if vf0.ID != "f1" {
		t.Errorf("Findings[0].ID = %q, want %q", vf0.ID, "f1")
	}
	if vf0.Type != "xss" {
		t.Errorf("Findings[0].Type = %q, want %q", vf0.Type, "xss")
	}
	if vf0.Severity != types.SeverityHigh {
		t.Errorf("Findings[0].Severity = %q, want %q", vf0.Severity, types.SeverityHigh)
	}
	if vf0.CWE != "CWE-79" {
		t.Errorf("Findings[0].CWE = %q, want %q", vf0.CWE, "CWE-79")
	}
	if vf0.RawRequest == "" {
		t.Error("Findings[0].RawRequest should not be empty when evidence has request")
	}
	if vf0.RawResponse == "" {
		t.Error("Findings[0].RawResponse should not be empty when evidence has response")
	}

	// Verify second finding (no evidence)
	vf1 := export.Findings[1]
	if vf1.ID != "f2" {
		t.Errorf("Findings[1].ID = %q, want %q", vf1.ID, "f2")
	}
	if vf1.RawRequest != "" {
		t.Error("Findings[1].RawRequest should be empty when no evidence")
	}
	if vf1.RawResponse != "" {
		t.Error("Findings[1].RawResponse should be empty when no evidence")
	}
}

func TestExportVinculum_EmptyFindings(t *testing.T) {
	scanResult := &types.ScanResult{
		ScanID:   "test-scan-empty",
		Target:   "https://example.com",
		Findings: []types.Finding{},
	}

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "vinculum-empty.json")

	err := ExportVinculum(scanResult, outPath)
	if err != nil {
		t.Fatalf("ExportVinculum failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	var export types.VinculumExport
	if err := json.Unmarshal(data, &export); err != nil {
		t.Fatalf("failed to parse output JSON: %v", err)
	}

	if export.ToolSource != "indago" {
		t.Errorf("ToolSource = %q, want %q", export.ToolSource, "indago")
	}

	// Findings should be nil/empty since no findings were provided
	if len(export.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(export.Findings))
	}

	// Validate the output is valid JSON by checking the raw data parses
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}
