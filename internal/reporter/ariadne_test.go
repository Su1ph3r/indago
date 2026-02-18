package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestExportAriadne(t *testing.T) {
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
				Endpoint:    "/api/search",
				Method:      "GET",
				Parameter:   "q",
				CWE:         "CWE-79",
				Timestamp:   time.Now(),
			},
			{
				ID:          "f2",
				Type:        "sqli",
				Severity:    types.SeverityCritical,
				Confidence:  types.ConfidenceMedium,
				Title:       "SQL Injection",
				Description: "SQL injection in search query",
				Endpoint:    "/api/search",
				Method:      "GET",
				Parameter:   "q",
				CWE:         "CWE-89",
				Timestamp:   time.Now(),
			},
			{
				ID:          "f3",
				Type:        "idor",
				Severity:    types.SeverityMedium,
				Confidence:  types.ConfidenceLow,
				Title:       "IDOR on user profile",
				Description: "Insecure direct object reference",
				Endpoint:    "/api/users/profile",
				Method:      "GET",
				Parameter:   "user_id",
				CWE:         "CWE-639",
				Timestamp:   time.Now(),
			},
		},
	}

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "ariadne.json")

	err := ExportAriadne(scanResult, outPath)
	if err != nil {
		t.Fatalf("ExportAriadne failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	var export types.AriadneExport
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

	// Findings should be grouped by endpoint (Method:Endpoint)
	// f1 and f2 share GET:/api/search, f3 is at GET:/api/users/profile
	if len(export.AttackPaths) != 2 {
		t.Fatalf("expected 2 attack paths (grouped by endpoint), got %d", len(export.AttackPaths))
	}

	// Find each path by endpoint
	pathMap := make(map[string]types.AriadneAttackPath)
	for _, ap := range export.AttackPaths {
		pathMap[ap.Method+":"+ap.Endpoint] = ap
	}

	searchPath, ok := pathMap["GET:/api/search"]
	if !ok {
		t.Fatal("expected attack path for GET:/api/search")
	}
	if len(searchPath.Findings) != 2 {
		t.Errorf("expected 2 findings in /api/search path, got %d", len(searchPath.Findings))
	}

	profilePath, ok := pathMap["GET:/api/users/profile"]
	if !ok {
		t.Fatal("expected attack path for GET:/api/users/profile")
	}
	if len(profilePath.Findings) != 1 {
		t.Errorf("expected 1 finding in /api/users/profile path, got %d", len(profilePath.Findings))
	}

	// Attack paths should be sorted by severity (highest first)
	// critical < high < medium in rank, so critical comes first
	if len(export.AttackPaths) >= 2 {
		first := export.AttackPaths[0]
		second := export.AttackPaths[1]
		if severityRank(first.Severity) > severityRank(second.Severity) {
			t.Errorf("attack paths not sorted by severity: first=%q, second=%q", first.Severity, second.Severity)
		}
	}
}

func TestExportAriadne_EmptyFindings(t *testing.T) {
	scanResult := &types.ScanResult{
		ScanID:   "test-scan-empty",
		Target:   "https://example.com",
		Findings: []types.Finding{},
	}

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "ariadne-empty.json")

	err := ExportAriadne(scanResult, outPath)
	if err != nil {
		t.Fatalf("ExportAriadne failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	var export types.AriadneExport
	if err := json.Unmarshal(data, &export); err != nil {
		t.Fatalf("failed to parse output JSON: %v", err)
	}

	if export.ToolSource != "indago" {
		t.Errorf("ToolSource = %q, want %q", export.ToolSource, "indago")
	}

	if len(export.AttackPaths) != 0 {
		t.Errorf("expected 0 attack paths, got %d", len(export.AttackPaths))
	}

	// Validate the output is valid JSON
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}
