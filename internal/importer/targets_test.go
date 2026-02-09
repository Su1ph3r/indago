package importer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestLoadTargetsReticustos(t *testing.T) {
	data := types.TargetImport{
		ExportSource:  "reticustos",
		TargetBaseURL: "https://example.com",
		Endpoints: []types.ImportedEndpoint{
			{Path: "/api/users", Method: "GET", Params: []string{"id", "page"}, Port: 443, Protocol: "https"},
			{Path: "/api/login", Method: "POST", Params: []string{}, Port: 443, Protocol: "https"},
		},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "targets.json")
	b, _ := json.Marshal(data)
	os.WriteFile(path, b, 0644)

	imp, err := LoadTargets(path)
	if err != nil {
		t.Fatalf("LoadTargets failed: %v", err)
	}

	if imp.ExportSource != "reticustos" {
		t.Errorf("expected export_source 'reticustos', got '%s'", imp.ExportSource)
	}

	if len(imp.Endpoints) != 2 {
		t.Errorf("expected 2 endpoints, got %d", len(imp.Endpoints))
	}
}

func TestLoadTargetsAriadne(t *testing.T) {
	data := types.TargetImport{
		Format:        "indago-targets",
		ExportSource:  "ariadne",
		TargetBaseURL: "https://example.com",
		Endpoints: []types.ImportedEndpoint{
			{Path: "/api/users", Method: "GET", Params: []string{"id"}},
		},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "ariadne-targets.json")
	b, _ := json.Marshal(data)
	os.WriteFile(path, b, 0644)

	imp, err := LoadTargets(path)
	if err != nil {
		t.Fatalf("LoadTargets failed: %v", err)
	}

	if imp.ExportSource != "ariadne" {
		t.Errorf("expected export_source 'ariadne', got '%s'", imp.ExportSource)
	}
}

func TestLoadTargetsAutoDetect(t *testing.T) {
	// Test auto-detection when export_source is empty but format is set
	raw := map[string]interface{}{
		"format":         "indago-targets",
		"target_base_url": "https://example.com",
		"endpoints": []map[string]interface{}{
			{"path": "/api/test", "method": "GET"},
		},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "auto-detect.json")
	b, _ := json.Marshal(raw)
	os.WriteFile(path, b, 0644)

	imp, err := LoadTargets(path)
	if err != nil {
		t.Fatalf("LoadTargets failed: %v", err)
	}

	if imp.ExportSource != "ariadne" {
		t.Errorf("expected auto-detected export_source 'ariadne', got '%s'", imp.ExportSource)
	}
}

func TestLoadTargetsFileNotFound(t *testing.T) {
	_, err := LoadTargets("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadTargetsInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "invalid.json")
	os.WriteFile(path, []byte("not json"), 0644)

	_, err := LoadTargets(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestToEndpoints(t *testing.T) {
	imp := &types.TargetImport{
		ExportSource:  "reticustos",
		TargetBaseURL: "https://example.com",
		Endpoints: []types.ImportedEndpoint{
			{Path: "/api/users", Method: "GET", Params: []string{"id", "page"}},
			{Path: "/api/login", Method: "POST"},
		},
	}

	endpoints := ToEndpoints(imp)

	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(endpoints))
	}

	if endpoints[0].BaseURL != "https://example.com" {
		t.Errorf("expected base URL 'https://example.com', got '%s'", endpoints[0].BaseURL)
	}

	if endpoints[0].Method != "GET" {
		t.Errorf("expected method GET, got %s", endpoints[0].Method)
	}

	if len(endpoints[0].Parameters) != 2 {
		t.Errorf("expected 2 parameters, got %d", len(endpoints[0].Parameters))
	}

	if endpoints[0].Parameters[0].Name != "id" {
		t.Errorf("expected parameter name 'id', got '%s'", endpoints[0].Parameters[0].Name)
	}

	if endpoints[1].Method != "POST" {
		t.Errorf("expected method POST, got %s", endpoints[1].Method)
	}
}

func TestToEndpointsFallbackBaseURL(t *testing.T) {
	imp := &types.TargetImport{
		Endpoints: []types.ImportedEndpoint{
			{Path: "/test", Method: "GET", Port: 8080, Protocol: "http"},
		},
	}

	endpoints := ToEndpoints(imp)
	if endpoints[0].BaseURL != "http://target:8080" {
		t.Errorf("expected fallback URL 'http://target:8080', got '%s'", endpoints[0].BaseURL)
	}
}

func TestToEndpointsDefaultProtocol(t *testing.T) {
	imp := &types.TargetImport{
		Endpoints: []types.ImportedEndpoint{
			{Path: "/test", Method: "GET"},
		},
	}

	endpoints := ToEndpoints(imp)
	if endpoints[0].BaseURL != "https://target:443" {
		t.Errorf("expected default URL 'https://target:443', got '%s'", endpoints[0].BaseURL)
	}
}

func TestToEndpointsDefaultMethod(t *testing.T) {
	imp := &types.TargetImport{
		TargetBaseURL: "https://example.com",
		Endpoints: []types.ImportedEndpoint{
			{Path: "/test"},
		},
	}

	endpoints := ToEndpoints(imp)
	if endpoints[0].Method != "GET" {
		t.Errorf("expected default method 'GET', got '%s'", endpoints[0].Method)
	}
}

func TestToEndpointsPerEndpointBaseURL(t *testing.T) {
	imp := &types.TargetImport{
		TargetBaseURL: "https://example.com",
		Endpoints: []types.ImportedEndpoint{
			{Path: "/test", Method: "GET", BaseURL: "https://other.com"},
		},
	}

	endpoints := ToEndpoints(imp)
	if endpoints[0].BaseURL != "https://other.com" {
		t.Errorf("expected per-endpoint base URL 'https://other.com', got '%s'", endpoints[0].BaseURL)
	}
}

func TestToEndpointsEmpty(t *testing.T) {
	imp := &types.TargetImport{
		Endpoints: []types.ImportedEndpoint{},
	}

	endpoints := ToEndpoints(imp)
	if len(endpoints) != 0 {
		t.Errorf("expected 0 endpoints, got %d", len(endpoints))
	}
}
