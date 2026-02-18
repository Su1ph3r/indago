package importer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestLoadBurritoBypasses_Valid(t *testing.T) {
	data := types.BurritoBypassImport{
		ExportSource: "bypass-burrito",
		ScanID:       "scan-001",
		Target:       "https://example.com",
		Bypasses: []types.BurritoBypass{
			{
				Endpoint:          "/api/users",
				Method:            "GET",
				Parameter:         "q",
				BypassPayload:     "<scr%69pt>alert(1)</script>",
				BypassTechnique:   "encoding",
				VulnerabilityType: "xss",
				StatusCode:        200,
			},
			{
				Endpoint:          "/api/search",
				Method:            "POST",
				Parameter:         "id",
				BypassPayload:     "1%27%20OR%201%3D1--",
				BypassTechnique:   "url_encoding",
				VulnerabilityType: "sqli",
				StatusCode:        200,
			},
		},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "burrito.json")
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("failed to marshal test data: %v", err)
	}
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	imp, err := LoadBurritoBypasses(path)
	if err != nil {
		t.Fatalf("LoadBurritoBypasses failed: %v", err)
	}

	if imp.ExportSource != "bypass-burrito" {
		t.Errorf("ExportSource = %q, want %q", imp.ExportSource, "bypass-burrito")
	}

	if imp.ScanID != "scan-001" {
		t.Errorf("ScanID = %q, want %q", imp.ScanID, "scan-001")
	}

	if len(imp.Bypasses) != 2 {
		t.Errorf("expected 2 bypasses, got %d", len(imp.Bypasses))
	}

	if imp.Bypasses[0].BypassPayload != "<scr%69pt>alert(1)</script>" {
		t.Errorf("unexpected bypass payload: %s", imp.Bypasses[0].BypassPayload)
	}
}

func TestLoadBurritoBypasses_InvalidFile(t *testing.T) {
	_, err := LoadBurritoBypasses("/nonexistent/path/burrito.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestLoadBurritoBypasses_InvalidSource(t *testing.T) {
	data := types.BurritoBypassImport{
		ExportSource: "wrong-tool",
		Bypasses: []types.BurritoBypass{
			{
				Endpoint:          "/api/test",
				Method:            "GET",
				BypassPayload:     "test",
				VulnerabilityType: "xss",
			},
		},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "wrong-source.json")
	b, _ := json.Marshal(data)
	os.WriteFile(path, b, 0644)

	_, err := LoadBurritoBypasses(path)
	if err == nil {
		t.Fatal("expected error for wrong export_source, got nil")
	}
}

func TestBypassesToFuzzRequests(t *testing.T) {
	imp := &types.BurritoBypassImport{
		ExportSource: "bypass-burrito",
		Bypasses: []types.BurritoBypass{
			{
				Endpoint:          "/api/users",
				Method:            "GET",
				Parameter:         "q",
				BypassPayload:     "<img src=x>",
				BypassTechnique:   "tag_mangling",
				VulnerabilityType: "xss",
			},
			{
				Endpoint:          "/api/data",
				Method:            "POST",
				Parameter:         "id",
				BypassPayload:     "1 OR 1=1",
				BypassTechnique:   "space_bypass",
				VulnerabilityType: "sqli",
			},
		},
	}

	endpoints := []types.Endpoint{
		{
			Method: "GET",
			Path:   "/api/users",
			Parameters: []types.Parameter{
				{Name: "q", In: "query", Type: "string"},
				{Name: "page", In: "query", Type: "string"},
			},
		},
		{
			Method: "POST",
			Path:   "/api/data",
			Parameters: []types.Parameter{
				{Name: "id", In: "body", Type: "string"},
			},
		},
	}

	requests := BypassesToFuzzRequests(imp, endpoints)

	if len(requests) != 2 {
		t.Fatalf("expected 2 fuzz requests, got %d", len(requests))
	}

	// First request should match the GET /api/users endpoint
	r0 := requests[0]
	if r0.Payload.Value != "<img src=x>" {
		t.Errorf("request[0].Payload.Value = %q, want %q", r0.Payload.Value, "<img src=x>")
	}
	if r0.Payload.Category != "waf_bypass" {
		t.Errorf("request[0].Payload.Category = %q, want %q", r0.Payload.Category, "waf_bypass")
	}
	if r0.Payload.Metadata["source"] != "bypass-burrito" {
		t.Errorf("request[0].Payload.Metadata[\"source\"] = %q, want %q", r0.Payload.Metadata["source"], "bypass-burrito")
	}
	if r0.Payload.Metadata["bypass_technique"] != "tag_mangling" {
		t.Errorf("request[0].Payload.Metadata[\"bypass_technique\"] = %q, want %q", r0.Payload.Metadata["bypass_technique"], "tag_mangling")
	}
	if r0.Param == nil {
		t.Fatal("request[0].Param is nil, expected matched parameter")
	}
	if r0.Param.Name != "q" {
		t.Errorf("request[0].Param.Name = %q, want %q", r0.Param.Name, "q")
	}
	if r0.Position != "query" {
		t.Errorf("request[0].Position = %q, want %q", r0.Position, "query")
	}

	// Second request should match the POST /api/data endpoint
	r1 := requests[1]
	if r1.Payload.Value != "1 OR 1=1" {
		t.Errorf("request[1].Payload.Value = %q, want %q", r1.Payload.Value, "1 OR 1=1")
	}
	if r1.Param == nil {
		t.Fatal("request[1].Param is nil, expected matched parameter")
	}
	if r1.Param.Name != "id" {
		t.Errorf("request[1].Param.Name = %q, want %q", r1.Param.Name, "id")
	}
}
