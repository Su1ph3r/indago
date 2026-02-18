package checkpoint

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

func TestNewManager(t *testing.T) {
	tests := []struct {
		name     string
		config   *ManagerConfig
		wantPath string
		wantAuto bool
	}{
		{
			name:     "nil config uses defaults",
			config:   nil,
			wantPath: ".indago-checkpoint.json",
			wantAuto: true,
		},
		{
			name: "custom config",
			config: &ManagerConfig{
				FilePath: "/tmp/custom.json",
				Interval: 10 * time.Second,
				AutoSave: false,
			},
			wantPath: "/tmp/custom.json",
			wantAuto: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewManager(tt.config)
			if m == nil {
				t.Fatal("NewManager returned nil")
			}
			if m.filePath != tt.wantPath {
				t.Errorf("filePath = %q, want %q", m.filePath, tt.wantPath)
			}
			if m.autoSave != tt.wantAuto {
				t.Errorf("autoSave = %v, want %v", m.autoSave, tt.wantAuto)
			}
			if m.state == nil {
				t.Fatal("state should not be nil")
			}
			if m.state.Version != "1.0" {
				t.Errorf("state.Version = %q, want %q", m.state.Version, "1.0")
			}
			if m.state.CompletedReqs == nil {
				t.Error("state.CompletedReqs should be initialized")
			}
			if m.state.Findings == nil {
				t.Error("state.Findings should be initialized")
			}
		})
	}
}

func TestInitialize(t *testing.T) {
	m := NewManager(&ManagerConfig{FilePath: "test.json"})
	cfg := &types.ScanConfig{
		Provider:    "openai",
		InputFile:   "api.yaml",
		InputType:   "openapi",
		Concurrency: 5,
	}

	m.Initialize("scan-123", "api.yaml", "openapi", "https://example.com", cfg)

	state := m.GetState()
	if state.ScanID != "scan-123" {
		t.Errorf("ScanID = %q, want %q", state.ScanID, "scan-123")
	}
	if state.InputFile != "api.yaml" {
		t.Errorf("InputFile = %q, want %q", state.InputFile, "api.yaml")
	}
	if state.InputType != "openapi" {
		t.Errorf("InputType = %q, want %q", state.InputType, "openapi")
	}
	if state.Target != "https://example.com" {
		t.Errorf("Target = %q, want %q", state.Target, "https://example.com")
	}
	if state.Config == nil {
		t.Fatal("Config should not be nil")
	}
	if state.Config.Provider != "openai" {
		t.Errorf("Config.Provider = %q, want %q", state.Config.Provider, "openai")
	}
	if state.Version != "1.0" {
		t.Errorf("Version = %q, want %q", state.Version, "1.0")
	}
	if state.StartTime.IsZero() {
		t.Error("StartTime should be set")
	}
	if state.LastUpdate.IsZero() {
		t.Error("LastUpdate should be set")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	cpFile := filepath.Join(tmpDir, "checkpoint.json")

	cfg := &types.ScanConfig{
		Provider:    "anthropic",
		Model:       "claude-3",
		InputFile:   "spec.yaml",
		InputType:   "openapi",
		Concurrency: 10,
		RateLimit:   50.0,
	}

	// Create and populate a manager
	m := NewManager(&ManagerConfig{FilePath: cpFile})
	m.Initialize("scan-abc", "spec.yaml", "openapi", "https://api.test.com", cfg)
	m.SetProgress(10, 5, 100, 50)
	m.RecordCompletion("fp-1")
	m.RecordCompletion("fp-2")
	m.AddFinding(types.Finding{
		ID:       "f-1",
		Type:     "sqli",
		Severity: types.SeverityHigh,
		Title:    "SQL Injection",
		Endpoint: "/users",
		Method:   "GET",
	})
	m.AddError(types.ScanError{
		Endpoint: "/admin",
		Error:    "connection refused",
	})

	// Save
	if err := m.Save(); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Load into a new manager
	m2 := NewManager(&ManagerConfig{FilePath: cpFile})
	if err := m2.Load(cpFile); err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	state := m2.GetState()

	if state.ScanID != "scan-abc" {
		t.Errorf("ScanID = %q, want %q", state.ScanID, "scan-abc")
	}
	if state.Target != "https://api.test.com" {
		t.Errorf("Target = %q, want %q", state.Target, "https://api.test.com")
	}
	if state.InputFile != "spec.yaml" {
		t.Errorf("InputFile = %q, want %q", state.InputFile, "spec.yaml")
	}
	if state.Config == nil {
		t.Fatal("Config should not be nil after load")
	}
	if state.Config.Provider != "anthropic" {
		t.Errorf("Config.Provider = %q, want %q", state.Config.Provider, "anthropic")
	}
	if state.Config.Model != "claude-3" {
		t.Errorf("Config.Model = %q, want %q", state.Config.Model, "claude-3")
	}
	if len(state.CompletedReqs) != 2 {
		t.Errorf("CompletedReqs length = %d, want 2", len(state.CompletedReqs))
	}
	if len(state.Findings) != 1 {
		t.Errorf("Findings length = %d, want 1", len(state.Findings))
	}
	if state.Findings[0].ID != "f-1" {
		t.Errorf("Findings[0].ID = %q, want %q", state.Findings[0].ID, "f-1")
	}
	if len(state.Errors) != 1 {
		t.Errorf("Errors length = %d, want 1", len(state.Errors))
	}
	if state.Errors[0].Endpoint != "/admin" {
		t.Errorf("Errors[0].Endpoint = %q, want %q", state.Errors[0].Endpoint, "/admin")
	}
}

func TestSetProgress(t *testing.T) {
	m := NewManager(&ManagerConfig{FilePath: "test.json"})

	tests := []struct {
		name              string
		total, completed  int
		totalReqs, compReqs int
		wantPercent       float64
	}{
		{
			name:        "half complete",
			total:       10,
			completed:   5,
			totalReqs:   100,
			compReqs:    50,
			wantPercent: 50.0,
		},
		{
			name:        "zero total requests",
			total:       10,
			completed:   0,
			totalReqs:   0,
			compReqs:    0,
			wantPercent: 0.0,
		},
		{
			name:        "all complete",
			total:       10,
			completed:   10,
			totalReqs:   100,
			compReqs:    100,
			wantPercent: 100.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.SetProgress(tt.total, tt.completed, tt.totalReqs, tt.compReqs)
			state := m.GetState()

			if state.Progress.TotalEndpoints != tt.total {
				t.Errorf("TotalEndpoints = %d, want %d", state.Progress.TotalEndpoints, tt.total)
			}
			if state.Progress.ScannedEndpoints != tt.completed {
				t.Errorf("ScannedEndpoints = %d, want %d", state.Progress.ScannedEndpoints, tt.completed)
			}
			if state.Progress.TotalRequests != tt.totalReqs {
				t.Errorf("TotalRequests = %d, want %d", state.Progress.TotalRequests, tt.totalReqs)
			}
			if state.Progress.CompletedRequests != tt.compReqs {
				t.Errorf("CompletedRequests = %d, want %d", state.Progress.CompletedRequests, tt.compReqs)
			}
			if state.Progress.PercentComplete != tt.wantPercent {
				t.Errorf("PercentComplete = %f, want %f", state.Progress.PercentComplete, tt.wantPercent)
			}
		})
	}
}

func TestRecordCompletion(t *testing.T) {
	m := NewManager(&ManagerConfig{FilePath: "test.json"})

	m.RecordCompletion("fp-1")
	m.RecordCompletion("fp-2")
	m.RecordCompletion("fp-3")

	state := m.GetState()
	if len(state.CompletedReqs) != 3 {
		t.Errorf("CompletedReqs length = %d, want 3", len(state.CompletedReqs))
	}
	if state.Progress.CompletedRequests != 3 {
		t.Errorf("CompletedRequests = %d, want 3", state.Progress.CompletedRequests)
	}

	// Verify fingerprints are in order
	want := []string{"fp-1", "fp-2", "fp-3"}
	for i, fp := range state.CompletedReqs {
		if fp != want[i] {
			t.Errorf("CompletedReqs[%d] = %q, want %q", i, fp, want[i])
		}
	}
}

func TestIsCompleted(t *testing.T) {
	m := NewManager(&ManagerConfig{FilePath: "test.json"})
	m.RecordCompletion("fp-done")

	tests := []struct {
		name        string
		fingerprint string
		want        bool
	}{
		{
			name:        "completed fingerprint",
			fingerprint: "fp-done",
			want:        true,
		},
		{
			name:        "unknown fingerprint",
			fingerprint: "fp-unknown",
			want:        false,
		},
		{
			name:        "empty fingerprint",
			fingerprint: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.IsCompleted(tt.fingerprint)
			if got != tt.want {
				t.Errorf("IsCompleted(%q) = %v, want %v", tt.fingerprint, got, tt.want)
			}
		})
	}
}

func TestAddFinding(t *testing.T) {
	m := NewManager(&ManagerConfig{FilePath: "test.json"})

	f1 := types.Finding{
		ID:       "f-1",
		Type:     "sqli",
		Severity: types.SeverityHigh,
		Title:    "SQL Injection in /users",
		Endpoint: "/users",
		Method:   "GET",
	}
	f2 := types.Finding{
		ID:       "f-2",
		Type:     "xss",
		Severity: types.SeverityMedium,
		Title:    "XSS in /search",
		Endpoint: "/search",
		Method:   "POST",
	}

	m.AddFinding(f1)
	m.AddFinding(f2)

	findings := m.GetFindings()
	if len(findings) != 2 {
		t.Fatalf("Findings length = %d, want 2", len(findings))
	}
	if findings[0].ID != "f-1" {
		t.Errorf("Findings[0].ID = %q, want %q", findings[0].ID, "f-1")
	}
	if findings[1].ID != "f-2" {
		t.Errorf("Findings[1].ID = %q, want %q", findings[1].ID, "f-2")
	}
}

func TestAddError(t *testing.T) {
	m := NewManager(&ManagerConfig{FilePath: "test.json"})

	e1 := types.ScanError{
		Endpoint:  "/api/v1/users",
		Error:     "connection timeout",
		Timestamp: time.Now(),
		Retried:   true,
	}
	e2 := types.ScanError{
		Endpoint: "/api/v1/admin",
		Error:    "403 forbidden",
	}

	m.AddError(e1)
	m.AddError(e2)

	state := m.GetState()
	if len(state.Errors) != 2 {
		t.Fatalf("Errors length = %d, want 2", len(state.Errors))
	}
	if state.Errors[0].Endpoint != "/api/v1/users" {
		t.Errorf("Errors[0].Endpoint = %q, want %q", state.Errors[0].Endpoint, "/api/v1/users")
	}
	if !state.Errors[0].Retried {
		t.Error("Errors[0].Retried should be true")
	}
	if state.Errors[1].Error != "403 forbidden" {
		t.Errorf("Errors[1].Error = %q, want %q", state.Errors[1].Error, "403 forbidden")
	}
}

func TestGetState(t *testing.T) {
	m := NewManager(&ManagerConfig{FilePath: "test.json"})
	m.Initialize("scan-1", "api.yaml", "openapi", "https://example.com", nil)

	state := m.GetState()
	if state.ScanID != "scan-1" {
		t.Errorf("ScanID = %q, want %q", state.ScanID, "scan-1")
	}

	// Verify it's a copy - modifying the returned state should not affect the manager
	state.ScanID = "modified"
	original := m.GetState()
	if original.ScanID != "scan-1" {
		t.Errorf("GetState did not return a copy; ScanID was modified to %q", original.ScanID)
	}
}

func TestGetFindings(t *testing.T) {
	m := NewManager(&ManagerConfig{FilePath: "test.json"})

	// Empty findings
	findings := m.GetFindings()
	if len(findings) != 0 {
		t.Errorf("initial Findings length = %d, want 0", len(findings))
	}

	// Add a finding and verify
	m.AddFinding(types.Finding{ID: "f-1", Title: "Test"})
	findings = m.GetFindings()
	if len(findings) != 1 {
		t.Fatalf("Findings length = %d, want 1", len(findings))
	}

	// Verify it's a copy
	findings[0].ID = "modified"
	original := m.GetFindings()
	if original[0].ID != "f-1" {
		t.Errorf("GetFindings did not return a copy; ID was modified to %q", original[0].ID)
	}
}

func TestFilterPendingRequests(t *testing.T) {
	m := NewManager(&ManagerConfig{FilePath: "test.json"})
	m.RecordCompletion("fp-1")
	m.RecordCompletion("fp-3")

	requests := []payloads.FuzzRequest{
		{
			Endpoint: types.Endpoint{Path: "/a"},
			Payload:  payloads.Payload{Value: "1"},
		},
		{
			Endpoint: types.Endpoint{Path: "/b"},
			Payload:  payloads.Payload{Value: "2"},
		},
		{
			Endpoint: types.Endpoint{Path: "/c"},
			Payload:  payloads.Payload{Value: "3"},
		},
		{
			Endpoint: types.Endpoint{Path: "/d"},
			Payload:  payloads.Payload{Value: "4"},
		},
	}

	// Fingerprinter: fp-1, fp-2, fp-3, fp-4
	fingerprinter := func(req payloads.FuzzRequest) string {
		return "fp-" + req.Payload.Value
	}

	pending := m.FilterPendingRequests(requests, fingerprinter)

	if len(pending) != 2 {
		t.Fatalf("pending length = %d, want 2", len(pending))
	}
	// fp-2 and fp-4 should remain
	if pending[0].Endpoint.Path != "/b" {
		t.Errorf("pending[0].Path = %q, want %q", pending[0].Endpoint.Path, "/b")
	}
	if pending[1].Endpoint.Path != "/d" {
		t.Errorf("pending[1].Path = %q, want %q", pending[1].Endpoint.Path, "/d")
	}
}

func TestFilterPendingRequests_NoneCompleted(t *testing.T) {
	m := NewManager(&ManagerConfig{FilePath: "test.json"})

	requests := []payloads.FuzzRequest{
		{Endpoint: types.Endpoint{Path: "/a"}},
		{Endpoint: types.Endpoint{Path: "/b"}},
	}

	fingerprinter := func(req payloads.FuzzRequest) string {
		return req.Endpoint.Path
	}

	pending := m.FilterPendingRequests(requests, fingerprinter)
	if len(pending) != 2 {
		t.Errorf("pending length = %d, want 2", len(pending))
	}
}

func TestFilterPendingRequests_AllCompleted(t *testing.T) {
	m := NewManager(&ManagerConfig{FilePath: "test.json"})
	m.RecordCompletion("/a")
	m.RecordCompletion("/b")

	requests := []payloads.FuzzRequest{
		{Endpoint: types.Endpoint{Path: "/a"}},
		{Endpoint: types.Endpoint{Path: "/b"}},
	}

	fingerprinter := func(req payloads.FuzzRequest) string {
		return req.Endpoint.Path
	}

	pending := m.FilterPendingRequests(requests, fingerprinter)
	if len(pending) != 0 {
		t.Errorf("pending length = %d, want 0", len(pending))
	}
}

func TestExists(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a temp file
	cpFile := filepath.Join(tmpDir, "exists.json")
	if err := os.WriteFile(cpFile, []byte("{}"), 0600); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "existing file",
			filePath: cpFile,
			want:     true,
		},
		{
			name:     "non-existent file",
			filePath: filepath.Join(tmpDir, "nonexistent.json"),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Exists(tt.filePath)
			if got != tt.want {
				t.Errorf("Exists(%q) = %v, want %v", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestLoadAndResume(t *testing.T) {
	tmpDir := t.TempDir()
	cpFile := filepath.Join(tmpDir, "resume.json")

	// Create a checkpoint first
	m := NewManager(&ManagerConfig{FilePath: cpFile})
	m.Initialize("scan-resume", "api.yaml", "openapi", "https://target.com", nil)
	m.RecordCompletion("fp-done")
	m.AddFinding(types.Finding{ID: "f-resume", Type: "xss"})
	if err := m.Save(); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Load and resume
	resumed, err := LoadAndResume(cpFile)
	if err != nil {
		t.Fatalf("LoadAndResume() error: %v", err)
	}

	state := resumed.GetState()
	if state.ScanID != "scan-resume" {
		t.Errorf("ScanID = %q, want %q", state.ScanID, "scan-resume")
	}
	if state.Target != "https://target.com" {
		t.Errorf("Target = %q, want %q", state.Target, "https://target.com")
	}
	if len(state.CompletedReqs) != 1 {
		t.Errorf("CompletedReqs length = %d, want 1", len(state.CompletedReqs))
	}
	if !resumed.IsCompleted("fp-done") {
		t.Error("fp-done should be completed after resume")
	}
	if len(state.Findings) != 1 {
		t.Errorf("Findings length = %d, want 1", len(state.Findings))
	}
}

func TestLoadAndResume_InvalidFile(t *testing.T) {
	_, err := LoadAndResume("/nonexistent/path/resume.json")
	if err == nil {
		t.Error("LoadAndResume with invalid path should return error")
	}
}

func TestGetResumeInfo(t *testing.T) {
	m := NewManager(&ManagerConfig{FilePath: "test.json"})
	m.Initialize("scan-info", "api.yaml", "openapi", "https://example.com", nil)
	m.SetProgress(10, 5, 100, 50)
	m.AddFinding(types.Finding{ID: "f-1"})
	m.AddFinding(types.Finding{ID: "f-2"})
	m.AddError(types.ScanError{Endpoint: "/err", Error: "timeout"})

	info := m.GetResumeInfo()

	if info.ScanID != "scan-info" {
		t.Errorf("ScanID = %q, want %q", info.ScanID, "scan-info")
	}
	if info.Target != "https://example.com" {
		t.Errorf("Target = %q, want %q", info.Target, "https://example.com")
	}
	if info.FindingsCount != 2 {
		t.Errorf("FindingsCount = %d, want 2", info.FindingsCount)
	}
	if info.ErrorsCount != 1 {
		t.Errorf("ErrorsCount = %d, want 1", info.ErrorsCount)
	}
	if info.Progress.TotalEndpoints != 10 {
		t.Errorf("Progress.TotalEndpoints = %d, want 10", info.Progress.TotalEndpoints)
	}
	if info.Progress.PercentComplete != 50.0 {
		t.Errorf("Progress.PercentComplete = %f, want 50.0", info.Progress.PercentComplete)
	}
	if info.StartTime.IsZero() {
		t.Error("StartTime should not be zero")
	}
	if info.LastUpdate.IsZero() {
		t.Error("LastUpdate should not be zero")
	}
}

func TestCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	cpFile := filepath.Join(tmpDir, "cleanup.json")

	m := NewManager(&ManagerConfig{FilePath: cpFile})
	m.Initialize("scan-cleanup", "api.yaml", "openapi", "https://example.com", nil)

	// Save so the file exists
	if err := m.Save(); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Verify file exists
	if !Exists(cpFile) {
		t.Fatal("checkpoint file should exist after Save")
	}

	// Cleanup
	if err := m.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error: %v", err)
	}

	// Verify file is removed
	if Exists(cpFile) {
		t.Error("checkpoint file should not exist after Cleanup")
	}
}

func TestCleanup_NonExistentFile(t *testing.T) {
	m := NewManager(&ManagerConfig{FilePath: "/nonexistent/path/file.json"})
	err := m.Cleanup()
	if err == nil {
		t.Error("Cleanup of non-existent file should return error")
	}
}

func TestDefaultManagerConfig(t *testing.T) {
	cfg := DefaultManagerConfig()
	if cfg.FilePath != ".indago-checkpoint.json" {
		t.Errorf("FilePath = %q, want %q", cfg.FilePath, ".indago-checkpoint.json")
	}
	if cfg.Interval != 30*time.Second {
		t.Errorf("Interval = %v, want %v", cfg.Interval, 30*time.Second)
	}
	if !cfg.AutoSave {
		t.Error("AutoSave should be true by default")
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	cpFile := filepath.Join(tmpDir, "bad.json")

	if err := os.WriteFile(cpFile, []byte("not valid json{{{"), 0600); err != nil {
		t.Fatalf("failed to write invalid json: %v", err)
	}

	m := NewManager(&ManagerConfig{FilePath: cpFile})
	err := m.Load(cpFile)
	if err == nil {
		t.Error("Load with invalid JSON should return error")
	}
}

func TestLoad_NonExistentFile(t *testing.T) {
	m := NewManager(&ManagerConfig{FilePath: "test.json"})
	err := m.Load("/nonexistent/path/file.json")
	if err == nil {
		t.Error("Load with non-existent file should return error")
	}
}
