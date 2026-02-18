package importer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestLoadCepheusFindings_Valid(t *testing.T) {
	data := types.CepheusImport{
		ExportSource: "cepheus",
		ScanID:       "scan-100",
		ClusterName:  "prod-cluster",
		Containers: []types.CepheusContainer{
			{
				Name:       "web-app",
				Image:      "nginx:latest",
				Namespace:  "default",
				Privileged: true,
				RunAsRoot:  true,
			},
		},
		EscapePaths: []types.CepheusEscapePath{
			{
				ID:          "ep-1",
				Description: "Privileged container escape",
				Severity:    "critical",
				Container:   "web-app",
				Technique:   "privileged_escape",
			},
		},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "cepheus.json")
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("failed to marshal test data: %v", err)
	}
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	imp, err := LoadCepheusFindings(path)
	if err != nil {
		t.Fatalf("LoadCepheusFindings failed: %v", err)
	}

	if imp.ExportSource != "cepheus" {
		t.Errorf("ExportSource = %q, want %q", imp.ExportSource, "cepheus")
	}
	if imp.ScanID != "scan-100" {
		t.Errorf("ScanID = %q, want %q", imp.ScanID, "scan-100")
	}
	if imp.ClusterName != "prod-cluster" {
		t.Errorf("ClusterName = %q, want %q", imp.ClusterName, "prod-cluster")
	}
	if len(imp.Containers) != 1 {
		t.Errorf("expected 1 container, got %d", len(imp.Containers))
	}
	if len(imp.EscapePaths) != 1 {
		t.Errorf("expected 1 escape path, got %d", len(imp.EscapePaths))
	}
}

func TestLoadCepheusFindings_EmptySource(t *testing.T) {
	// Empty export_source should be accepted
	data := types.CepheusImport{
		Containers: []types.CepheusContainer{
			{Name: "app", Image: "app:v1"},
		},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "cepheus-nosrc.json")
	b, _ := json.Marshal(data)
	os.WriteFile(path, b, 0644)

	imp, err := LoadCepheusFindings(path)
	if err != nil {
		t.Fatalf("LoadCepheusFindings failed for empty source: %v", err)
	}
	if len(imp.Containers) != 1 {
		t.Errorf("expected 1 container, got %d", len(imp.Containers))
	}
}

func TestLoadCepheusFindings_InvalidFile(t *testing.T) {
	_, err := LoadCepheusFindings("/nonexistent/path/cepheus.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestLoadCepheusFindings_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.json")
	os.WriteFile(path, []byte("not json"), 0644)

	_, err := LoadCepheusFindings(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestLoadCepheusFindings_WrongSource(t *testing.T) {
	data := types.CepheusImport{
		ExportSource: "wrong-tool",
		Containers: []types.CepheusContainer{
			{Name: "app", Image: "app:v1"},
		},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "wrong.json")
	b, _ := json.Marshal(data)
	os.WriteFile(path, b, 0644)

	_, err := LoadCepheusFindings(path)
	if err == nil {
		t.Fatal("expected error for wrong export_source, got nil")
	}
}

func TestLoadCepheusFindings_EmptyData(t *testing.T) {
	data := types.CepheusImport{
		ExportSource: "cepheus",
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "empty.json")
	b, _ := json.Marshal(data)
	os.WriteFile(path, b, 0644)

	_, err := LoadCepheusFindings(path)
	if err == nil {
		t.Fatal("expected error for empty containers and escape paths, got nil")
	}
}

func TestEnrichFindings_SSRFPrivileged(t *testing.T) {
	cepheusData := &types.CepheusImport{
		Containers: []types.CepheusContainer{
			{Name: "app", Image: "app:v1", Privileged: true},
		},
	}
	findings := []types.Finding{
		{Type: types.AttackSSRF, Severity: types.SeverityHigh, Description: "SSRF found"},
	}

	result := EnrichFindingsWithContainerContext(cepheusData, findings)

	if !containsTag(result[0].Tags, "container:escape_risk") {
		t.Error("expected container:escape_risk tag")
	}
	if !containsTag(result[0].Tags, "container:privileged") {
		t.Error("expected container:privileged tag")
	}
}

func TestEnrichFindings_PathTraversalHostMount(t *testing.T) {
	cepheusData := &types.CepheusImport{
		Containers: []types.CepheusContainer{
			{Name: "app", Image: "app:v1", Mounts: []string{"/etc:/host-etc"}},
		},
	}
	findings := []types.Finding{
		{Type: types.AttackPathTraversal, Severity: types.SeverityHigh, Description: "Path traversal"},
	}

	result := EnrichFindingsWithContainerContext(cepheusData, findings)

	if !containsTag(result[0].Tags, "container:host_access") {
		t.Error("expected container:host_access tag")
	}
	if !containsTag(result[0].Tags, "container:host_mount") {
		t.Error("expected container:host_mount tag")
	}
}

func TestEnrichFindings_CommandInjectionDangerousCaps(t *testing.T) {
	cepheusData := &types.CepheusImport{
		Containers: []types.CepheusContainer{
			{Name: "app", Image: "app:v1", Capabilities: []string{"SYS_ADMIN"}},
		},
	}
	findings := []types.Finding{
		{Type: types.AttackCommandInject, Severity: types.SeverityHigh, Description: "Command injection"},
	}

	result := EnrichFindingsWithContainerContext(cepheusData, findings)

	if !containsTag(result[0].Tags, "container:privesc") {
		t.Error("expected container:privesc tag")
	}
	if !containsTag(result[0].Tags, "container:dangerous_caps") {
		t.Error("expected container:dangerous_caps tag")
	}
}

func TestEnrichFindings_SSRFHostNetwork(t *testing.T) {
	cepheusData := &types.CepheusImport{
		Containers: []types.CepheusContainer{
			{Name: "app", Image: "app:v1", HostNetwork: true},
		},
	}
	findings := []types.Finding{
		{Type: types.AttackSSRF, Severity: types.SeverityHigh, Description: "SSRF found"},
	}

	result := EnrichFindingsWithContainerContext(cepheusData, findings)

	if !containsTag(result[0].Tags, "container:network_escape") {
		t.Error("expected container:network_escape tag")
	}
	if !containsTag(result[0].Tags, "container:host_network") {
		t.Error("expected container:host_network tag")
	}
}

func TestEnrichFindings_EscapePathsAvailable(t *testing.T) {
	cepheusData := &types.CepheusImport{
		Containers: []types.CepheusContainer{
			{Name: "app", Image: "app:v1"},
		},
		EscapePaths: []types.CepheusEscapePath{
			{ID: "ep-1", Description: "escape", Severity: "critical", Container: "app", Technique: "privileged_escape"},
		},
	}
	findings := []types.Finding{
		{Type: "xss", Severity: types.SeverityCritical, Description: "XSS found"},
		{Type: "xss", Severity: types.SeverityLow, Description: "Low XSS"},
	}

	result := EnrichFindingsWithContainerContext(cepheusData, findings)

	if !containsTag(result[0].Tags, "container:escape_paths_available") {
		t.Error("expected container:escape_paths_available tag on critical finding")
	}
	if containsTag(result[1].Tags, "container:escape_paths_available") {
		t.Error("did not expect container:escape_paths_available tag on low finding")
	}
}

func TestEnrichFindings_NoMatchingConditions(t *testing.T) {
	cepheusData := &types.CepheusImport{
		Containers: []types.CepheusContainer{
			{Name: "app", Image: "app:v1"}, // No dangerous features
		},
	}
	findings := []types.Finding{
		{Type: types.AttackSSRF, Severity: types.SeverityMedium, Description: "SSRF found"},
	}

	result := EnrichFindingsWithContainerContext(cepheusData, findings)

	if len(result[0].Tags) != 0 {
		t.Errorf("expected no tags, got %v", result[0].Tags)
	}
}

func TestIsHostMount(t *testing.T) {
	tests := []struct {
		mount string
		want  bool
	}{
		{"/etc:/host-etc", true},
		{"/var:/data", true},
		{"/proc", true},
		{"/sys:/host-sys", true},
		{"/dev:/host-dev", true},
		{"/root:/mnt", true},
		{"/home:/mnt", true},
		{"/:/host", true},
		{"/app/data:/data", false},
		{"tmpfs:/tmp", false},
		{"volume-name:/data", false},
	}

	for _, tt := range tests {
		got := isHostMount(tt.mount)
		if got != tt.want {
			t.Errorf("isHostMount(%q) = %v, want %v", tt.mount, got, tt.want)
		}
	}
}

func TestIsDangerousCapability(t *testing.T) {
	tests := []struct {
		cap  string
		want bool
	}{
		{"SYS_ADMIN", true},
		{"SYS_PTRACE", true},
		{"SYS_RAWIO", true},
		{"SYS_MODULE", true},
		{"DAC_READ_SEARCH", true},
		{"NET_ADMIN", true},
		{"NET_RAW", true},
		{"SYS_CHROOT", true},
		{"CAP_SYS_ADMIN", true},
		{"CAP_NET_RAW", true},
		{"sys_admin", true},       // case insensitive
		{"cap_sys_ptrace", true},  // case insensitive with prefix
		{"CHOWN", false},
		{"SETUID", false},
		{"FOWNER", false},
	}

	for _, tt := range tests {
		got := isDangerousCapability(tt.cap)
		if got != tt.want {
			t.Errorf("isDangerousCapability(%q) = %v, want %v", tt.cap, got, tt.want)
		}
	}
}

func TestAppendUnique(t *testing.T) {
	result := appendUnique([]string{"a", "b"}, "b", "c", "a", "d")
	if len(result) != 4 {
		t.Errorf("expected 4 items, got %d: %v", len(result), result)
	}

	// Test with nil slice
	result = appendUnique(nil, "x", "y", "x")
	if len(result) != 2 {
		t.Errorf("expected 2 items, got %d: %v", len(result), result)
	}
}

func containsTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}
