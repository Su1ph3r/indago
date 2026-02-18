package plugin

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

// --- Mock implementations ---

type mockAttackPlugin struct {
	name        string
	description string
	attackTypes []string
	payloads    []Payload
	priority    int
}

func (m *mockAttackPlugin) Name() string        { return m.name }
func (m *mockAttackPlugin) Description() string  { return m.description }
func (m *mockAttackPlugin) AttackTypes() []string { return m.attackTypes }
func (m *mockAttackPlugin) Priority() int         { return m.priority }
func (m *mockAttackPlugin) Generate(ctx context.Context, endpoint types.Endpoint, param *types.Parameter) ([]Payload, error) {
	return m.payloads, nil
}

type mockResponseMatcher struct {
	name        string
	description string
	result      *MatchResult
	priority    int
}

func (m *mockResponseMatcher) Name() string        { return m.name }
func (m *mockResponseMatcher) Description() string  { return m.description }
func (m *mockResponseMatcher) Priority() int         { return m.priority }
func (m *mockResponseMatcher) Match(ctx context.Context, response *types.HTTPResponse, request *types.HTTPRequest) (*MatchResult, error) {
	return m.result, nil
}

// --- Registry tests ---

func TestNewRegistry(t *testing.T) {
	reg := NewRegistry()
	if reg == nil {
		t.Fatal("NewRegistry returned nil")
	}
	if len(reg.GetAttackPlugins()) != 0 {
		t.Errorf("expected 0 attack plugins, got %d", len(reg.GetAttackPlugins()))
	}
	if len(reg.GetResponseMatchers()) != 0 {
		t.Errorf("expected 0 response matchers, got %d", len(reg.GetResponseMatchers()))
	}
}

func TestRegisterAttackPlugin(t *testing.T) {
	reg := NewRegistry()
	p := &mockAttackPlugin{name: "test-plugin", attackTypes: []string{"sqli"}}
	reg.RegisterAttackPlugin(p)

	plugins := reg.GetAttackPlugins()
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}
	if plugins[0].Name() != "test-plugin" {
		t.Errorf("expected name 'test-plugin', got %q", plugins[0].Name())
	}
}

func TestRegisterResponseMatcher(t *testing.T) {
	reg := NewRegistry()
	m := &mockResponseMatcher{name: "test-matcher", result: &MatchResult{Matched: false}}
	reg.RegisterResponseMatcher(m)

	matchers := reg.GetResponseMatchers()
	if len(matchers) != 1 {
		t.Fatalf("expected 1 matcher, got %d", len(matchers))
	}
	if matchers[0].Name() != "test-matcher" {
		t.Errorf("expected name 'test-matcher', got %q", matchers[0].Name())
	}
}

func TestGetAttackPlugins(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterAttackPlugin(&mockAttackPlugin{name: "a", attackTypes: []string{"xss"}})
	reg.RegisterAttackPlugin(&mockAttackPlugin{name: "b", attackTypes: []string{"sqli"}})
	reg.RegisterAttackPlugin(&mockAttackPlugin{name: "c", attackTypes: []string{"idor"}})

	plugins := reg.GetAttackPlugins()
	if len(plugins) != 3 {
		t.Fatalf("expected 3 plugins, got %d", len(plugins))
	}
}

func TestGetResponseMatchers(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterResponseMatcher(&mockResponseMatcher{name: "m1", result: &MatchResult{Matched: false}})
	reg.RegisterResponseMatcher(&mockResponseMatcher{name: "m2", result: &MatchResult{Matched: false}})

	matchers := reg.GetResponseMatchers()
	if len(matchers) != 2 {
		t.Fatalf("expected 2 matchers, got %d", len(matchers))
	}
}

func TestGetPluginsForType(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterAttackPlugin(&mockAttackPlugin{name: "sqli-plugin", attackTypes: []string{"sqli"}})
	reg.RegisterAttackPlugin(&mockAttackPlugin{name: "xss-plugin", attackTypes: []string{"xss"}})
	reg.RegisterAttackPlugin(&mockAttackPlugin{name: "multi-plugin", attackTypes: []string{"sqli", "xss"}})

	sqliPlugins := reg.GetPluginsForType("sqli")
	if len(sqliPlugins) != 2 {
		t.Errorf("expected 2 sqli plugins, got %d", len(sqliPlugins))
	}

	xssPlugins := reg.GetPluginsForType("xss")
	if len(xssPlugins) != 2 {
		t.Errorf("expected 2 xss plugins, got %d", len(xssPlugins))
	}

	idorPlugins := reg.GetPluginsForType("idor")
	if len(idorPlugins) != 0 {
		t.Errorf("expected 0 idor plugins, got %d", len(idorPlugins))
	}
}

func TestPrioritySortingAttackPlugins(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterAttackPlugin(&mockAttackPlugin{name: "low", priority: 1, attackTypes: []string{"xss"}})
	reg.RegisterAttackPlugin(&mockAttackPlugin{name: "high", priority: 10, attackTypes: []string{"xss"}})
	reg.RegisterAttackPlugin(&mockAttackPlugin{name: "mid", priority: 5, attackTypes: []string{"xss"}})

	plugins := reg.GetAttackPlugins()
	if plugins[0].Name() != "high" {
		t.Errorf("expected first plugin 'high', got %q", plugins[0].Name())
	}
	if plugins[1].Name() != "mid" {
		t.Errorf("expected second plugin 'mid', got %q", plugins[1].Name())
	}
	if plugins[2].Name() != "low" {
		t.Errorf("expected third plugin 'low', got %q", plugins[2].Name())
	}
}

func TestPrioritySortingResponseMatchers(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterResponseMatcher(&mockResponseMatcher{name: "low", priority: 1, result: &MatchResult{}})
	reg.RegisterResponseMatcher(&mockResponseMatcher{name: "high", priority: 10, result: &MatchResult{}})
	reg.RegisterResponseMatcher(&mockResponseMatcher{name: "mid", priority: 5, result: &MatchResult{}})

	matchers := reg.GetResponseMatchers()
	if matchers[0].Name() != "high" {
		t.Errorf("expected first matcher 'high', got %q", matchers[0].Name())
	}
	if matchers[1].Name() != "mid" {
		t.Errorf("expected second matcher 'mid', got %q", matchers[1].Name())
	}
	if matchers[2].Name() != "low" {
		t.Errorf("expected third matcher 'low', got %q", matchers[2].Name())
	}
}

// --- Loader tests ---

func TestNewLoader(t *testing.T) {
	reg := NewRegistry()
	loader := NewLoader(reg)
	if loader == nil {
		t.Fatal("NewLoader returned nil")
	}
	if loader.registry != reg {
		t.Error("loader registry does not match provided registry")
	}
}

func TestLoadPayloadFileJSON(t *testing.T) {
	tmpDir := t.TempDir()
	payloadData := struct {
		Name        string    `json:"name"`
		Description string    `json:"description"`
		AttackTypes []string  `json:"attack_types"`
		Payloads    []Payload `json:"payloads"`
	}{
		Name:        "test-json-payloads",
		Description: "Test JSON payload file",
		AttackTypes: []string{"sqli", "xss"},
		Payloads: []Payload{
			{Value: "' OR 1=1--", Type: "sqli", Category: "auth_bypass", Description: "SQL injection"},
			{Value: "<script>alert(1)</script>", Type: "xss", Category: "reflected", Description: "XSS payload"},
		},
	}

	filePath := filepath.Join(tmpDir, "payloads.json")
	data, err := json.Marshal(payloadData)
	if err != nil {
		t.Fatalf("failed to marshal JSON: %v", err)
	}
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	reg := NewRegistry()
	loader := NewLoader(reg)
	if err := loader.LoadPayloadFile(filePath); err != nil {
		t.Fatalf("LoadPayloadFile failed: %v", err)
	}

	plugins := reg.GetAttackPlugins()
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}
	if plugins[0].Name() != "test-json-payloads" {
		t.Errorf("expected name 'test-json-payloads', got %q", plugins[0].Name())
	}

	payloads, err := plugins[0].Generate(context.Background(), types.Endpoint{}, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if len(payloads) != 2 {
		t.Errorf("expected 2 payloads, got %d", len(payloads))
	}
}

func TestLoadPayloadFileTxt(t *testing.T) {
	tmpDir := t.TempDir()
	content := "# comment line\npayload_one\npayload_two\n\npayload_three\n"

	filePath := filepath.Join(tmpDir, "payloads.txt")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	reg := NewRegistry()
	loader := NewLoader(reg)
	if err := loader.LoadPayloadFile(filePath); err != nil {
		t.Fatalf("LoadPayloadFile failed: %v", err)
	}

	plugins := reg.GetAttackPlugins()
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}
	if plugins[0].Name() != "payloads" {
		t.Errorf("expected name 'payloads', got %q", plugins[0].Name())
	}

	payloads, err := plugins[0].Generate(context.Background(), types.Endpoint{}, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	// 3 payloads: comment and blank line skipped
	if len(payloads) != 3 {
		t.Errorf("expected 3 payloads, got %d", len(payloads))
	}
}

func TestLoadMatcherFile(t *testing.T) {
	tmpDir := t.TempDir()
	matcherData := struct {
		Name        string       `json:"name"`
		Description string       `json:"description"`
		Matchers    []MatcherDef `json:"matchers"`
	}{
		Name:        "test-matchers",
		Description: "Test matcher file",
		Matchers: []MatcherDef{
			{
				Name:        "Error Disclosure",
				Description: "Detects error messages in responses",
				Patterns:    []string{"stack trace", "exception"},
				Severity:    "medium",
				Confidence:  "high",
				CWE:         "CWE-209",
			},
			{
				Name:        "SQL Error",
				Description: "Detects SQL errors",
				Patterns:    []string{"syntax error", "mysql_fetch"},
				Severity:    "high",
				Confidence:  "high",
				CWE:         "CWE-89",
			},
		},
	}

	filePath := filepath.Join(tmpDir, "matchers.json")
	data, err := json.Marshal(matcherData)
	if err != nil {
		t.Fatalf("failed to marshal JSON: %v", err)
	}
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	reg := NewRegistry()
	loader := NewLoader(reg)
	if err := loader.LoadMatcherFile(filePath); err != nil {
		t.Fatalf("LoadMatcherFile failed: %v", err)
	}

	matchers := reg.GetResponseMatchers()
	if len(matchers) != 2 {
		t.Fatalf("expected 2 matchers, got %d", len(matchers))
	}
	if matchers[0].Name() != "Error Disclosure" {
		t.Errorf("expected first matcher 'Error Disclosure', got %q", matchers[0].Name())
	}
}

func TestLoadPlugins(t *testing.T) {
	tmpDir := t.TempDir()

	// Create payload file
	payloadData := struct {
		Name        string    `json:"name"`
		Description string    `json:"description"`
		AttackTypes []string  `json:"attack_types"`
		Payloads    []Payload `json:"payloads"`
	}{
		Name:        "loaded-plugin",
		Description: "Plugin loaded via LoadPlugins",
		AttackTypes: []string{"xss"},
		Payloads:    []Payload{{Value: "<img src=x>", Type: "xss", Category: "reflected"}},
	}
	payloadPath := filepath.Join(tmpDir, "payloads.json")
	data, _ := json.Marshal(payloadData)
	os.WriteFile(payloadPath, data, 0644)

	// Create matcher file
	matcherData := struct {
		Name        string       `json:"name"`
		Description string       `json:"description"`
		Matchers    []MatcherDef `json:"matchers"`
	}{
		Name:        "loaded-matchers",
		Description: "Matchers loaded via LoadPlugins",
		Matchers: []MatcherDef{
			{Name: "test-detect", Description: "test", Patterns: []string{"error"}, Severity: "low", Confidence: "low"},
		},
	}
	matcherPath := filepath.Join(tmpDir, "matchers.json")
	data, _ = json.Marshal(matcherData)
	os.WriteFile(matcherPath, data, 0644)

	config := PluginConfig{
		Enabled:      true,
		PayloadFiles: []string{payloadPath},
		MatcherFiles: []string{matcherPath},
	}

	reg, err := LoadPlugins(config)
	if err != nil {
		t.Fatalf("LoadPlugins failed: %v", err)
	}
	if len(reg.GetAttackPlugins()) != 1 {
		t.Errorf("expected 1 attack plugin, got %d", len(reg.GetAttackPlugins()))
	}
	if len(reg.GetResponseMatchers()) != 1 {
		t.Errorf("expected 1 response matcher, got %d", len(reg.GetResponseMatchers()))
	}
}

func TestLoadPluginsDisabled(t *testing.T) {
	config := PluginConfig{
		Enabled:      false,
		PayloadFiles: []string{"/nonexistent/file.json"},
	}
	reg, err := LoadPlugins(config)
	if err != nil {
		t.Fatalf("LoadPlugins with disabled config should not error: %v", err)
	}
	if len(reg.GetAttackPlugins()) != 0 {
		t.Errorf("disabled config should produce 0 plugins, got %d", len(reg.GetAttackPlugins()))
	}
}

func TestLoadPayloadFileNotFound(t *testing.T) {
	reg := NewRegistry()
	loader := NewLoader(reg)
	err := loader.LoadPayloadFile("/nonexistent/payloads.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestLoadMatcherFileNotFound(t *testing.T) {
	reg := NewRegistry()
	loader := NewLoader(reg)
	err := loader.LoadMatcherFile("/nonexistent/matchers.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

// --- FilePayloadPlugin method tests ---

func TestFilePayloadPluginMethods(t *testing.T) {
	p := &FilePayloadPlugin{
		name:        "file-plugin",
		description: "A file-based plugin",
		attackTypes: []string{"sqli", "xss"},
		payloads: []Payload{
			{Value: "test", Type: "sqli"},
		},
		filePath: "/tmp/test.json",
	}

	if p.Name() != "file-plugin" {
		t.Errorf("expected name 'file-plugin', got %q", p.Name())
	}
	if p.Description() != "A file-based plugin" {
		t.Errorf("expected description 'A file-based plugin', got %q", p.Description())
	}
	if len(p.AttackTypes()) != 2 {
		t.Errorf("expected 2 attack types, got %d", len(p.AttackTypes()))
	}
	if p.Priority() != 0 {
		t.Errorf("expected priority 0, got %d", p.Priority())
	}

	payloads, err := p.Generate(context.Background(), types.Endpoint{}, nil)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if len(payloads) != 1 {
		t.Errorf("expected 1 payload, got %d", len(payloads))
	}
	if payloads[0].Value != "test" {
		t.Errorf("expected payload value 'test', got %q", payloads[0].Value)
	}
}

// --- FileResponseMatcher method tests ---

func TestFileResponseMatcherMethods(t *testing.T) {
	m := &FileResponseMatcher{
		name:        "file-matcher",
		description: "A file-based matcher",
		patterns:    []string{"error", "exception"},
		severity:    "high",
		confidence:  "medium",
		cwe:         "CWE-209",
	}

	if m.Name() != "file-matcher" {
		t.Errorf("expected name 'file-matcher', got %q", m.Name())
	}
	if m.Description() != "A file-based matcher" {
		t.Errorf("expected description 'A file-based matcher', got %q", m.Description())
	}
	if m.Priority() != 0 {
		t.Errorf("expected priority 0, got %d", m.Priority())
	}
}

func TestFileResponseMatcherMatch(t *testing.T) {
	m := &FileResponseMatcher{
		name:        "error-matcher",
		description: "Detects errors",
		patterns:    []string{"stack trace", "exception"},
		severity:    "medium",
		confidence:  "high",
		cwe:         "CWE-209",
	}

	// Matching response
	resp := &types.HTTPResponse{Body: "Internal server error: stack trace at line 42"}
	req := &types.HTTPRequest{Method: "GET", URL: "http://example.com/api"}
	result, err := m.Match(context.Background(), resp, req)
	if err != nil {
		t.Fatalf("Match failed: %v", err)
	}
	if !result.Matched {
		t.Error("expected match, got no match")
	}
	if result.Severity != "medium" {
		t.Errorf("expected severity 'medium', got %q", result.Severity)
	}
	if result.CWE != "CWE-209" {
		t.Errorf("expected CWE 'CWE-209', got %q", result.CWE)
	}
	if len(result.Evidence) != 1 || result.Evidence[0] != "stack trace" {
		t.Errorf("expected evidence ['stack trace'], got %v", result.Evidence)
	}

	// Non-matching response
	resp2 := &types.HTTPResponse{Body: "OK success"}
	result2, err := m.Match(context.Background(), resp2, req)
	if err != nil {
		t.Fatalf("Match failed: %v", err)
	}
	if result2.Matched {
		t.Error("expected no match, got match")
	}

	// Nil response
	result3, err := m.Match(context.Background(), nil, req)
	if err != nil {
		t.Fatalf("Match with nil response failed: %v", err)
	}
	if result3.Matched {
		t.Error("expected no match for nil response, got match")
	}
}

// --- Helper function tests ---

func TestGetExtension(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"payloads.json", "json"},
		{"payloads.txt", "txt"},
		{"payloads.yaml", "yaml"},
		{"/path/to/file.JSON", "json"},
		{"noext", ""},
		{"/dir/noext", ""},
	}
	for _, tt := range tests {
		got := getExtension(tt.path)
		if got != tt.expected {
			t.Errorf("getExtension(%q) = %q, want %q", tt.path, got, tt.expected)
		}
	}
}

func TestGetBaseName(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"payloads.json", "payloads"},
		{"/path/to/payloads.txt", "payloads"},
		{"noext", "noext"},
		{"/dir/noext", "noext"},
	}
	for _, tt := range tests {
		got := getBaseName(tt.path)
		if got != tt.expected {
			t.Errorf("getBaseName(%q) = %q, want %q", tt.path, got, tt.expected)
		}
	}
}
