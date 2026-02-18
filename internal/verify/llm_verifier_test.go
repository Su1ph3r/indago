package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/su1ph3r/indago/internal/fuzzer"
	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

// mockProvider implements llm.Provider for testing
type mockProvider struct {
	response string
	err      error
	name     string
	model    string
}

func (m *mockProvider) Analyze(_ context.Context, _ string) (string, error) {
	return m.response, m.err
}

func (m *mockProvider) AnalyzeStructured(_ context.Context, _ string, result interface{}) error {
	if m.err != nil {
		return m.err
	}
	return json.Unmarshal([]byte(m.response), result)
}

func (m *mockProvider) AnalyzeWithSystem(_ context.Context, _, _ string) (string, error) {
	return m.response, m.err
}

func (m *mockProvider) Name() string {
	if m.name != "" {
		return m.name
	}
	return "mock"
}

func (m *mockProvider) Model() string {
	if m.model != "" {
		return m.model
	}
	return "mock-model"
}

func defaultConfig() types.VerificationSettings {
	return types.VerificationSettings{
		Enabled:             true,
		MaxBodyLength:       2000,
		MaxRequestBody:      500,
		MaxFindingsPerBatch: 5,
		FuzzFollowUps:       false,
		MaxFollowUpPayloads: 3,
		Concurrency:         2,
	}
}

func makeFinding(method, endpoint, severity, confidence, findingType string) types.Finding {
	return types.Finding{
		ID:         "test-id",
		Type:       findingType,
		Severity:   severity,
		Confidence: confidence,
		Title:      fmt.Sprintf("Test %s on %s %s", findingType, method, endpoint),
		Endpoint:   endpoint,
		Method:     method,
		Evidence: &types.Evidence{
			Request: &types.HTTPRequest{
				Method: method,
				URL:    "http://example.com" + endpoint,
				Body:   `{"user_id": "1"}`,
			},
			Response: &types.HTTPResponse{
				StatusCode: 200,
				Body:       `{"data": "sensitive"}`,
			},
			MatchedData: []string{"sensitive"},
		},
	}
}

func TestNewLLMVerifier(t *testing.T) {
	provider := &mockProvider{}
	cfg := defaultConfig()
	v := NewLLMVerifier(provider, cfg, nil, nil)

	if v == nil {
		t.Fatal("expected non-nil verifier")
	}
	if v.provider != provider {
		t.Error("provider not set")
	}
	if v.config != cfg {
		t.Error("config not set")
	}
}

func TestVerifyFindings_Confirmed(t *testing.T) {
	resp := llmBatchResponse{
		Assessments: []llmFindingAssessment{
			{
				FindingIndex:   0,
				Exploitability: "confirmed",
				Confidence:     "high",
				Analysis:       "This is a confirmed IDOR vulnerability",
			},
		},
	}
	respJSON, _ := json.Marshal(resp)

	provider := &mockProvider{response: string(respJSON)}
	v := NewLLMVerifier(provider, defaultConfig(), nil, nil)

	findings := []types.Finding{
		makeFinding("GET", "/users/1", types.SeverityHigh, types.ConfidenceMedium, "idor"),
	}

	verified, followUp, err := v.VerifyFindings(context.Background(), findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(followUp) != 0 {
		t.Errorf("expected no follow-ups, got %d", len(followUp))
	}

	if len(verified) != 1 {
		t.Fatalf("expected 1 verified finding, got %d", len(verified))
	}

	f := verified[0]
	if f.Verification == nil {
		t.Fatal("expected verification metadata")
	}
	if !f.Verification.Verified {
		t.Error("expected verified=true for confirmed finding")
	}
	if f.Confidence != types.ConfidenceHigh {
		t.Errorf("expected confidence=high, got %s", f.Confidence)
	}
	if f.Verification.Exploitability != "confirmed" {
		t.Errorf("expected exploitability=confirmed, got %s", f.Verification.Exploitability)
	}
	if f.Verification.OriginalConfidence != types.ConfidenceMedium {
		t.Errorf("expected original_confidence=medium, got %s", f.Verification.OriginalConfidence)
	}
}

func TestVerifyFindings_FalsePositive(t *testing.T) {
	resp := llmBatchResponse{
		Assessments: []llmFindingAssessment{
			{
				FindingIndex:   0,
				Exploitability: "false_positive",
				Confidence:     "high",
				Analysis:       "This appears to be a normal response pattern",
			},
		},
	}
	respJSON, _ := json.Marshal(resp)

	provider := &mockProvider{response: string(respJSON)}
	v := NewLLMVerifier(provider, defaultConfig(), nil, nil)

	findings := []types.Finding{
		makeFinding("GET", "/users/1", types.SeverityMedium, types.ConfidenceHigh, "idor"),
	}

	verified, _, err := v.VerifyFindings(context.Background(), findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := verified[0]
	if f.Verification == nil {
		t.Fatal("expected verification metadata")
	}
	if f.Verification.Verified {
		t.Error("expected verified=false for false_positive")
	}
	if f.Confidence != types.ConfidenceLow {
		t.Errorf("expected confidence=low, got %s", f.Confidence)
	}
}

func TestVerifyFindings_BatchGrouping(t *testing.T) {
	resp := llmBatchResponse{
		Assessments: []llmFindingAssessment{
			{FindingIndex: 0, Exploitability: "confirmed", Confidence: "high", Analysis: "confirmed"},
		},
	}
	respJSON, _ := json.Marshal(resp)

	provider := &mockProvider{response: string(respJSON)}
	v := NewLLMVerifier(provider, defaultConfig(), nil, nil)

	findings := []types.Finding{
		makeFinding("GET", "/users/1", types.SeverityHigh, types.ConfidenceMedium, "idor"),
		makeFinding("POST", "/admin/settings", types.SeverityHigh, types.ConfidenceMedium, "auth_bypass"),
	}

	verified, _, err := v.VerifyFindings(context.Background(), findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Both endpoints should have been processed (2 separate batches)
	if len(verified) != 2 {
		t.Errorf("expected 2 verified findings, got %d", len(verified))
	}
}

func TestVerifyFindings_LLMFailure(t *testing.T) {
	provider := &mockProvider{err: fmt.Errorf("provider unavailable")}
	v := NewLLMVerifier(provider, defaultConfig(), nil, nil)

	findings := []types.Finding{
		makeFinding("GET", "/users/1", types.SeverityHigh, types.ConfidenceMedium, "idor"),
	}

	verified, _, err := v.VerifyFindings(context.Background(), findings)
	if err == nil {
		t.Error("expected error from LLM failure")
	}

	// Findings should still be returned
	if len(verified) != 1 {
		t.Errorf("expected 1 finding returned on failure, got %d", len(verified))
	}

	// Verification metadata should NOT be set on failure
	if verified[0].Verification != nil {
		t.Error("expected no verification metadata on LLM failure")
	}
}

func TestVerifyFindings_Empty(t *testing.T) {
	provider := &mockProvider{}
	v := NewLLMVerifier(provider, defaultConfig(), nil, nil)

	verified, followUp, err := v.VerifyFindings(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(verified) != 0 {
		t.Errorf("expected 0 verified, got %d", len(verified))
	}
	if len(followUp) != 0 {
		t.Errorf("expected 0 follow-ups, got %d", len(followUp))
	}
}

func TestVerifyFindings_NoFollowUps(t *testing.T) {
	resp := llmBatchResponse{
		Assessments: []llmFindingAssessment{
			{
				FindingIndex:      0,
				Exploitability:    "likely",
				Confidence:        "medium",
				Analysis:          "Likely exploitable",
				SuggestedPayloads: []string{"' OR 1=1--", "admin' --"},
			},
		},
	}
	respJSON, _ := json.Marshal(resp)

	cfg := defaultConfig()
	cfg.FuzzFollowUps = false

	provider := &mockProvider{response: string(respJSON)}
	v := NewLLMVerifier(provider, cfg, nil, nil)

	findings := []types.Finding{
		makeFinding("GET", "/users/1", types.SeverityHigh, types.ConfidenceMedium, "sqli"),
	}

	_, followUp, err := v.VerifyFindings(context.Background(), findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(followUp) != 0 {
		t.Errorf("expected no follow-ups when FuzzFollowUps=false, got %d", len(followUp))
	}
}

func TestBuildVerificationPrompt(t *testing.T) {
	provider := &mockProvider{}
	v := NewLLMVerifier(provider, defaultConfig(), nil, nil)

	findings := []types.Finding{
		makeFinding("GET", "/users/1", types.SeverityHigh, types.ConfidenceMedium, "idor"),
	}

	system, user := v.buildVerificationPrompt(findings)

	if !strings.Contains(system, "expert application security researcher") {
		t.Error("system prompt missing expected content")
	}
	if !strings.Contains(system, "exploitability") {
		t.Error("system prompt missing exploitability schema")
	}
	if !strings.Contains(user, "Finding 0") {
		t.Error("user prompt missing finding index")
	}
	if !strings.Contains(user, "GET") {
		t.Error("user prompt missing method")
	}
	if !strings.Contains(user, "/users/1") {
		t.Error("user prompt missing endpoint")
	}
	if !strings.Contains(user, "idor") {
		t.Error("user prompt missing finding type")
	}
}

func TestTruncateBody(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		maxLen int
		want   string
	}{
		{"short body", "hello", 100, "hello"},
		{"exact length", "12345", 5, "12345"},
		{"over length", "1234567890", 5, "12345...[truncated]"},
		{"empty body", "", 100, ""},
		{"zero max uses default", strings.Repeat("x", 2001), 0, strings.Repeat("x", 2000) + "...[truncated]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateBody(tt.body, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncateBody(%q, %d) = %q, want %q", tt.body, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestGroupByEndpoint(t *testing.T) {
	findings := []types.Finding{
		{Method: "GET", Endpoint: "/users/1", Type: "idor"},
		{Method: "GET", Endpoint: "/users/1", Type: "data_exposure"},
		{Method: "POST", Endpoint: "/admin", Type: "auth_bypass"},
	}

	groups := groupByEndpoint(findings)

	if len(groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(groups))
	}
	if len(groups["GET:/users/1"]) != 2 {
		t.Errorf("expected 2 findings for GET:/users/1, got %d", len(groups["GET:/users/1"]))
	}
	if len(groups["POST:/admin"]) != 1 {
		t.Errorf("expected 1 finding for POST:/admin, got %d", len(groups["POST:/admin"]))
	}
}

func TestApplyAssessment(t *testing.T) {
	tests := []struct {
		name               string
		initialConfidence  string
		exploitability     string
		expectedVerified   bool
		expectedConfidence string
	}{
		{"confirmed upgrades to high", types.ConfidenceMedium, "confirmed", true, types.ConfidenceHigh},
		{"confirmed from low", types.ConfidenceLow, "confirmed", true, types.ConfidenceHigh},
		{"likely upgrades one level", types.ConfidenceLow, "likely", true, types.ConfidenceMedium},
		{"likely from medium", types.ConfidenceMedium, "likely", true, types.ConfidenceHigh},
		{"likely from high stays high", types.ConfidenceHigh, "likely", true, types.ConfidenceHigh},
		{"unlikely downgrades", types.ConfidenceHigh, "unlikely", false, types.ConfidenceMedium},
		{"unlikely from medium", types.ConfidenceMedium, "unlikely", false, types.ConfidenceLow},
		{"unlikely from low stays low", types.ConfidenceLow, "unlikely", false, types.ConfidenceLow},
		{"false_positive sets low", types.ConfidenceHigh, "false_positive", false, types.ConfidenceLow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockProvider{name: "test-provider", model: "test-model"}
			v := NewLLMVerifier(provider, defaultConfig(), nil, nil)

			finding := types.Finding{
				Confidence: tt.initialConfidence,
			}

			assessment := llmFindingAssessment{
				Exploitability: tt.exploitability,
				Confidence:     "medium",
				Analysis:       "test analysis",
			}

			v.applyAssessment(&finding, assessment)

			if finding.Verification == nil {
				t.Fatal("expected verification metadata")
			}
			if finding.Verification.Verified != tt.expectedVerified {
				t.Errorf("expected verified=%v, got %v", tt.expectedVerified, finding.Verification.Verified)
			}
			if finding.Confidence != tt.expectedConfidence {
				t.Errorf("expected confidence=%s, got %s", tt.expectedConfidence, finding.Confidence)
			}
			if finding.Verification.OriginalConfidence != tt.initialConfidence {
				t.Errorf("expected original_confidence=%s, got %s", tt.initialConfidence, finding.Verification.OriginalConfidence)
			}
			if finding.Verification.ProviderName != "test-provider" {
				t.Errorf("expected provider_name=test-provider, got %s", finding.Verification.ProviderName)
			}
			if finding.Verification.ModelName != "test-model" {
				t.Errorf("expected model_name=test-model, got %s", finding.Verification.ModelName)
			}
		})
	}
}

func TestSanitizeFollowUpPayload(t *testing.T) {
	tests := []struct {
		name      string
		payload   string
		wantClean string
		wantValid bool
	}{
		{"valid payload passes through", "' OR 1=1--", "' OR 1=1--", true},
		{"null bytes are stripped", "test\x00payload", "testpayload", true},
		{"file scheme rejected", "file:///etc/passwd", "", false},
		{"data scheme rejected", "data:text/html,<script>alert(1)</script>", "", false},
		{"javascript scheme rejected", "javascript:alert(1)", "", false},
		{"gopher scheme rejected", "gopher://evil.com/x", "", false},
		{"control character rejected", "payload\x01here", "", false},
		{"tab allowed", "payload\there", "payload\there", true},
		{"newline allowed", "payload\nhere", "payload\nhere", true},
		{"carriage return allowed", "payload\rhere", "payload\rhere", true},
		{"embedded dangerous scheme rejected", "http://ok.com?r=file:///etc/passwd", "", false},
		{"case insensitive scheme check", "FILE:///etc/passwd", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotClean, gotValid := sanitizeFollowUpPayload(tt.payload)
			if gotValid != tt.wantValid {
				t.Errorf("sanitizeFollowUpPayload(%q) valid = %v, want %v", tt.payload, gotValid, tt.wantValid)
			}
			if gotValid && gotClean != tt.wantClean {
				t.Errorf("sanitizeFollowUpPayload(%q) clean = %q, want %q", tt.payload, gotClean, tt.wantClean)
			}
		})
	}
}

func TestContainsExternalURL(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		targetBase string
		want       bool
	}{
		{"no URL", "' OR 1=1--", "http://example.com", false},
		{"same host", "http://example.com/admin", "http://example.com", false},
		{"external host", "http://evil.com/steal?d=1", "http://example.com", true},
		{"subdomain of target", "http://api.example.com/x", "http://example.com", false},
		{"empty target", "http://evil.com/x", "", false},
		{"https external", "https://attacker.io/c", "http://example.com", true},
		{"mixed URLs", "test http://example.com/a http://evil.com/b", "http://example.com", true},
		{"no scheme", "just some payload text", "http://example.com", false},
		{"target with port", "http://evil.com/x", "http://example.com:8080", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsExternalURL(tt.payload, tt.targetBase)
			if got != tt.want {
				t.Errorf("containsExternalURL(%q, %q) = %v, want %v", tt.payload, tt.targetBase, got, tt.want)
			}
		})
	}
}

// --- Confirmation pass tests ---

func makeVerifiedFinding(id, method, endpoint, severity, confidence, findingType, exploitability, llmConfidence string) types.Finding {
	f := makeFinding(method, endpoint, severity, confidence, findingType)
	f.ID = id
	f.Verification = &types.VerificationMeta{
		Verified:           exploitability == "confirmed" || exploitability == "likely",
		OriginalConfidence: confidence,
		Exploitability:     exploitability,
		LLMConfidence:      llmConfidence,
		Analysis:           "Initial analysis",
		ProviderName:       "mock",
		ModelName:          "mock-model",
	}
	return f
}

func TestFilterForConfirmation(t *testing.T) {
	tests := []struct {
		name           string
		exploitability string
		llmConfidence  string
		wantIncluded   bool
	}{
		{"likely+high included", "likely", "high", true},
		{"likely+medium included", "likely", "medium", true},
		{"likely+low included", "likely", "low", true},
		{"unlikely+medium included", "unlikely", "medium", true},
		{"unlikely+high included", "unlikely", "high", true},
		{"confirmed+high excluded", "confirmed", "high", false},
		{"confirmed+medium included", "confirmed", "medium", true},
		{"false_positive excluded", "false_positive", "high", false},
		{"unlikely+low excluded", "unlikely", "low", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := makeVerifiedFinding("test-1", "GET", "/test", "high", "medium", "idor", tt.exploitability, tt.llmConfidence)
			candidates := filterForConfirmation([]types.Finding{f})
			got := len(candidates) > 0
			if got != tt.wantIncluded {
				t.Errorf("filterForConfirmation(%s, %s) included=%v, want %v", tt.exploitability, tt.llmConfidence, got, tt.wantIncluded)
			}
		})
	}
}

func TestFilterForConfirmation_NoVerification(t *testing.T) {
	f := makeFinding("GET", "/test", "high", "medium", "idor")
	// No verification metadata
	candidates := filterForConfirmation([]types.Finding{f})
	if len(candidates) != 0 {
		t.Errorf("expected 0 candidates for finding without verification, got %d", len(candidates))
	}
}

func TestConfirmFindings_SinglePassUpgrade(t *testing.T) {
	callCount := 0
	provider := &sequenceProvider{
		responses: []string{
			// generatePayloadsForFinding call
			`{"payloads": [{"value": "' OR 1=1--", "position": "body", "parameter": "id", "rationale": "SQL injection test", "expected_result": "error"}]}`,
			// finalVerify call
			`{"final_exploitability": "confirmed", "final_confidence": "high", "combined_analysis": "Confirmed via confirmation payload"}`,
		},
		callCount: &callCount,
	}

	cfg := defaultConfig()
	cfg.MaxConfirmPayloads = 5
	v := NewLLMVerifier(provider, cfg, newNoopEngine(), newNoopAnalyzer())

	findings := []types.Finding{
		makeVerifiedFinding("f-1", "GET", "/users/1", "high", "medium", "sqli", "likely", "medium"),
	}

	result, err := v.ConfirmFindings(context.Background(), findings, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}

	f := result[0]
	if f.Confidence != types.ConfidenceHigh {
		t.Errorf("expected confidence=high, got %s", f.Confidence)
	}
	if f.Verification.Exploitability != "confirmed" {
		t.Errorf("expected exploitability=confirmed, got %s", f.Verification.Exploitability)
	}
	if len(f.Verification.ConfirmationPasses) != 1 {
		t.Fatalf("expected 1 confirmation pass, got %d", len(f.Verification.ConfirmationPasses))
	}
	pass := f.Verification.ConfirmationPasses[0]
	if pass.PassNumber != 2 {
		t.Errorf("expected pass_number=2, got %d", pass.PassNumber)
	}
	if pass.FinalExploitability != "confirmed" {
		t.Errorf("expected final_exploitability=confirmed, got %s", pass.FinalExploitability)
	}
}

func TestConfirmFindings_Downgrade(t *testing.T) {
	callCount := 0
	provider := &sequenceProvider{
		responses: []string{
			`{"payloads": [{"value": "test", "position": "body", "parameter": "id", "rationale": "test", "expected_result": "test"}]}`,
			`{"final_exploitability": "false_positive", "final_confidence": "high", "combined_analysis": "Not exploitable"}`,
		},
		callCount: &callCount,
	}

	v := NewLLMVerifier(provider, defaultConfig(), newNoopEngine(), newNoopAnalyzer())

	findings := []types.Finding{
		makeVerifiedFinding("f-1", "GET", "/test", "medium", "medium", "xss", "likely", "medium"),
	}

	result, err := v.ConfirmFindings(context.Background(), findings, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := result[0]
	if f.Confidence != types.ConfidenceLow {
		t.Errorf("expected confidence=low after false_positive, got %s", f.Confidence)
	}
	if f.Verification.Exploitability != "false_positive" {
		t.Errorf("expected exploitability=false_positive, got %s", f.Verification.Exploitability)
	}
}

func TestConfirmFindings_EarlyExit(t *testing.T) {
	// All findings already confirmed+high — should exit without any LLM calls
	callCount := 0
	provider := &sequenceProvider{
		responses: []string{},
		callCount: &callCount,
	}

	v := NewLLMVerifier(provider, defaultConfig(), newNoopEngine(), newNoopAnalyzer())

	findings := []types.Finding{
		makeVerifiedFinding("f-1", "GET", "/test", "high", "high", "idor", "confirmed", "high"),
	}

	result, err := v.ConfirmFindings(context.Background(), findings, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if *provider.callCount != 0 {
		t.Errorf("expected 0 LLM calls for already-confirmed finding, got %d", *provider.callCount)
	}
	if len(result[0].Verification.ConfirmationPasses) != 0 {
		t.Errorf("expected no confirmation passes, got %d", len(result[0].Verification.ConfirmationPasses))
	}
}

func TestConfirmFindings_MultiPass(t *testing.T) {
	callCount := 0
	provider := &sequenceProvider{
		responses: []string{
			// Pass 2: generate payloads
			`{"payloads": [{"value": "test1", "position": "body", "parameter": "id", "rationale": "test", "expected_result": "test"}]}`,
			// Pass 2: final verify — stays likely
			`{"final_exploitability": "likely", "final_confidence": "medium", "combined_analysis": "Still likely after pass 2"}`,
			// Pass 3: generate payloads
			`{"payloads": [{"value": "test2", "position": "body", "parameter": "id", "rationale": "test", "expected_result": "test"}]}`,
			// Pass 3: final verify — confirmed
			`{"final_exploitability": "confirmed", "final_confidence": "high", "combined_analysis": "Confirmed after pass 3"}`,
		},
		callCount: &callCount,
	}

	v := NewLLMVerifier(provider, defaultConfig(), newNoopEngine(), newNoopAnalyzer())

	findings := []types.Finding{
		makeVerifiedFinding("f-1", "GET", "/test", "high", "medium", "idor", "likely", "medium"),
	}

	result, err := v.ConfirmFindings(context.Background(), findings, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := result[0]
	if len(f.Verification.ConfirmationPasses) != 2 {
		t.Fatalf("expected 2 confirmation passes, got %d", len(f.Verification.ConfirmationPasses))
	}
	if f.Verification.ConfirmationPasses[0].PassNumber != 2 {
		t.Errorf("expected first pass number=2, got %d", f.Verification.ConfirmationPasses[0].PassNumber)
	}
	if f.Verification.ConfirmationPasses[1].PassNumber != 3 {
		t.Errorf("expected second pass number=3, got %d", f.Verification.ConfirmationPasses[1].PassNumber)
	}
	if f.Verification.Exploitability != "confirmed" {
		t.Errorf("expected final exploitability=confirmed, got %s", f.Verification.Exploitability)
	}
}

func TestConfirmFindings_NoEngine(t *testing.T) {
	provider := &mockProvider{}
	v := NewLLMVerifier(provider, defaultConfig(), nil, nil)

	findings := []types.Finding{
		makeVerifiedFinding("f-1", "GET", "/test", "high", "medium", "idor", "likely", "medium"),
	}

	_, err := v.ConfirmFindings(context.Background(), findings, 2)
	if err == nil {
		t.Error("expected error when engine is nil")
	}
}

func TestConfirmFindings_MaxPassesCapped(t *testing.T) {
	// Request 10 passes — should cap at 5 internally
	callCount := 0
	provider := &sequenceProvider{
		responses: []string{
			// We'll provide enough responses for up to 4 extra passes (5-1=4), but the finding
			// gets confirmed on pass 2, so only 2 LLM calls (generate + verify) should happen.
			`{"payloads": [{"value": "test", "position": "body", "parameter": "id", "rationale": "test", "expected_result": "test"}]}`,
			`{"final_exploitability": "confirmed", "final_confidence": "high", "combined_analysis": "Confirmed"}`,
		},
		callCount: &callCount,
	}

	v := NewLLMVerifier(provider, defaultConfig(), newNoopEngine(), newNoopAnalyzer())

	findings := []types.Finding{
		makeVerifiedFinding("f-1", "GET", "/test", "high", "medium", "idor", "likely", "medium"),
	}

	result, err := v.ConfirmFindings(context.Background(), findings, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Finding was confirmed on pass 2, so pass 3 should find no candidates and stop
	f := result[0]
	if f.Verification.Exploitability != "confirmed" {
		t.Errorf("expected confirmed, got %s", f.Verification.Exploitability)
	}
	// Should only have 1 confirmation pass (pass 2), then early exit
	if len(f.Verification.ConfirmationPasses) != 1 {
		t.Errorf("expected 1 confirmation pass, got %d", len(f.Verification.ConfirmationPasses))
	}
}

func TestGenerateConfirmationPayloads_Sanitization(t *testing.T) {
	// LLM returns a dangerous payload — should be filtered out
	callCount := 0
	provider := &sequenceProvider{
		responses: []string{
			`{"payloads": [
				{"value": "file:///etc/passwd", "position": "body", "parameter": "id", "rationale": "path traversal", "expected_result": "file contents"},
				{"value": "valid-payload", "position": "body", "parameter": "id", "rationale": "safe test", "expected_result": "error"}
			]}`,
		},
		callCount: &callCount,
	}

	v := NewLLMVerifier(provider, defaultConfig(), nil, nil)

	candidates := []types.Finding{
		makeVerifiedFinding("f-1", "GET", "/test", "high", "medium", "sqli", "likely", "medium"),
	}

	result := v.generateConfirmationPayloads(context.Background(), candidates)

	reqs, ok := result["f-1"]
	if !ok {
		t.Fatal("expected payloads for f-1")
	}
	// Only the valid payload should remain
	if len(reqs) != 1 {
		t.Fatalf("expected 1 payload after sanitization, got %d", len(reqs))
	}
	if reqs[0].Payload.Value != "valid-payload" {
		t.Errorf("expected valid-payload, got %s", reqs[0].Payload.Value)
	}
}

// sequenceProvider returns responses in order for successive AnalyzeWithSystem calls.
type sequenceProvider struct {
	responses []string
	callCount *int
	err       error
}

func (s *sequenceProvider) Analyze(_ context.Context, _ string) (string, error) {
	return s.nextResponse()
}

func (s *sequenceProvider) AnalyzeStructured(_ context.Context, _ string, result interface{}) error {
	resp, err := s.nextResponse()
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(resp), result)
}

func (s *sequenceProvider) AnalyzeWithSystem(_ context.Context, _, _ string) (string, error) {
	return s.nextResponse()
}

func (s *sequenceProvider) Name() string  { return "sequence-mock" }
func (s *sequenceProvider) Model() string { return "sequence-model" }

func (s *sequenceProvider) nextResponse() (string, error) {
	if s.err != nil {
		return "", s.err
	}
	idx := *s.callCount
	*s.callCount++
	if idx < len(s.responses) {
		return s.responses[idx], nil
	}
	return `{}`, nil
}

// mockFuzzExecutor implements FuzzExecutor and returns no results.
type mockFuzzExecutor struct{}

func (m *mockFuzzExecutor) Fuzz(_ context.Context, _ []payloads.FuzzRequest) <-chan *fuzzer.FuzzResult {
	ch := make(chan *fuzzer.FuzzResult)
	close(ch)
	return ch
}

func (m *mockFuzzExecutor) GetBaseline(_ context.Context, _ types.Endpoint) (*types.HTTPResponse, error) {
	return nil, nil
}

// mockResponseAnalyzer implements ResponseAnalyzer and returns no findings.
type mockResponseAnalyzer struct{}

func (m *mockResponseAnalyzer) AnalyzeResult(_ *fuzzer.FuzzResult, _ *types.HTTPResponse) []types.Finding {
	return nil
}

func newNoopEngine() FuzzExecutor {
	return &mockFuzzExecutor{}
}

func newNoopAnalyzer() ResponseAnalyzer {
	return &mockResponseAnalyzer{}
}

func TestChunkFindings(t *testing.T) {
	tests := []struct {
		name       string
		count      int
		size       int
		wantChunks int
		wantLast   int // expected length of last chunk
	}{
		{"empty slice", 0, 5, 0, 0},
		{"smaller than batch", 3, 5, 1, 3},
		{"exact batch size", 5, 5, 1, 5},
		{"larger than batch", 7, 5, 2, 2},
		{"multiple full batches", 10, 5, 2, 5},
		{"default size when zero", 7, 0, 2, 2}, // defaults to 5
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := make([]types.Finding, tt.count)
			for i := range findings {
				findings[i] = types.Finding{ID: fmt.Sprintf("f-%d", i)}
			}

			chunks := chunkFindings(findings, tt.size)

			if len(chunks) != tt.wantChunks {
				t.Fatalf("chunkFindings(%d, %d) returned %d chunks, want %d", tt.count, tt.size, len(chunks), tt.wantChunks)
			}

			if tt.wantChunks > 0 {
				last := chunks[len(chunks)-1]
				if len(last) != tt.wantLast {
					t.Errorf("last chunk has %d items, want %d", len(last), tt.wantLast)
				}
			}

			// Verify all findings are present
			total := 0
			for _, c := range chunks {
				total += len(c)
			}
			if total != tt.count {
				t.Errorf("total items across chunks = %d, want %d", total, tt.count)
			}
		})
	}
}
