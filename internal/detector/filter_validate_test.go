package detector

import (
	"strings"
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestDedup_ConfidenceTiebreaker(t *testing.T) {
	settings := types.FilterSettings{
		Enabled:          true,
		MinConfidence:    0.0,
		MinSeverity:      types.SeverityInfo,
		DedupeByEndpoint: true,
	}
	filter := NewFindingFilter(settings)

	findings := []types.Finding{
		{Method: "GET", Endpoint: "/api/users", Type: types.AttackSQLi, Severity: types.SeverityHigh, Confidence: types.ConfidenceLow, Parameter: "id"},
		{Method: "GET", Endpoint: "/api/users", Type: types.AttackSQLi, Severity: types.SeverityHigh, Confidence: types.ConfidenceHigh, Parameter: "id",
			Evidence: &types.Evidence{
				Response:    &types.HTTPResponse{StatusCode: 500},
				MatchedData: []string{"SQL syntax error"},
			}},
	}

	filtered := filter.Filter(findings)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(filtered))
	}
	// The filter recalculates confidence, but the evidence-rich finding
	// should win. Check that it has the evidence we expect.
	if filtered[0].Evidence == nil || len(filtered[0].Evidence.MatchedData) == 0 {
		t.Error("expected the evidence-rich finding to survive dedup")
	}
}

func TestDedup_EvidenceRichnessTiebreaker(t *testing.T) {
	settings := types.FilterSettings{
		Enabled:          true,
		MinConfidence:    0.0,
		MinSeverity:      types.SeverityInfo,
		DedupeByEndpoint: true,
	}
	filter := NewFindingFilter(settings)

	findings := []types.Finding{
		{Method: "GET", Endpoint: "/api/data", Type: types.AttackSQLi, Severity: types.SeverityHigh, Confidence: types.ConfidenceHigh, Parameter: "q"},
		{Method: "GET", Endpoint: "/api/data", Type: types.AttackSQLi, Severity: types.SeverityHigh, Confidence: types.ConfidenceHigh, Parameter: "q",
			Evidence: &types.Evidence{
				Response:     &types.HTTPResponse{StatusCode: 500},
				MatchedData:  []string{"error near"},
				BaselineResp: &types.HTTPResponse{StatusCode: 200},
			}},
	}

	filtered := filter.Filter(findings)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(filtered))
	}
	if filtered[0].Evidence == nil || filtered[0].Evidence.BaselineResp == nil {
		t.Error("expected the evidence-rich finding to win tiebreak")
	}
}

func TestDedup_PayloadConfirmationCount(t *testing.T) {
	settings := types.FilterSettings{
		Enabled:          true,
		MinConfidence:    0.0,
		MinSeverity:      types.SeverityInfo,
		DedupeByEndpoint: true,
	}
	filter := NewFindingFilter(settings)

	findings := []types.Finding{
		{Method: "GET", Endpoint: "/users/v1/{username}", Type: types.AttackSQLi, Severity: types.SeverityHigh, Confidence: types.ConfidenceHigh, Parameter: "username", Description: "SQL injection detected"},
		{Method: "GET", Endpoint: "/users/v1/{username}", Type: types.AttackSQLi, Severity: types.SeverityMedium, Confidence: types.ConfidenceMedium, Parameter: "username"},
		{Method: "GET", Endpoint: "/users/v1/{username}", Type: types.AttackSQLi, Severity: types.SeverityHigh, Confidence: types.ConfidenceLow, Parameter: "username"},
		{Method: "GET", Endpoint: "/users/v1/{username}", Type: types.AttackSQLi, Severity: types.SeverityMedium, Confidence: types.ConfidenceLow, Parameter: "username"},
		{Method: "GET", Endpoint: "/users/v1/{username}", Type: types.AttackSQLi, Severity: types.SeverityHigh, Confidence: types.ConfidenceMedium, Parameter: "username"},
	}

	filtered := filter.Filter(findings)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding after dedup, got %d", len(filtered))
	}
	if !strings.Contains(filtered[0].Description, "Confirmed by 5 payloads") {
		t.Errorf("expected 'Confirmed by 5 payloads' in description, got: %q", filtered[0].Description)
	}
}

func TestDedup_SingleFindingNoConfirmationTag(t *testing.T) {
	settings := types.FilterSettings{
		Enabled:          true,
		MinConfidence:    0.0,
		MinSeverity:      types.SeverityInfo,
		DedupeByEndpoint: true,
	}
	filter := NewFindingFilter(settings)

	findings := []types.Finding{
		{Method: "GET", Endpoint: "/api/single", Type: types.AttackXSS, Severity: types.SeverityMedium, Parameter: "q", Description: "XSS found"},
	}

	filtered := filter.Filter(findings)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(filtered))
	}
	if strings.Contains(filtered[0].Description, "Confirmed by") {
		t.Errorf("single finding should not get confirmation tag, got: %q", filtered[0].Description)
	}
}

func TestConfidenceValue(t *testing.T) {
	tests := []struct {
		confidence string
		expected   int
	}{
		{types.ConfidenceHigh, 3},
		{types.ConfidenceMedium, 2},
		{types.ConfidenceLow, 1},
		{"", 0},
		{"unknown", 0},
	}
	for _, tt := range tests {
		got := confidenceValue(tt.confidence)
		if got != tt.expected {
			t.Errorf("confidenceValue(%q) = %d, want %d", tt.confidence, got, tt.expected)
		}
	}
}

func TestEvidenceRichness(t *testing.T) {
	tests := []struct {
		name     string
		finding  types.Finding
		expected int
	}{
		{"no evidence", types.Finding{}, 0},
		{"evidence only", types.Finding{Evidence: &types.Evidence{}}, 1},
		{"evidence + matched data", types.Finding{Evidence: &types.Evidence{MatchedData: []string{"data"}}}, 2},
		{"evidence + baseline", types.Finding{Evidence: &types.Evidence{BaselineResp: &types.HTTPResponse{}}}, 2},
		{"all evidence", types.Finding{Evidence: &types.Evidence{MatchedData: []string{"data"}, BaselineResp: &types.HTTPResponse{}}}, 3},
	}
	for _, tt := range tests {
		got := evidenceRichness(tt.finding)
		if got != tt.expected {
			t.Errorf("evidenceRichness(%s) = %d, want %d", tt.name, got, tt.expected)
		}
	}
}
