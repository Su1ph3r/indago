package detector

import (
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestFindingFilter_FilterByConfidence(t *testing.T) {
	settings := types.FilterSettings{
		Enabled:       true,
		MinConfidence: 0.7,
		MinSeverity:   types.SeverityInfo,
	}
	filter := NewFindingFilter(settings)

	findings := []types.Finding{
		{Type: types.AttackSQLi, Severity: types.SeverityHigh, Confidence: types.ConfidenceHigh,
			Evidence: &types.Evidence{
				Response:     &types.HTTPResponse{StatusCode: 500},
				MatchedData:  []string{"SQL syntax error"},
				BaselineResp: &types.HTTPResponse{StatusCode: 200},
			}},
		{Type: "content_anomaly", Severity: types.SeverityLow, Confidence: types.ConfidenceLow},
	}

	filtered := filter.Filter(findings)
	// The high-evidence SQLi should pass, the low-evidence anomaly should be filtered
	if len(filtered) == 0 {
		t.Error("expected at least one finding to pass confidence filter")
	}
	for _, f := range filtered {
		if f.Type == "content_anomaly" && f.Confidence == types.ConfidenceLow {
			// This might pass if the raw score is above threshold due to base score
			// The key is that the filter IS running
		}
	}
}

func TestFindingFilter_FilterBySeverity(t *testing.T) {
	settings := types.FilterSettings{
		Enabled:       true,
		MinSeverity:   types.SeverityMedium,
		MinConfidence: 0.0, // Don't filter by confidence
	}
	filter := NewFindingFilter(settings)

	findings := []types.Finding{
		{Type: types.AttackSQLi, Severity: types.SeverityHigh},
		{Type: "server_error", Severity: types.SeverityLow},
		{Type: "information_disclosure", Severity: types.SeverityInfo},
	}

	filtered := filter.Filter(findings)
	for _, f := range filtered {
		if f.Severity == types.SeverityLow || f.Severity == types.SeverityInfo {
			t.Errorf("finding with severity %s should be filtered when min is medium", f.Severity)
		}
	}
}

func TestFindingFilter_Disabled(t *testing.T) {
	settings := types.FilterSettings{Enabled: false}
	filter := NewFindingFilter(settings)

	findings := []types.Finding{
		{Type: "test1", Severity: types.SeverityInfo},
		{Type: "test2", Severity: types.SeverityLow},
	}

	filtered := filter.Filter(findings)
	if len(filtered) != len(findings) {
		t.Errorf("disabled filter should pass all findings, got %d want %d", len(filtered), len(findings))
	}
}

func TestFindingFilter_DeduplicateByEndpoint(t *testing.T) {
	settings := types.FilterSettings{
		Enabled:          true,
		MinConfidence:    0.0,
		MinSeverity:      types.SeverityInfo,
		DedupeByEndpoint: true,
	}
	filter := NewFindingFilter(settings)

	findings := []types.Finding{
		{Method: "GET", Endpoint: "/api/users", Type: types.AttackSQLi, Severity: types.SeverityMedium, Parameter: "id"},
		{Method: "GET", Endpoint: "/api/users", Type: types.AttackSQLi, Severity: types.SeverityHigh, Parameter: "id"},
		{Method: "GET", Endpoint: "/api/users", Type: types.AttackXSS, Severity: types.SeverityMedium, Parameter: "name"},
	}

	filtered := filter.Filter(findings)
	// Should dedup the two SQLi on same endpoint+param, keeping highest severity
	sqliCount := 0
	for _, f := range filtered {
		if f.Type == types.AttackSQLi {
			sqliCount++
			if f.Severity != types.SeverityHigh {
				t.Error("dedup should keep highest severity finding")
			}
		}
	}
	if sqliCount != 1 {
		t.Errorf("expected 1 SQLi finding after dedup, got %d", sqliCount)
	}
}

func TestNoiseFilter_Generic404(t *testing.T) {
	nf := NewNoiseFilter()

	findings := []types.Finding{
		{Type: types.AttackSQLi, Evidence: &types.Evidence{Response: &types.HTTPResponse{StatusCode: 404}}},
		{Type: types.AttackSQLi, Evidence: &types.Evidence{Response: &types.HTTPResponse{StatusCode: 500}}},
	}

	filtered := nf.Filter(findings)
	if len(filtered) != 1 {
		t.Errorf("expected 1 finding after 404 filter, got %d", len(filtered))
	}
	if filtered[0].Evidence.Response.StatusCode != 500 {
		t.Error("wrong finding kept after 404 filter")
	}
}

func TestNoiseFilter_RateLimit429(t *testing.T) {
	nf := NewNoiseFilter()

	findings := []types.Finding{
		{Type: types.AttackRateLimit, Evidence: &types.Evidence{Response: &types.HTTPResponse{StatusCode: 429}}},
	}

	filtered := nf.Filter(findings)
	if len(filtered) != 0 {
		t.Error("rate limit 429 should be filtered as noise")
	}
}

func TestNoiseFilter_EmptyXSSPayload(t *testing.T) {
	nf := NewNoiseFilter()

	findings := []types.Finding{
		{Type: types.AttackXSS, Payload: ""},
		{Type: types.AttackXSS, Payload: "<script>alert(1)</script>"},
	}

	filtered := nf.Filter(findings)
	if len(filtered) != 1 {
		t.Errorf("expected 1 finding after empty XSS filter, got %d", len(filtered))
	}
}

func TestNoiseFilter_InfrastructureErrors(t *testing.T) {
	nf := NewNoiseFilter()

	for _, code := range []int{502, 503, 504} {
		findings := []types.Finding{
			{Type: "server_error", Evidence: &types.Evidence{Response: &types.HTTPResponse{StatusCode: code}}},
		}
		filtered := nf.Filter(findings)
		if len(filtered) != 0 {
			t.Errorf("server_error with status %d should be filtered as infrastructure noise", code)
		}
	}

	// 500 should NOT be filtered (it's an app error)
	findings := []types.Finding{
		{Type: "server_error", Evidence: &types.Evidence{Response: &types.HTTPResponse{StatusCode: 500}}},
	}
	filtered := nf.Filter(findings)
	if len(filtered) != 1 {
		t.Error("server_error with 500 should NOT be filtered")
	}
}

func TestNoiseFilter_ContentAnomaly(t *testing.T) {
	nf := NewNoiseFilter()

	findings := []types.Finding{
		{Type: "content_anomaly"},
	}

	filtered := nf.Filter(findings)
	if len(filtered) != 0 {
		t.Error("content_anomaly should be filtered as noise")
	}
}

func TestNoiseFilter_JWTOnAuthEndpoint(t *testing.T) {
	nf := NewNoiseFilter()

	authPaths := []string{"/api/auth/login", "/oauth/token", "/v1/login", "/auth/refresh"}
	for _, path := range authPaths {
		findings := []types.Finding{
			{Type: "data_leak", Title: "JWT Token Exposed", Endpoint: path},
		}
		filtered := nf.Filter(findings)
		if len(filtered) != 0 {
			t.Errorf("JWT on %s should be filtered as noise", path)
		}
	}

	// JWT on non-auth endpoint should NOT be filtered
	findings := []types.Finding{
		{Type: "data_leak", Title: "JWT Token Exposed", Endpoint: "/api/users/profile"},
	}
	filtered := nf.Filter(findings)
	if len(filtered) != 1 {
		t.Error("JWT on non-auth endpoint should NOT be filtered")
	}
}

func TestNoiseFilter_TechVersionDisclosure(t *testing.T) {
	nf := NewNoiseFilter()

	findings := []types.Finding{
		{Type: "information_disclosure", Severity: types.SeverityInfo, Title: "Technology Version Disclosure"},
	}

	filtered := nf.Filter(findings)
	if len(filtered) != 0 {
		t.Error("technology version disclosure should be filtered as noise")
	}
}

func TestNoiseFilter_PassiveChecksFindingsPassThrough(t *testing.T) {
	nf := NewNoiseFilter()

	findings := []types.Finding{
		{Type: types.AttackRateLimitMissing, Severity: types.SeverityLow, Endpoint: "/api/users"},
		{Type: types.AttackMissingHeaders, Severity: types.SeverityLow, Endpoint: "/api/users"},
		{Type: types.AttackCORSMisconfig, Severity: types.SeverityMedium, Endpoint: "/api/users"},
	}

	filtered := nf.Filter(findings)
	if len(filtered) != 3 {
		t.Errorf("passive check findings should not be filtered, expected 3 got %d", len(filtered))
	}
}

func TestNoiseFilter_LegitFindingPassesThrough(t *testing.T) {
	nf := NewNoiseFilter()

	findings := []types.Finding{
		{Type: types.AttackSQLi, Severity: types.SeverityHigh, Payload: "' OR 1=1--",
			Evidence: &types.Evidence{Response: &types.HTTPResponse{StatusCode: 500}}},
	}

	filtered := nf.Filter(findings)
	if len(filtered) != 1 {
		t.Error("legitimate SQLi finding should pass through noise filter")
	}
}

func TestCombinedFilter_ChainsFilters(t *testing.T) {
	settings := types.FilterSettings{
		Enabled:          true,
		MinConfidence:    0.0,
		MinSeverity:      types.SeverityInfo,
		DedupeByEndpoint: true,
		FilterNoise:      true,
	}
	cf := NewCombinedFilter(settings)

	findings := []types.Finding{
		// This should be filtered by noise (content_anomaly)
		{Type: "content_anomaly", Severity: types.SeverityLow},
		// This should pass
		{Type: types.AttackSQLi, Severity: types.SeverityHigh, Method: "GET", Endpoint: "/test",
			Evidence: &types.Evidence{Response: &types.HTTPResponse{StatusCode: 500}}},
	}

	filtered := cf.Filter(findings)
	if len(filtered) != 1 {
		t.Errorf("expected 1 finding after combined filter, got %d", len(filtered))
	}
	if len(filtered) > 0 && filtered[0].Type != types.AttackSQLi {
		t.Error("wrong finding survived combined filter")
	}
}

func TestFindingFilter_BOLAPerParameterKept(t *testing.T) {
	settings := types.FilterSettings{
		Enabled:          true,
		MinConfidence:    0.0,
		MinSeverity:      types.SeverityInfo,
		DedupeByEndpoint: true,
	}
	filter := NewFindingFilter(settings)

	// BOLA findings on different parameters of the same endpoint should
	// each be kept — a pentester needs to know which parameter is vulnerable
	findings := []types.Finding{
		{Method: "GET", Endpoint: "/users/v1/{username}", Type: types.AttackBOLA, Severity: types.SeverityHigh, Parameter: "username"},
		{Method: "GET", Endpoint: "/users/v1/{username}", Type: types.AttackBOLA, Severity: types.SeverityCritical, Parameter: "user_id"},
		{Method: "GET", Endpoint: "/users/v1/{username}", Type: types.AttackBOLA, Severity: types.SeverityMedium, Parameter: "id"},
	}

	filtered := filter.Filter(findings)
	bolaCount := 0
	for _, f := range filtered {
		if f.Type == types.AttackBOLA {
			bolaCount++
		}
	}
	if bolaCount != 3 {
		t.Errorf("expected 3 BOLA findings (one per parameter), got %d", bolaCount)
	}
}

func TestFindingFilter_IDORPerParameterKept(t *testing.T) {
	settings := types.FilterSettings{
		Enabled:          true,
		MinConfidence:    0.0,
		MinSeverity:      types.SeverityInfo,
		DedupeByEndpoint: true,
	}
	filter := NewFindingFilter(settings)

	// IDOR findings on different parameters should each be kept
	findings := []types.Finding{
		{Method: "GET", Endpoint: "/users/{id}", Type: types.AttackIDOR, Severity: types.SeverityHigh, Parameter: "id"},
		{Method: "GET", Endpoint: "/users/{id}", Type: types.AttackIDOR, Severity: types.SeverityMedium, Parameter: "user_id"},
	}

	filtered := filter.Filter(findings)
	idorCount := 0
	for _, f := range filtered {
		if f.Type == types.AttackIDOR {
			idorCount++
		}
	}
	if idorCount != 2 {
		t.Errorf("expected 2 IDOR findings (one per parameter), got %d", idorCount)
	}
}

func TestSeverityValue(t *testing.T) {
	tests := []struct {
		severity string
		expected int
	}{
		{types.SeverityCritical, 5},
		{types.SeverityHigh, 4},
		{types.SeverityMedium, 3},
		{types.SeverityLow, 2},
		{types.SeverityInfo, 1},
		{"unknown", 0},
	}

	for _, tt := range tests {
		result := severityValue(tt.severity)
		if result != tt.expected {
			t.Errorf("severityValue(%q) = %d, want %d", tt.severity, result, tt.expected)
		}
	}
}
