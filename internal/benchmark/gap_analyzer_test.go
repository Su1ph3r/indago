package benchmark

import (
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestAnalyzeGaps_EndpointNotScanned(t *testing.T) {
	fn := []MatchResult{
		{
			Vuln: Vulnerability{
				ID:       "001",
				Name:     "SQL Injection",
				Class:    "sqli",
				Endpoint: "/users/v1/{username}",
				Method:   "GET",
			},
		},
	}

	// No endpoints scanned at all
	gaps := AnalyzeGaps(fn, nil, "", nil)

	if len(gaps) != 1 {
		t.Fatalf("expected 1 gap, got %d", len(gaps))
	}
	if gaps[0].Gap != GapEndpointNotScanned {
		t.Errorf("expected GAP_ENDPOINT_NOT_SCANNED, got %s", gaps[0].Gap)
	}
}

func TestAnalyzeGaps_NoPayloads(t *testing.T) {
	fn := []MatchResult{
		{
			Vuln: Vulnerability{
				ID:       "006",
				Name:     "User Enumeration",
				Class:    "enumeration",
				Endpoint: "/users/v1/login",
				Method:   "POST",
			},
		},
	}

	scanned := []string{"/users/v1/login"}
	gaps := AnalyzeGaps(fn, nil, "", scanned)

	if len(gaps) != 1 {
		t.Fatalf("expected 1 gap, got %d", len(gaps))
	}
	// "enumeration" is not in known attack classes, so should be GapNewVulnClass
	if gaps[0].Gap != GapNewVulnClass {
		t.Errorf("expected GAP_NEW_VULN_CLASS, got %s", gaps[0].Gap)
	}
}

func TestAnalyzeGaps_FilteredOut(t *testing.T) {
	fn := []MatchResult{
		{
			Vuln: Vulnerability{
				ID:       "005",
				Name:     "Data Exposure",
				Class:    "data_exposure",
				Endpoint: "/users/v1/_debug",
				Method:   "GET",
				MatchRules: MatchRules{
					FindingTypes:    []string{"data_exposure"},
					EndpointPattern: "/users/v1/_debug",
					Method:          "GET",
				},
			},
		},
	}

	// There are findings for this endpoint, but wrong type
	allFindings := []types.Finding{
		{
			Type:     "xss",
			Endpoint: "/users/v1/_debug",
			Method:   "GET",
		},
	}

	scanned := []string{"/users/v1/_debug"}
	gaps := AnalyzeGaps(fn, allFindings, "", scanned)

	if len(gaps) != 1 {
		t.Fatalf("expected 1 gap, got %d", len(gaps))
	}
	if gaps[0].Gap != GapFilteredOut {
		t.Errorf("expected GAP_FILTERED_OUT, got %s", gaps[0].Gap)
	}
}

func TestClassToPayloadTypes(t *testing.T) {
	tests := []struct {
		class    string
		expected []string
	}{
		{"sqli", []string{"sqli", "sql_injection", "sql"}},
		{"bola", []string{"bola", "idor", "bfla", "auth_bypass"}},
		{"unknown_class", []string{"unknown_class"}},
	}

	for _, tt := range tests {
		got := classToPayloadTypes(tt.class)
		if len(got) != len(tt.expected) {
			t.Errorf("classToPayloadTypes(%q) returned %d items, expected %d", tt.class, len(got), len(tt.expected))
		}
	}
}

func TestIsKnownAttackClass(t *testing.T) {
	if !isKnownAttackClass("sqli") {
		t.Error("sqli should be a known attack class")
	}
	if !isKnownAttackClass("bola") {
		t.Error("bola should be a known attack class")
	}
	if isKnownAttackClass("enumeration") {
		t.Error("enumeration should NOT be a known attack class")
	}
	if isKnownAttackClass("foo_bar") {
		t.Error("foo_bar should NOT be a known attack class")
	}
}
