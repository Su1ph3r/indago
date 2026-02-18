package benchmark

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestLoadGroundTruth(t *testing.T) {
	// Find the ground truth file relative to project root
	path := findTestFile(t, "testdata/vampi/ground_truth.yaml")

	gt, err := LoadGroundTruth(path)
	if err != nil {
		t.Fatalf("LoadGroundTruth: %v", err)
	}

	if len(gt.Vulnerabilities) != 16 {
		t.Errorf("expected 16 vulnerabilities, got %d", len(gt.Vulnerabilities))
	}

	// Verify first entry
	v := gt.Vulnerabilities[0]
	if v.ID != "001" {
		t.Errorf("expected ID '001', got %q", v.ID)
	}
	if v.Class != "sqli" {
		t.Errorf("expected class 'sqli', got %q", v.Class)
	}
	if v.MinMatches != 1 {
		t.Errorf("expected min_matches 1, got %d", v.MinMatches)
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"/users/v1/*", "/users/v1/admin", true},
		{"/users/v1/*", "/users/v1/foo/bar", false},
		{"/users/v1/*/password", "/users/v1/admin/password", true},
		{"/users/v1/*/password", "/users/v1/admin/email", false},
		{"/users/v1/_debug", "/users/v1/_debug", true},
		{"/users/v1/_debug", "/users/v1/other", false},
		// {param} template matching
		{"/users/v1/{username}", "/users/v1/admin", true},
		{"/users/v1/{username}/password", "/users/v1/admin/password", true},
		{"/users/v1/{username}/password", "/users/v1/{username}/password", true},
		// Both sides can have templates
		{"/users/v1/*", "/users/v1/{username}", true},
		{"/users/v1/{id}", "/users/v1/{username}", true},
	}

	for _, tt := range tests {
		got := matchGlob(tt.pattern, tt.value)
		if got != tt.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
		}
	}
}

func TestMatchFindings_TruePositive(t *testing.T) {
	gt := &GroundTruth{
		Vulnerabilities: []Vulnerability{
			{
				ID:    "001",
				Name:  "SQL Injection",
				Class: "sqli",
				MatchRules: MatchRules{
					FindingTypes:    []string{"sqli"},
					EndpointPattern: "/users/v1/*",
					Method:          "GET",
				},
				MinMatches: 1,
			},
		},
	}

	findings := []types.Finding{
		{
			Type:       "sqli",
			Endpoint:   "/users/v1/admin",
			Method:     "GET",
			Severity:   "high",
			Confidence: "high",
		},
	}

	results, fps := MatchFindings(gt, findings)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Matched {
		t.Error("expected vuln 001 to be matched")
	}
	if len(fps) != 0 {
		t.Errorf("expected 0 false positives, got %d", len(fps))
	}
}

func TestMatchFindings_FalseNegative(t *testing.T) {
	gt := &GroundTruth{
		Vulnerabilities: []Vulnerability{
			{
				ID:    "001",
				Name:  "SQL Injection",
				Class: "sqli",
				MatchRules: MatchRules{
					FindingTypes:    []string{"sqli"},
					EndpointPattern: "/users/v1/*",
				},
				MinMatches: 1,
			},
		},
	}

	// No SQLi findings, only XSS
	findings := []types.Finding{
		{
			Type:     "xss",
			Endpoint: "/users/v1/admin",
			Method:   "GET",
		},
	}

	results, fps := MatchFindings(gt, findings)

	if results[0].Matched {
		t.Error("expected vuln 001 to NOT be matched (wrong finding type)")
	}
	if len(fps) != 1 {
		t.Errorf("expected 1 false positive, got %d", len(fps))
	}
}

func TestMatchFindings_MinMatches(t *testing.T) {
	gt := &GroundTruth{
		Vulnerabilities: []Vulnerability{
			{
				ID:    "003",
				Name:  "BOLA on multiple endpoints",
				Class: "bola",
				MatchRules: MatchRules{
					FindingTypes:    []string{"bola", "idor"},
					EndpointPattern: "/users/v1/*",
				},
				MinMatches: 2,
			},
		},
	}

	// Only 1 BOLA finding — should be false negative
	findings := []types.Finding{
		{
			Type:     "bola",
			Endpoint: "/users/v1/admin",
			Method:   "PUT",
		},
	}

	results, _ := MatchFindings(gt, findings)
	if results[0].Matched {
		t.Error("expected vuln 003 to NOT be matched (only 1 match, needs 2)")
	}

	// Add a second BOLA finding — should now match
	findings = append(findings, types.Finding{
		Type:     "idor",
		Endpoint: "/users/v1/other",
		Method:   "GET",
	})

	results, _ = MatchFindings(gt, findings)
	if !results[0].Matched {
		t.Error("expected vuln 003 to be matched (2 matches)")
	}
}

func TestSeverityFiltering(t *testing.T) {
	gt := &GroundTruth{
		Vulnerabilities: []Vulnerability{
			{
				ID:    "001",
				Name:  "Test",
				Class: "sqli",
				MatchRules: MatchRules{
					FindingTypes: []string{"sqli"},
					MinSeverity:  "medium",
				},
				MinMatches: 1,
			},
		},
	}

	// Info severity should not match when min is medium
	findings := []types.Finding{
		{Type: "sqli", Severity: "info", Endpoint: "/test"},
	}

	results, _ := MatchFindings(gt, findings)
	if results[0].Matched {
		t.Error("info severity should not match when min_severity is medium")
	}

	// High severity should match
	findings[0].Severity = "high"
	results, _ = MatchFindings(gt, findings)
	if !results[0].Matched {
		t.Error("high severity should match when min_severity is medium")
	}
}

// findTestFile walks up from the test directory to find a file relative to the project root.
func findTestFile(t *testing.T, relativePath string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	for {
		candidate := filepath.Join(dir, relativePath)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find %s in parent directories", relativePath)
		}
		dir = parent
	}
}
