package importer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestLoadNubicustosFindings_Valid(t *testing.T) {
	data := types.NubicustosImport{
		ExportSource:  "nubicustos",
		ScanID:        "scan-cloud-001",
		CloudProvider: "aws",
		AccountID:     "123456789012",
		Findings: []types.NubicustosCloudFinding{
			{
				ID:          "nc-001",
				Type:        "s3_public",
				Severity:    "high",
				Resource:    "arn:aws:s3:::my-public-bucket",
				Region:      "us-east-1",
				Description: "S3 bucket is publicly accessible",
			},
			{
				ID:          "nc-002",
				Type:        "iam_overprivileged",
				Severity:    "critical",
				Resource:    "arn:aws:iam::123456789012:role/admin-role",
				Description: "IAM role has overprivileged policies",
			},
		},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nubicustos.json")
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("failed to marshal test data: %v", err)
	}
	if err := os.WriteFile(path, b, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	imp, err := LoadNubicustosFindings(path)
	if err != nil {
		t.Fatalf("LoadNubicustosFindings failed: %v", err)
	}

	if imp.ExportSource != "nubicustos" {
		t.Errorf("ExportSource = %q, want %q", imp.ExportSource, "nubicustos")
	}
	if imp.ScanID != "scan-cloud-001" {
		t.Errorf("ScanID = %q, want %q", imp.ScanID, "scan-cloud-001")
	}
	if imp.CloudProvider != "aws" {
		t.Errorf("CloudProvider = %q, want %q", imp.CloudProvider, "aws")
	}
	if len(imp.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(imp.Findings))
	}
	if imp.Findings[0].Type != "s3_public" {
		t.Errorf("Findings[0].Type = %q, want %q", imp.Findings[0].Type, "s3_public")
	}
}

func TestLoadNubicustosFindings_EmptySource(t *testing.T) {
	// Empty export_source should be accepted (treated as nubicustos)
	data := types.NubicustosImport{
		Findings: []types.NubicustosCloudFinding{
			{
				ID:          "nc-001",
				Type:        "s3_public",
				Severity:    "high",
				Resource:    "arn:aws:s3:::bucket",
				Description: "Public bucket",
			},
		},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nubicustos.json")
	b, _ := json.Marshal(data)
	os.WriteFile(path, b, 0644)

	imp, err := LoadNubicustosFindings(path)
	if err != nil {
		t.Fatalf("expected success for empty export_source, got: %v", err)
	}
	if len(imp.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(imp.Findings))
	}
}

func TestLoadNubicustosFindings_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.json")
	os.WriteFile(path, []byte("{invalid json"), 0644)

	_, err := LoadNubicustosFindings(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestLoadNubicustosFindings_NonexistentFile(t *testing.T) {
	_, err := LoadNubicustosFindings("/nonexistent/path/nubicustos.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestLoadNubicustosFindings_EmptyFindings(t *testing.T) {
	data := types.NubicustosImport{
		ExportSource: "nubicustos",
		Findings:     []types.NubicustosCloudFinding{},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "empty.json")
	b, _ := json.Marshal(data)
	os.WriteFile(path, b, 0644)

	_, err := LoadNubicustosFindings(path)
	if err == nil {
		t.Fatal("expected error for empty findings, got nil")
	}
}

func TestLoadNubicustosFindings_WrongSource(t *testing.T) {
	data := types.NubicustosImport{
		ExportSource: "wrong-tool",
		Findings: []types.NubicustosCloudFinding{
			{
				ID:          "nc-001",
				Type:        "s3_public",
				Severity:    "high",
				Resource:    "arn:aws:s3:::bucket",
				Description: "Public bucket",
			},
		},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "wrong-source.json")
	b, _ := json.Marshal(data)
	os.WriteFile(path, b, 0644)

	_, err := LoadNubicustosFindings(path)
	if err == nil {
		t.Fatal("expected error for wrong export_source, got nil")
	}
}

func TestEnrichEndpointsFromCloud(t *testing.T) {
	imp := &types.NubicustosImport{
		Findings: []types.NubicustosCloudFinding{
			{
				ID:          "nc-001",
				Type:        "s3_public",
				Severity:    "high",
				Resource:    "arn:aws:s3:::bucket",
				Description: "Public S3 bucket",
			},
			{
				ID:          "nc-002",
				Type:        "iam_overprivileged",
				Severity:    "critical",
				Resource:    "arn:aws:iam::123456789012:role/admin",
				Description: "Overprivileged IAM role",
			},
		},
	}

	endpoints := []types.Endpoint{
		{
			Method: "GET",
			Path:   "/api/files",
		},
		{
			Method: "POST",
			Path:   "/api/upload",
			Tags:   []string{"existing_tag"},
		},
	}

	result := EnrichEndpointsFromCloud(imp, endpoints)

	if len(result) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(result))
	}

	// Both endpoints should have tags from both findings
	for i, ep := range result {
		// Check s3_public tags
		if !containsTag(ep.Tags, "cloud:s3_public") {
			t.Errorf("endpoint[%d] missing tag 'cloud:s3_public'", i)
		}
		if !containsTag(ep.Tags, "ssrf_target") {
			t.Errorf("endpoint[%d] missing tag 'ssrf_target'", i)
		}
		// Check iam tags
		if !containsTag(ep.Tags, "cloud:iam_issue") {
			t.Errorf("endpoint[%d] missing tag 'cloud:iam_issue'", i)
		}
		if !containsTag(ep.Tags, "auth_bypass_candidate") {
			t.Errorf("endpoint[%d] missing tag 'auth_bypass_candidate'", i)
		}

		// Check attack vectors
		if !containsAttack(ep.SuggestedAttacks, types.AttackSSRF) {
			t.Errorf("endpoint[%d] missing attack %q", i, types.AttackSSRF)
		}
		if !containsAttack(ep.SuggestedAttacks, types.AttackAuthBypass) {
			t.Errorf("endpoint[%d] missing attack %q", i, types.AttackAuthBypass)
		}
		if !containsAttack(ep.SuggestedAttacks, types.AttackBFLA) {
			t.Errorf("endpoint[%d] missing attack %q", i, types.AttackBFLA)
		}
	}

	// Second endpoint should still have its existing tag
	if !containsTag(result[1].Tags, "existing_tag") {
		t.Error("endpoint[1] lost existing tag 'existing_tag'")
	}
}

func TestMapCloudFindingToTags(t *testing.T) {
	tests := []struct {
		name     string
		finding  types.NubicustosCloudFinding
		expected []string
	}{
		{
			name:     "s3_public",
			finding:  types.NubicustosCloudFinding{Type: "s3_public"},
			expected: []string{"cloud:s3_public", "ssrf_target"},
		},
		{
			name:     "iam_overprivileged",
			finding:  types.NubicustosCloudFinding{Type: "iam_overprivileged"},
			expected: []string{"cloud:iam_issue", "auth_bypass_candidate"},
		},
		{
			name:     "security_group_open",
			finding:  types.NubicustosCloudFinding{Type: "security_group_open"},
			expected: []string{"cloud:open_sg", "network_exposure"},
		},
		{
			name:     "rds_public",
			finding:  types.NubicustosCloudFinding{Type: "rds_public"},
			expected: []string{"cloud:rds_public", "data_exposure"},
		},
		{
			name:     "lambda_exposed",
			finding:  types.NubicustosCloudFinding{Type: "lambda_exposed"},
			expected: []string{"cloud:lambda_issue", "injection_target"},
		},
		{
			name:     "unknown_type",
			finding:  types.NubicustosCloudFinding{Type: "custom_issue"},
			expected: []string{"cloud:custom_issue"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tags := mapCloudFindingToTags(tt.finding)
			if len(tags) != len(tt.expected) {
				t.Fatalf("expected %d tags, got %d: %v", len(tt.expected), len(tags), tags)
			}
			for i, exp := range tt.expected {
				if tags[i] != exp {
					t.Errorf("tags[%d] = %q, want %q", i, tags[i], exp)
				}
			}
		})
	}
}

func TestMapCloudFindingToAttacks(t *testing.T) {
	tests := []struct {
		name     string
		finding  types.NubicustosCloudFinding
		expected []string // attack type strings
	}{
		{
			name:     "s3_public",
			finding:  types.NubicustosCloudFinding{Type: "s3_public", Description: "Public bucket"},
			expected: []string{types.AttackSSRF, types.AttackPathTraversal},
		},
		{
			name:     "iam_overprivileged",
			finding:  types.NubicustosCloudFinding{Type: "iam_overprivileged", Description: "Overprivileged role"},
			expected: []string{types.AttackAuthBypass, types.AttackBFLA},
		},
		{
			name:     "security_group_open",
			finding:  types.NubicustosCloudFinding{Type: "security_group_open", Description: "Open SG"},
			expected: []string{types.AttackSSRF},
		},
		{
			name:     "rds_public",
			finding:  types.NubicustosCloudFinding{Type: "rds_public", Description: "Public RDS"},
			expected: []string{types.AttackSQLi, types.AttackNoSQLi},
		},
		{
			name:     "lambda_exposed",
			finding:  types.NubicustosCloudFinding{Type: "lambda_exposed", Description: "Exposed lambda"},
			expected: []string{types.AttackCommandInject, types.AttackSSTI},
		},
		{
			name:     "unknown_type",
			finding:  types.NubicustosCloudFinding{Type: "custom_issue", Description: "Custom"},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attacks := mapCloudFindingToAttacks(tt.finding)
			if len(attacks) != len(tt.expected) {
				t.Fatalf("expected %d attacks, got %d", len(tt.expected), len(attacks))
			}
			for i, exp := range tt.expected {
				if attacks[i].Type != exp {
					t.Errorf("attacks[%d].Type = %q, want %q", i, attacks[i].Type, exp)
				}
				if attacks[i].Category != "cloud" {
					t.Errorf("attacks[%d].Category = %q, want %q", i, attacks[i].Category, "cloud")
				}
			}
		})
	}
}

func TestAppendUniqueTags(t *testing.T) {
	result := appendUniqueTags([]string{"a", "b"}, "b", "c", "a", "d")
	expected := []string{"a", "b", "c", "d"}

	if len(result) != len(expected) {
		t.Fatalf("expected %d items, got %d: %v", len(expected), len(result), result)
	}
	for i, exp := range expected {
		if result[i] != exp {
			t.Errorf("result[%d] = %q, want %q", i, result[i], exp)
		}
	}
}

func TestAppendUniqueTags_EmptySlice(t *testing.T) {
	result := appendUniqueTags(nil, "a", "b", "a")
	if len(result) != 2 {
		t.Fatalf("expected 2 items, got %d: %v", len(result), result)
	}
}

func TestAppendUniqueAttacks(t *testing.T) {
	existing := []types.AttackVector{
		{Type: types.AttackSSRF, Category: "existing"},
	}
	newItems := []types.AttackVector{
		{Type: types.AttackSSRF, Category: "cloud"},    // duplicate, should be skipped
		{Type: types.AttackSQLi, Category: "cloud"},     // new
		{Type: types.AttackSQLi, Category: "cloud_dup"}, // duplicate type, should be skipped
	}

	result := appendUniqueAttacks(existing, newItems...)

	if len(result) != 2 {
		t.Fatalf("expected 2 attacks, got %d", len(result))
	}
	if result[0].Type != types.AttackSSRF {
		t.Errorf("result[0].Type = %q, want %q", result[0].Type, types.AttackSSRF)
	}
	// The existing SSRF should keep its original category
	if result[0].Category != "existing" {
		t.Errorf("result[0].Category = %q, want %q (should keep original)", result[0].Category, "existing")
	}
	if result[1].Type != types.AttackSQLi {
		t.Errorf("result[1].Type = %q, want %q", result[1].Type, types.AttackSQLi)
	}
}

// containsTag is defined in cepheus_test.go

func containsAttack(attacks []types.AttackVector, attackType string) bool {
	for _, a := range attacks {
		if a.Type == attackType {
			return true
		}
	}
	return false
}
