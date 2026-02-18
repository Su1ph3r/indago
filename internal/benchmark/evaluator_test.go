package benchmark

import (
	"math"
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestEvaluate_PerfectRecall(t *testing.T) {
	gt := &GroundTruth{
		Vulnerabilities: []Vulnerability{
			{ID: "001", Class: "sqli", MatchRules: MatchRules{FindingTypes: []string{"sqli"}}, MinMatches: 1},
			{ID: "002", Class: "bola", MatchRules: MatchRules{FindingTypes: []string{"bola"}}, MinMatches: 1},
		},
	}

	findings := []types.Finding{
		{Type: "sqli", Confidence: "high"},
		{Type: "bola", Confidence: "high"},
	}

	result := Evaluate(gt, findings)

	if result.Recall != 1.0 {
		t.Errorf("expected recall 1.0, got %f", result.Recall)
	}
	if result.Precision != 1.0 {
		t.Errorf("expected precision 1.0, got %f", result.Precision)
	}
	if len(result.FalseNegatives) != 0 {
		t.Errorf("expected 0 false negatives, got %d", len(result.FalseNegatives))
	}
	if len(result.FalsePositives) != 0 {
		t.Errorf("expected 0 false positives, got %d", len(result.FalsePositives))
	}
}

func TestEvaluate_PartialRecall(t *testing.T) {
	gt := &GroundTruth{
		Vulnerabilities: []Vulnerability{
			{ID: "001", Class: "sqli", MatchRules: MatchRules{FindingTypes: []string{"sqli"}}, MinMatches: 1},
			{ID: "002", Class: "bola", MatchRules: MatchRules{FindingTypes: []string{"bola"}}, MinMatches: 1},
		},
	}

	// Only detect SQLi, miss BOLA
	findings := []types.Finding{
		{Type: "sqli", Confidence: "high"},
	}

	result := Evaluate(gt, findings)

	if result.Recall != 0.5 {
		t.Errorf("expected recall 0.5, got %f", result.Recall)
	}
	if len(result.FalseNegatives) != 1 {
		t.Errorf("expected 1 false negative, got %d", len(result.FalseNegatives))
	}
}

func TestEvaluate_FalsePositives(t *testing.T) {
	gt := &GroundTruth{
		Vulnerabilities: []Vulnerability{
			{ID: "001", Class: "sqli", MatchRules: MatchRules{FindingTypes: []string{"sqli"}}, MinMatches: 1},
		},
	}

	findings := []types.Finding{
		{Type: "sqli", Confidence: "high"},
		{Type: "xss", Confidence: "low"}, // FP: not in ground truth
	}

	result := Evaluate(gt, findings)

	if len(result.FalsePositives) != 1 {
		t.Errorf("expected 1 false positive, got %d", len(result.FalsePositives))
	}
	// precision = 1 TP / (1 TP + 1 FP) = 0.5
	if math.Abs(result.Precision-0.5) > 0.01 {
		t.Errorf("expected precision ~0.5, got %f", result.Precision)
	}
}

func TestEvaluate_NoFindings(t *testing.T) {
	gt := &GroundTruth{
		Vulnerabilities: []Vulnerability{
			{ID: "001", Class: "sqli", MatchRules: MatchRules{FindingTypes: []string{"sqli"}}, MinMatches: 1},
		},
	}

	result := Evaluate(gt, nil)

	if result.Recall != 0 {
		t.Errorf("expected recall 0, got %f", result.Recall)
	}
	if len(result.FalseNegatives) != 1 {
		t.Errorf("expected 1 false negative, got %d", len(result.FalseNegatives))
	}
}

func TestComputeAvgConfidence(t *testing.T) {
	findings := []types.Finding{
		{Confidence: "high"},   // 1.0
		{Confidence: "medium"}, // 0.6
		{Confidence: "low"},    // 0.3
	}

	avg := computeAvgConfidence(findings)
	expected := (1.0 + 0.6 + 0.3) / 3.0
	if math.Abs(avg-expected) > 0.01 {
		t.Errorf("expected avg confidence ~%.3f, got %.3f", expected, avg)
	}
}
