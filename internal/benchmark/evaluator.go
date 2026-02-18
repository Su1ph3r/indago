package benchmark

import (
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// Evaluate compares scan results against ground truth and returns a full
// evaluation with precision, recall, F1 score, and per-vulnerability detail.
func Evaluate(gt *GroundTruth, findings []types.Finding) *EvaluationResult {
	matchResults, fp := MatchFindings(gt, findings)

	var tp, fn []MatchResult
	for _, mr := range matchResults {
		if mr.Matched {
			tp = append(tp, mr)
		} else {
			fn = append(fn, mr)
		}
	}

	totalGT := len(gt.Vulnerabilities)
	tpCount := len(tp)
	fpCount := len(fp)

	var precision, recall, f1 float64
	if tpCount+fpCount > 0 {
		precision = float64(tpCount) / float64(tpCount+fpCount)
	}
	if totalGT > 0 {
		recall = float64(tpCount) / float64(totalGT)
	}
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}

	avgConf := computeAvgConfidence(findings)

	return &EvaluationResult{
		TruePositives:   tp,
		FalseNegatives:  fn,
		FalsePositives:  fp,
		Precision:       precision,
		Recall:          recall,
		F1:              f1,
		AvgConfidence:   avgConf,
		TotalFindings:   len(findings),
		TotalGroundTrue: totalGT,
	}
}

func computeAvgConfidence(findings []types.Finding) float64 {
	if len(findings) == 0 {
		return 0
	}
	var total float64
	for _, f := range findings {
		total += confidenceToFloat(f.Confidence)
	}
	return total / float64(len(findings))
}

func confidenceToFloat(c string) float64 {
	switch strings.ToLower(c) {
	case "high":
		return 1.0
	case "medium":
		return 0.6
	case "low":
		return 0.3
	default:
		return 0.1
	}
}
