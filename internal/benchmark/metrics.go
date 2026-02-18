package benchmark

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/su1ph3r/indago/pkg/types"
)

// EvaluationResult holds the outcome of comparing scan findings to ground truth.
type EvaluationResult struct {
	TruePositives  []MatchResult   `json:"true_positives"`
	FalseNegatives []MatchResult   `json:"false_negatives"`
	FalsePositives []types.Finding `json:"false_positives"`

	Precision       float64 `json:"precision"`
	Recall          float64 `json:"recall"`
	F1              float64 `json:"f1"`
	AvgConfidence   float64 `json:"avg_confidence"`
	TotalFindings   int     `json:"total_findings"`
	TotalGroundTrue int     `json:"total_ground_truth"`
}

// FPSummary captures key details of a false positive finding for convergence tracking.
type FPSummary struct {
	Type      string `json:"type"`
	Endpoint  string `json:"endpoint"`
	Method    string `json:"method"`
	Parameter string `json:"parameter,omitempty"`
	Severity  string `json:"severity"`
	Title     string `json:"title,omitempty"`
}

// IterationRecord stores metrics for a single benchmark iteration.
type IterationRecord struct {
	Iteration            int         `json:"iteration"`
	Recall               float64     `json:"recall"`
	Precision            float64     `json:"precision"`
	F1                   float64     `json:"f1"`
	FalsePositives       int         `json:"false_positives"`
	FalseNegatives       int         `json:"false_negatives"`
	TruePositives        int         `json:"true_positives"`
	AvgConfidence        float64     `json:"avg_confidence"`
	TotalFindings        int         `json:"total_findings"`
	ImprovementsUsed     []string    `json:"improvements_applied"`
	Converged            bool        `json:"converged"`
	FalsePositiveDetails []FPSummary `json:"false_positive_details,omitempty"`
}

// ConvergenceTracker tracks iteration-over-iteration metrics and detects
// convergence or stalls.
type ConvergenceTracker struct {
	FilePath string
	History  []IterationRecord
}

// NewConvergenceTracker creates a tracker that appends records to the given JSONL file.
func NewConvergenceTracker(filePath string) *ConvergenceTracker {
	ct := &ConvergenceTracker{FilePath: filePath}
	ct.load()
	return ct
}

// Append adds an iteration record and writes it to the JSONL file.
func (ct *ConvergenceTracker) Append(rec IterationRecord) error {
	ct.History = append(ct.History, rec)

	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal iteration record: %w", err)
	}

	dir := filepath.Dir(ct.FilePath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create convergence dir: %w", err)
	}

	f, err := os.OpenFile(ct.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open convergence file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write convergence record: %w", err)
	}
	return nil
}

// IsConverged returns true if recall == 1.0, FP == 0, and average
// confidence >= 0.8.
func (ct *ConvergenceTracker) IsConverged(rec IterationRecord) bool {
	return rec.Recall >= 1.0 && rec.FalsePositives == 0 && rec.AvgConfidence >= 0.8
}

// IsStalled returns true if recall has not improved for the last n
// iterations.
func (ct *ConvergenceTracker) IsStalled(n int) bool {
	if len(ct.History) < n+1 {
		return false
	}
	latest := ct.History[len(ct.History)-1].Recall
	for i := len(ct.History) - n; i < len(ct.History)-1; i++ {
		if ct.History[i].Recall != latest {
			return false
		}
	}
	return true
}

// load reads existing records from the JSONL file.
func (ct *ConvergenceTracker) load() {
	data, err := os.ReadFile(ct.FilePath)
	if err != nil {
		return
	}
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var rec IterationRecord
		if err := json.Unmarshal(line, &rec); err == nil {
			ct.History = append(ct.History, rec)
		}
	}
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
