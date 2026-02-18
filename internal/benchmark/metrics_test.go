package benchmark

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConvergenceTracker_AppendAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "convergence.jsonl")

	tracker := NewConvergenceTracker(path)

	rec1 := IterationRecord{Iteration: 1, Recall: 0.5, Precision: 0.8, FalsePositives: 2}
	rec2 := IterationRecord{Iteration: 2, Recall: 0.75, Precision: 0.9, FalsePositives: 1}

	if err := tracker.Append(rec1); err != nil {
		t.Fatalf("Append rec1: %v", err)
	}
	if err := tracker.Append(rec2); err != nil {
		t.Fatalf("Append rec2: %v", err)
	}

	if len(tracker.History) != 2 {
		t.Errorf("expected 2 records, got %d", len(tracker.History))
	}

	// Reload from file
	tracker2 := NewConvergenceTracker(path)
	if len(tracker2.History) != 2 {
		t.Errorf("expected 2 records after reload, got %d", len(tracker2.History))
	}
	if tracker2.History[0].Recall != 0.5 {
		t.Errorf("expected recall 0.5, got %f", tracker2.History[0].Recall)
	}
}

func TestConvergenceTracker_IsConverged(t *testing.T) {
	tracker := &ConvergenceTracker{}

	converged := IterationRecord{Recall: 1.0, FalsePositives: 0, AvgConfidence: 0.85}
	if !tracker.IsConverged(converged) {
		t.Error("expected converged for recall=1.0, FP=0, conf=0.85")
	}

	notConverged := IterationRecord{Recall: 0.9, FalsePositives: 0, AvgConfidence: 0.9}
	if tracker.IsConverged(notConverged) {
		t.Error("expected NOT converged for recall=0.9")
	}

	hasFFP := IterationRecord{Recall: 1.0, FalsePositives: 1, AvgConfidence: 0.9}
	if tracker.IsConverged(hasFFP) {
		t.Error("expected NOT converged for FP=1")
	}

	lowConf := IterationRecord{Recall: 1.0, FalsePositives: 0, AvgConfidence: 0.5}
	if tracker.IsConverged(lowConf) {
		t.Error("expected NOT converged for avgConf=0.5")
	}
}

func TestConvergenceTracker_IsStalled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stall.jsonl")
	tracker := NewConvergenceTracker(path)

	// Add 4 records with same recall
	for i := 1; i <= 4; i++ {
		tracker.Append(IterationRecord{Iteration: i, Recall: 0.5})
	}

	if !tracker.IsStalled(3) {
		t.Error("expected stalled after 3 iterations with same recall")
	}

	// Add one with different recall
	tracker.Append(IterationRecord{Iteration: 5, Recall: 0.75})
	if tracker.IsStalled(3) {
		t.Error("expected NOT stalled after recall improvement")
	}
}

func TestConvergenceTracker_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "nested", "convergence.jsonl")

	tracker := NewConvergenceTracker(path)
	err := tracker.Append(IterationRecord{Iteration: 1, Recall: 0.5})
	if err != nil {
		t.Fatalf("Append with nested dir: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("expected convergence file to be created in nested directory")
	}
}
