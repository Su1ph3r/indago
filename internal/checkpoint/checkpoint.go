// Package checkpoint provides scan state persistence and recovery
package checkpoint

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

// Manager handles checkpoint operations
type Manager struct {
	mu           sync.Mutex
	filePath     string
	interval     time.Duration
	state        *ScanState
	lastSave     time.Time
	autoSave     bool
	stopChan     chan struct{}
	stopOnce     sync.Once
}

// ScanState represents the saved scan state
type ScanState struct {
	Version       string              `json:"version"`
	ScanID        string              `json:"scan_id"`
	StartTime     time.Time           `json:"start_time"`
	LastUpdate    time.Time           `json:"last_update"`
	InputFile     string              `json:"input_file"`
	InputType     string              `json:"input_type"`
	Target        string              `json:"target"`
	Config        *types.ScanConfig   `json:"config,omitempty"`
	Progress      ScanProgress        `json:"progress"`
	Findings      []types.Finding     `json:"findings"`
	CompletedReqs []string            `json:"completed_requests"` // Fingerprints of completed requests
	PendingReqs   []RequestState      `json:"pending_requests,omitempty"`
	Errors        []types.ScanError   `json:"errors,omitempty"`
}

// ScanProgress tracks scan progress
type ScanProgress struct {
	TotalEndpoints    int     `json:"total_endpoints"`
	ScannedEndpoints  int     `json:"scanned_endpoints"`
	TotalRequests     int     `json:"total_requests"`
	CompletedRequests int     `json:"completed_requests"`
	PercentComplete   float64 `json:"percent_complete"`
}

// RequestState represents a pending request state
type RequestState struct {
	Fingerprint string `json:"fingerprint"`
	Endpoint    string `json:"endpoint"`
	Method      string `json:"method"`
	Parameter   string `json:"parameter,omitempty"`
	PayloadType string `json:"payload_type"`
}

// ManagerConfig holds checkpoint manager configuration
type ManagerConfig struct {
	FilePath string
	Interval time.Duration
	AutoSave bool
}

// DefaultManagerConfig returns default configuration
func DefaultManagerConfig() *ManagerConfig {
	return &ManagerConfig{
		FilePath: ".indago-checkpoint.json",
		Interval: 30 * time.Second,
		AutoSave: true,
	}
}

// NewManager creates a new checkpoint manager
func NewManager(config *ManagerConfig) *Manager {
	if config == nil {
		config = DefaultManagerConfig()
	}

	return &Manager{
		filePath: config.FilePath,
		interval: config.Interval,
		autoSave: config.AutoSave,
		stopChan: make(chan struct{}),
		state: &ScanState{
			Version:       "1.0",
			CompletedReqs: []string{},
			Findings:      []types.Finding{},
		},
	}
}

// Initialize initializes the checkpoint state
func (m *Manager) Initialize(scanID string, inputFile, inputType, target string, config *types.ScanConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.state = &ScanState{
		Version:       "1.0",
		ScanID:        scanID,
		StartTime:     time.Now(),
		LastUpdate:    time.Now(),
		InputFile:     inputFile,
		InputType:     inputType,
		Target:        target,
		Config:        config,
		CompletedReqs: []string{},
		Findings:      []types.Finding{},
	}
}

// SetProgress updates progress information
func (m *Manager) SetProgress(total, completed, totalReqs, completedReqs int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.state.Progress = ScanProgress{
		TotalEndpoints:    total,
		ScannedEndpoints:  completed,
		TotalRequests:     totalReqs,
		CompletedRequests: completedReqs,
	}

	if totalReqs > 0 {
		m.state.Progress.PercentComplete = float64(completedReqs) / float64(totalReqs) * 100
	}

	m.state.LastUpdate = time.Now()
}

// RecordCompletion records a completed request
func (m *Manager) RecordCompletion(fingerprint string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.state.CompletedReqs = append(m.state.CompletedReqs, fingerprint)
	m.state.Progress.CompletedRequests = len(m.state.CompletedReqs)
	m.state.LastUpdate = time.Now()
}

// AddFinding adds a finding to the checkpoint
func (m *Manager) AddFinding(finding types.Finding) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.state.Findings = append(m.state.Findings, finding)
	m.state.LastUpdate = time.Now()
}

// AddError adds an error to the checkpoint
func (m *Manager) AddError(err types.ScanError) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.state.Errors = append(m.state.Errors, err)
	m.state.LastUpdate = time.Now()
}

// IsCompleted checks if a request has been completed
func (m *Manager) IsCompleted(fingerprint string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, fp := range m.state.CompletedReqs {
		if fp == fingerprint {
			return true
		}
	}
	return false
}

// Save saves the current state to file
func (m *Manager) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.state.LastUpdate = time.Now()

	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint: %w", err)
	}

	// Write to temp file first (0600 for security - may contain auth headers)
	tempFile := m.filePath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write checkpoint: %w", err)
	}

	// Rename to final file
	if err := os.Rename(tempFile, m.filePath); err != nil {
		return fmt.Errorf("failed to finalize checkpoint: %w", err)
	}

	m.lastSave = time.Now()
	return nil
}

// Load loads state from a checkpoint file
func (m *Manager) Load(filePath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read checkpoint: %w", err)
	}

	var state ScanState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("failed to parse checkpoint: %w", err)
	}

	m.state = &state
	m.filePath = filePath

	return nil
}

// GetState returns the current state
func (m *Manager) GetState() *ScanState {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return a copy
	stateCopy := *m.state
	return &stateCopy
}

// GetFindings returns current findings
func (m *Manager) GetFindings() []types.Finding {
	m.mu.Lock()
	defer m.mu.Unlock()

	findings := make([]types.Finding, len(m.state.Findings))
	copy(findings, m.state.Findings)
	return findings
}

// FilterPendingRequests filters out completed requests
func (m *Manager) FilterPendingRequests(requests []payloads.FuzzRequest, fingerprinter func(payloads.FuzzRequest) string) []payloads.FuzzRequest {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Build a set of completed fingerprints
	completed := make(map[string]bool)
	for _, fp := range m.state.CompletedReqs {
		completed[fp] = true
	}

	// Filter requests
	var pending []payloads.FuzzRequest
	for _, req := range requests {
		fp := fingerprinter(req)
		if !completed[fp] {
			pending = append(pending, req)
		}
	}

	return pending
}

// StartAutoSave starts automatic saving at intervals
func (m *Manager) StartAutoSave() {
	if !m.autoSave {
		return
	}

	go func() {
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := m.Save(); err != nil {
					// Log error but continue
					fmt.Printf("Warning: checkpoint save failed: %v\n", err)
				}
			case <-m.stopChan:
				return
			}
		}
	}()
}

// StopAutoSave stops automatic saving (safe to call multiple times)
func (m *Manager) StopAutoSave() {
	m.stopOnce.Do(func() {
		close(m.stopChan)
	})
}

// Cleanup removes the checkpoint file
func (m *Manager) Cleanup() error {
	return os.Remove(m.filePath)
}

// Exists checks if a checkpoint file exists
func Exists(filePath string) bool {
	_, err := os.Stat(filePath)
	return err == nil
}

// LoadAndResume loads a checkpoint and prepares for resume
func LoadAndResume(filePath string) (*Manager, error) {
	manager := NewManager(&ManagerConfig{
		FilePath: filePath,
		AutoSave: true,
	})

	if err := manager.Load(filePath); err != nil {
		return nil, err
	}

	return manager, nil
}

// GetResumeInfo returns information for displaying resume status
type ResumeInfo struct {
	ScanID        string
	StartTime     time.Time
	LastUpdate    time.Time
	Target        string
	Progress      ScanProgress
	FindingsCount int
	ErrorsCount   int
}

// GetResumeInfo returns information about a checkpoint for resuming
func (m *Manager) GetResumeInfo() *ResumeInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	return &ResumeInfo{
		ScanID:        m.state.ScanID,
		StartTime:     m.state.StartTime,
		LastUpdate:    m.state.LastUpdate,
		Target:        m.state.Target,
		Progress:      m.state.Progress,
		FindingsCount: len(m.state.Findings),
		ErrorsCount:   len(m.state.Errors),
	}
}
