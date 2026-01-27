// Package tui provides an interactive terminal user interface for Indago.
package tui

import (
	"context"
	"fmt"

	"github.com/su1ph3r/indago/pkg/types"
	tea "github.com/charmbracelet/bubbletea"
)

// Runner manages the TUI lifecycle and integration with the scanner.
type Runner struct {
	model       *Model
	program     *tea.Program
	progressCh  chan ProgressUpdate
	findingsCh  chan types.Finding
	doneCh      chan struct{}
	pauseCh     chan bool
}

// NewRunner creates a new TUI runner.
func NewRunner() *Runner {
	return &Runner{
		model:      NewModel(),
		progressCh: make(chan ProgressUpdate, 100),
		findingsCh: make(chan types.Finding, 100),
		doneCh:     make(chan struct{}),
		pauseCh:    make(chan bool),
	}
}

// Start initializes and runs the TUI.
func (r *Runner) Start(ctx context.Context) error {
	// Set up channels
	r.model.SetChannels(r.progressCh, r.findingsCh, r.doneCh, r.pauseCh)
	r.model.SetScanState(StateRunning)

	// Create program
	r.program = tea.NewProgram(r.model, tea.WithAltScreen())

	// Run in goroutine so we can handle context cancellation
	errCh := make(chan error, 1)
	go func() {
		_, err := r.program.Run()
		errCh <- err
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		r.program.Quit()
		return ctx.Err()
	}
}

// SendProgress sends a progress update to the TUI.
func (r *Runner) SendProgress(update ProgressUpdate) {
	select {
	case r.progressCh <- update:
	default:
		// Channel full, skip update
	}
}

// SendFinding sends a finding to the TUI.
func (r *Runner) SendFinding(finding types.Finding) {
	select {
	case r.findingsCh <- finding:
	default:
		// Channel full, skip finding display (still recorded)
	}
}

// SignalDone signals that the scan is complete.
func (r *Runner) SignalDone() {
	close(r.doneCh)
}

// GetPauseChannel returns the pause control channel.
func (r *Runner) GetPauseChannel() <-chan bool {
	return r.pauseCh
}

// GetTriageDecisions returns the triage decisions made by the user.
func (r *Runner) GetTriageDecisions() map[int]string {
	return r.model.GetTriageDecisions()
}

// Stop stops the TUI.
func (r *Runner) Stop() {
	if r.program != nil {
		r.program.Quit()
	}
}

// RunInteractive runs the TUI with simulated data for testing.
func RunInteractive() error {
	runner := NewRunner()

	// Create sample findings for demonstration
	sampleFindings := []types.Finding{
		{
			Type:        "SQL Injection",
			Severity:    types.SeverityCritical,
			Confidence:  types.ConfidenceHigh,
			Title:       "SQL Injection in Login",
			Method:      "POST",
			Endpoint:    "/api/users/login",
			Parameter:   "username",
			Description: "Potential SQL injection vulnerability detected in login endpoint",
			Evidence: &types.Evidence{
				Request: &types.HTTPRequest{
					Method: "POST",
					URL:    "/api/users/login",
					Body:   "username=' OR '1'='1&password=test",
				},
				Response: &types.HTTPResponse{
					StatusCode: 500,
					Status:     "Internal Server Error",
					Body:       "You have an error in your SQL syntax",
				},
				MatchedData: []string{"SQL syntax error"},
			},
			Remediation: "Use parameterized queries or prepared statements",
		},
		{
			Type:        "IDOR",
			Severity:    types.SeverityHigh,
			Confidence:  types.ConfidenceMedium,
			Title:       "IDOR in User Profile",
			Method:      "GET",
			Endpoint:    "/api/users/123/profile",
			Parameter:   "user_id",
			Description: "Insecure Direct Object Reference allows accessing other users' profiles",
			Evidence: &types.Evidence{
				Request: &types.HTTPRequest{
					Method: "GET",
					URL:    "/api/users/124/profile",
				},
				Response: &types.HTTPResponse{
					StatusCode: 200,
					Status:     "OK",
					Body:       `{"user_id": 124, "email": "other@example.com"}`,
				},
				MatchedData: []string{"Different user data returned"},
			},
			Remediation: "Implement proper authorization checks for resource access",
		},
		{
			Type:        "XSS",
			Severity:    types.SeverityMedium,
			Confidence:  types.ConfidenceMedium,
			Title:       "Reflected XSS in Comments",
			Method:      "POST",
			Endpoint:    "/api/comments",
			Parameter:   "content",
			Description: "Reflected XSS vulnerability in comment submission",
			Evidence: &types.Evidence{
				Request: &types.HTTPRequest{
					Method: "POST",
					URL:    "/api/comments",
					Body:   `content=<script>alert(1)</script>`,
				},
				Response: &types.HTTPResponse{
					StatusCode: 200,
					Status:     "OK",
					Body:       `<script>alert(1)</script>`,
				},
				MatchedData: []string{"<script>alert(1)</script>"},
			},
			Remediation: "Implement proper output encoding and Content-Security-Policy",
		},
	}

	// Send findings
	for _, f := range sampleFindings {
		runner.SendFinding(f)
	}

	// Run TUI
	fmt.Println("Starting Indago Interactive Mode...")
	return runner.Start(context.Background())
}
