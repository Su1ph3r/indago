// Package tui provides an interactive terminal user interface for Indago.
package tui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/su1ph3r/indago/pkg/types"
	tea "github.com/charmbracelet/bubbletea"
)

// ViewMode represents the current view in the TUI.
type ViewMode int

const (
	ViewProgress ViewMode = iota
	ViewFindings
	ViewTriage
	ViewHelp
)

// ScanState represents the state of the scan.
type ScanState int

const (
	StateIdle ScanState = iota
	StateRunning
	StatePaused
	StateComplete
	StateError
)

// Model represents the TUI application state.
type Model struct {
	mu sync.RWMutex

	// View state
	viewMode      ViewMode
	width         int
	height        int
	ready         bool

	// Scan state
	scanState     ScanState
	scanError     error

	// Progress tracking
	totalEndpoints   int
	scannedEndpoints int
	totalRequests    int
	completedReqs    int
	currentEndpoint  string
	startTime        time.Time
	requestsPerSec   float64

	// Findings
	findings       []types.Finding
	selectedIdx    int
	findingScroll  int

	// Triage state
	triageIdx      int
	triageDecisions map[int]string // finding index -> decision

	// Channels for communication
	progressChan   <-chan ProgressUpdate
	findingsChan   <-chan types.Finding
	doneChan       <-chan struct{}

	// Control
	pauseChan      chan<- bool
	isPaused       bool
}

// ProgressUpdate represents a progress update from the scanner.
type ProgressUpdate struct {
	TotalEndpoints   int
	ScannedEndpoints int
	TotalRequests    int
	CompletedReqs    int
	CurrentEndpoint  string
	RequestsPerSec   float64
}

// Msg types for the TUI
type (
	progressMsg    ProgressUpdate
	findingMsg     types.Finding
	scanDoneMsg    struct{}
	scanErrorMsg   error
	tickMsg        time.Time
	windowSizeMsg  tea.WindowSizeMsg
)

// NewModel creates a new TUI model.
func NewModel() *Model {
	return &Model{
		viewMode:        ViewProgress,
		scanState:       StateIdle,
		findings:        make([]types.Finding, 0),
		triageDecisions: make(map[int]string),
	}
}

// SetChannels sets the communication channels for the model.
func (m *Model) SetChannels(progress <-chan ProgressUpdate, findings <-chan types.Finding, done <-chan struct{}, pause chan<- bool) {
	m.progressChan = progress
	m.findingsChan = findings
	m.doneChan = done
	m.pauseChan = pause
}

// Init implements tea.Model.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(
		tea.EnterAltScreen,
		m.waitForProgress(),
		m.waitForFindings(),
		m.waitForDone(),
		tickCmd(),
	)
}

// Update implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKeypress(msg)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true
		return m, nil

	case progressMsg:
		m.mu.Lock()
		m.totalEndpoints = msg.TotalEndpoints
		m.scannedEndpoints = msg.ScannedEndpoints
		m.totalRequests = msg.TotalRequests
		m.completedReqs = msg.CompletedReqs
		m.currentEndpoint = msg.CurrentEndpoint
		m.requestsPerSec = msg.RequestsPerSec
		m.mu.Unlock()
		return m, m.waitForProgress()

	case findingMsg:
		m.mu.Lock()
		m.findings = append(m.findings, types.Finding(msg))
		m.mu.Unlock()
		return m, m.waitForFindings()

	case scanDoneMsg:
		m.scanState = StateComplete
		return m, nil

	case scanErrorMsg:
		m.scanState = StateError
		m.scanError = msg
		return m, nil

	case tickMsg:
		return m, tickCmd()
	}

	return m, nil
}

// handleKeypress handles keyboard input.
func (m *Model) handleKeypress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit

	case "tab":
		// Cycle through views
		m.viewMode = (m.viewMode + 1) % 4
		return m, nil

	case "1":
		m.viewMode = ViewProgress
		return m, nil

	case "2":
		m.viewMode = ViewFindings
		return m, nil

	case "3":
		m.viewMode = ViewTriage
		return m, nil

	case "?", "h":
		m.viewMode = ViewHelp
		return m, nil

	case "p":
		// Pause/resume
		if m.scanState == StateRunning {
			m.isPaused = !m.isPaused
			if m.pauseChan != nil {
				m.pauseChan <- m.isPaused
			}
			if m.isPaused {
				m.scanState = StatePaused
			} else {
				m.scanState = StateRunning
			}
		}
		return m, nil

	case "up", "k":
		if m.viewMode == ViewFindings && m.selectedIdx > 0 {
			m.selectedIdx--
		} else if m.viewMode == ViewTriage && m.triageIdx > 0 {
			m.triageIdx--
		}
		return m, nil

	case "down", "j":
		if m.viewMode == ViewFindings && m.selectedIdx < len(m.findings)-1 {
			m.selectedIdx++
		} else if m.viewMode == ViewTriage && m.triageIdx < len(m.findings)-1 {
			m.triageIdx++
		}
		return m, nil

	case "enter":
		if m.viewMode == ViewFindings {
			// Switch to triage for selected finding
			m.triageIdx = m.selectedIdx
			m.viewMode = ViewTriage
		}
		return m, nil

	case "t":
		// Mark as true positive
		if m.viewMode == ViewTriage {
			m.triageDecisions[m.triageIdx] = "true_positive"
			if m.triageIdx < len(m.findings)-1 {
				m.triageIdx++
			}
		}
		return m, nil

	case "f":
		// Mark as false positive
		if m.viewMode == ViewTriage {
			m.triageDecisions[m.triageIdx] = "false_positive"
			if m.triageIdx < len(m.findings)-1 {
				m.triageIdx++
			}
		}
		return m, nil

	case "s":
		// Skip
		if m.viewMode == ViewTriage {
			delete(m.triageDecisions, m.triageIdx)
			if m.triageIdx < len(m.findings)-1 {
				m.triageIdx++
			}
		}
		return m, nil
	}

	return m, nil
}

// View implements tea.Model.
func (m *Model) View() string {
	if !m.ready {
		return "Initializing..."
	}

	var b strings.Builder

	// Header
	b.WriteString(m.renderHeader())
	b.WriteString("\n\n")

	// Main content based on view mode
	switch m.viewMode {
	case ViewProgress:
		b.WriteString(m.renderProgress())
	case ViewFindings:
		b.WriteString(m.renderFindings())
	case ViewTriage:
		b.WriteString(m.renderTriage())
	case ViewHelp:
		b.WriteString(m.renderHelp())
	}

	// Footer
	b.WriteString("\n\n")
	b.WriteString(m.renderFooter())

	return b.String()
}

// renderHeader renders the header bar.
func (m *Model) renderHeader() string {
	title := "INDAGO - Interactive Security Scanner"

	// View tabs
	tabs := []string{"[1]Progress", "[2]Findings", "[3]Triage", "[?]Help"}
	for i, tab := range tabs {
		if ViewMode(i) == m.viewMode {
			tabs[i] = fmt.Sprintf("*%s*", tab)
		}
	}

	return fmt.Sprintf("%s\n%s", title, strings.Join(tabs, " | "))
}

// renderProgress renders the progress view.
func (m *Model) renderProgress() string {
	var b strings.Builder

	// Scan state
	stateStr := "Idle"
	switch m.scanState {
	case StateRunning:
		stateStr = "Running"
	case StatePaused:
		stateStr = "Paused"
	case StateComplete:
		stateStr = "Complete"
	case StateError:
		stateStr = fmt.Sprintf("Error: %v", m.scanError)
	}
	b.WriteString(fmt.Sprintf("Status: %s\n\n", stateStr))

	// Progress bars
	m.mu.RLock()
	endpointPct := 0.0
	if m.totalEndpoints > 0 {
		endpointPct = float64(m.scannedEndpoints) / float64(m.totalEndpoints) * 100
	}
	requestPct := 0.0
	if m.totalRequests > 0 {
		requestPct = float64(m.completedReqs) / float64(m.totalRequests) * 100
	}

	b.WriteString(fmt.Sprintf("Endpoints: %d/%d (%.1f%%)\n", m.scannedEndpoints, m.totalEndpoints, endpointPct))
	b.WriteString(renderProgressBar(endpointPct, 40))
	b.WriteString("\n\n")

	b.WriteString(fmt.Sprintf("Requests:  %d/%d (%.1f%%)\n", m.completedReqs, m.totalRequests, requestPct))
	b.WriteString(renderProgressBar(requestPct, 40))
	b.WriteString("\n\n")

	// Stats
	b.WriteString(fmt.Sprintf("Requests/sec: %.1f\n", m.requestsPerSec))
	b.WriteString(fmt.Sprintf("Findings:     %d\n", len(m.findings)))
	b.WriteString(fmt.Sprintf("Current:      %s\n", m.currentEndpoint))
	m.mu.RUnlock()

	return b.String()
}

// renderProgressBar renders a text-based progress bar.
func renderProgressBar(pct float64, width int) string {
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	empty := width - filled
	return fmt.Sprintf("[%s%s]", strings.Repeat("=", filled), strings.Repeat(" ", empty))
}

// renderFindings renders the findings list view.
func (m *Model) renderFindings() string {
	var b strings.Builder

	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.findings) == 0 {
		return "No findings yet..."
	}

	b.WriteString(fmt.Sprintf("Findings (%d total):\n\n", len(m.findings)))

	// Show visible findings
	visibleCount := min(m.height-10, len(m.findings))
	startIdx := m.findingScroll
	if m.selectedIdx >= startIdx+visibleCount {
		startIdx = m.selectedIdx - visibleCount + 1
	} else if m.selectedIdx < startIdx {
		startIdx = m.selectedIdx
	}
	m.findingScroll = startIdx

	endIdx := min(startIdx+visibleCount, len(m.findings))

	for i := startIdx; i < endIdx; i++ {
		f := m.findings[i]
		prefix := "  "
		if i == m.selectedIdx {
			prefix = "> "
		}

		severityTag := fmt.Sprintf("[%s]", strings.ToUpper(f.Severity))
		line := fmt.Sprintf("%s%s %s - %s %s", prefix, severityTag, f.Type, f.Method, f.Endpoint)
		if len(line) > m.width-2 {
			line = line[:m.width-5] + "..."
		}
		b.WriteString(line + "\n")
	}

	return b.String()
}

// renderTriage renders the triage view for a single finding.
func (m *Model) renderTriage() string {
	var b strings.Builder

	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.findings) == 0 {
		return "No findings to triage..."
	}

	if m.triageIdx >= len(m.findings) {
		m.triageIdx = len(m.findings) - 1
	}

	f := m.findings[m.triageIdx]

	b.WriteString(fmt.Sprintf("Triage Finding %d/%d\n\n", m.triageIdx+1, len(m.findings)))

	b.WriteString(fmt.Sprintf("Type:       %s\n", f.Type))
	b.WriteString(fmt.Sprintf("Severity:   %s\n", strings.ToUpper(f.Severity)))
	b.WriteString(fmt.Sprintf("Confidence: %s\n", f.Confidence))
	b.WriteString(fmt.Sprintf("Endpoint:   %s %s\n", f.Method, f.Endpoint))
	b.WriteString(fmt.Sprintf("Parameter:  %s\n", f.Parameter))
	b.WriteString("\nDescription:\n")
	b.WriteString(f.Description + "\n\n")

	if f.Evidence != nil {
		b.WriteString("Evidence:\n")
		if f.Evidence.Request != nil {
			b.WriteString(fmt.Sprintf("  Request: %s %s\n", f.Evidence.Request.Method, f.Evidence.Request.URL))
		}
		if f.Evidence.Response != nil {
			b.WriteString(fmt.Sprintf("  Response: %d %s\n", f.Evidence.Response.StatusCode, f.Evidence.Response.Status))
		}
		if len(f.Evidence.MatchedData) > 0 {
			b.WriteString(fmt.Sprintf("  Matched: %s\n", strings.Join(f.Evidence.MatchedData, ", ")))
		}
		b.WriteString("\n")
	}

	// Decision status
	decision, hasDecision := m.triageDecisions[m.triageIdx]
	if hasDecision {
		b.WriteString(fmt.Sprintf("Decision: %s\n", decision))
	} else {
		b.WriteString("Decision: (pending)\n")
	}

	b.WriteString("\n[T]rue positive | [F]alse positive | [S]kip")

	return b.String()
}

// renderHelp renders the help view.
func (m *Model) renderHelp() string {
	return `
INDAGO Interactive Mode - Help

Navigation:
  Tab        Cycle through views
  1/2/3/?    Switch to Progress/Findings/Triage/Help
  Up/k       Move selection up
  Down/j     Move selection down
  Enter      View selected finding in Triage

Scan Control:
  p          Pause/Resume scan
  q/Ctrl+C   Quit

Triage:
  t          Mark as True Positive
  f          Mark as False Positive
  s          Skip (no decision)

The triage decisions are saved and can be used to filter
the final report output.
`
}

// renderFooter renders the footer bar.
func (m *Model) renderFooter() string {
	return "Press 'q' to quit | 'p' to pause | Tab to switch views"
}

// waitForProgress waits for progress updates.
func (m *Model) waitForProgress() tea.Cmd {
	return func() tea.Msg {
		if m.progressChan == nil {
			return nil
		}
		update, ok := <-m.progressChan
		if !ok {
			return nil
		}
		return progressMsg(update)
	}
}

// waitForFindings waits for new findings.
func (m *Model) waitForFindings() tea.Cmd {
	return func() tea.Msg {
		if m.findingsChan == nil {
			return nil
		}
		finding, ok := <-m.findingsChan
		if !ok {
			return nil
		}
		return findingMsg(finding)
	}
}

// waitForDone waits for scan completion.
func (m *Model) waitForDone() tea.Cmd {
	return func() tea.Msg {
		if m.doneChan == nil {
			return nil
		}
		<-m.doneChan
		return scanDoneMsg{}
	}
}

// tickCmd creates a tick command for periodic updates.
func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// GetTriageDecisions returns the triage decisions made.
func (m *Model) GetTriageDecisions() map[int]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[int]string)
	for k, v := range m.triageDecisions {
		result[k] = v
	}
	return result
}

// SetScanState updates the scan state.
func (m *Model) SetScanState(state ScanState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanState = state
}

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
