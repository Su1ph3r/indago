// Package tui provides an interactive terminal user interface for Indago.
package tui

import (
	"fmt"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
	"github.com/charmbracelet/lipgloss"
)

// Styles for the TUI
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("205")).
			MarginBottom(1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("39"))

	tabStyle = lipgloss.NewStyle().
			Padding(0, 2)

	activeTabStyle = tabStyle.Copy().
			Bold(true).
			Foreground(lipgloss.Color("205")).
			Background(lipgloss.Color("236"))

	inactiveTabStyle = tabStyle.Copy().
				Foreground(lipgloss.Color("245"))

	statusRunning = lipgloss.NewStyle().
			Foreground(lipgloss.Color("46")). // Green
			Bold(true)

	statusPaused = lipgloss.NewStyle().
			Foreground(lipgloss.Color("226")). // Yellow
			Bold(true)

	statusComplete = lipgloss.NewStyle().
			Foreground(lipgloss.Color("39")). // Blue
			Bold(true)

	statusError = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")). // Red
			Bold(true)

	severityCritical = lipgloss.NewStyle().
				Foreground(lipgloss.Color("196")).
				Bold(true)

	severityHigh = lipgloss.NewStyle().
			Foreground(lipgloss.Color("208")).
			Bold(true)

	severityMedium = lipgloss.NewStyle().
			Foreground(lipgloss.Color("226"))

	severityLow = lipgloss.NewStyle().
			Foreground(lipgloss.Color("39"))

	severityInfo = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245"))

	selectedStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("236")).
			Bold(true)

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")).
			MarginTop(1)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("39")).
			Padding(1, 2)

	helpKeyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("205")).
			Bold(true)

	helpDescStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252"))
)

// StyledView provides styled rendering methods.
type StyledView struct {
	model  *Model
	width  int
	height int
}

// NewStyledView creates a new styled view.
func NewStyledView(model *Model) *StyledView {
	return &StyledView{
		model:  model,
		width:  model.width,
		height: model.height,
	}
}

// RenderHeader renders a styled header.
func (v *StyledView) RenderHeader() string {
	title := titleStyle.Render("INDAGO")
	subtitle := " - AI-Powered API Security Scanner"

	// Render tabs
	tabs := []struct {
		key   string
		label string
		mode  ViewMode
	}{
		{"1", "Progress", ViewProgress},
		{"2", "Findings", ViewFindings},
		{"3", "Triage", ViewTriage},
		{"?", "Help", ViewHelp},
	}

	var tabStrings []string
	for _, tab := range tabs {
		label := fmt.Sprintf("[%s] %s", tab.key, tab.label)
		if tab.mode == v.model.viewMode {
			tabStrings = append(tabStrings, activeTabStyle.Render(label))
		} else {
			tabStrings = append(tabStrings, inactiveTabStyle.Render(label))
		}
	}

	return fmt.Sprintf("%s%s\n%s", title, subtitle, strings.Join(tabStrings, " "))
}

// RenderStatus renders the scan status with appropriate styling.
func (v *StyledView) RenderStatus() string {
	var status string
	switch v.model.scanState {
	case StateRunning:
		status = statusRunning.Render("RUNNING")
	case StatePaused:
		status = statusPaused.Render("PAUSED")
	case StateComplete:
		status = statusComplete.Render("COMPLETE")
	case StateError:
		status = statusError.Render("ERROR")
	default:
		status = "IDLE"
	}

	return fmt.Sprintf("Status: %s", status)
}

// RenderProgressBar renders a styled progress bar.
func (v *StyledView) RenderProgressBar(label string, current, total int, width int) string {
	pct := 0.0
	if total > 0 {
		pct = float64(current) / float64(total) * 100
	}

	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	empty := width - filled

	bar := fmt.Sprintf("[%s%s] %.1f%%",
		lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render(strings.Repeat("█", filled)),
		strings.Repeat("░", empty),
		pct,
	)

	return fmt.Sprintf("%s: %d/%d\n%s", label, current, total, bar)
}

// RenderFinding renders a single finding with appropriate severity styling.
func (v *StyledView) RenderFinding(f types.Finding, selected bool) string {
	// Style severity tag
	var severityStyled string
	switch strings.ToLower(f.Severity) {
	case "critical":
		severityStyled = severityCritical.Render("[CRITICAL]")
	case "high":
		severityStyled = severityHigh.Render("[HIGH]")
	case "medium":
		severityStyled = severityMedium.Render("[MEDIUM]")
	case "low":
		severityStyled = severityLow.Render("[LOW]")
	default:
		severityStyled = severityInfo.Render("[INFO]")
	}

	// Build line
	line := fmt.Sprintf("%s %s - %s %s", severityStyled, f.Type, f.Method, f.Endpoint)
	if len(line) > v.width-4 {
		line = line[:v.width-7] + "..."
	}

	if selected {
		return selectedStyle.Render("> " + line)
	}
	return "  " + line
}

// RenderFindingDetail renders detailed finding information.
func (v *StyledView) RenderFindingDetail(f types.Finding) string {
	var b strings.Builder

	b.WriteString(headerStyle.Render("Finding Details") + "\n\n")

	// Type with severity styling
	var severityStyled string
	switch strings.ToLower(f.Severity) {
	case "critical":
		severityStyled = severityCritical.Render(strings.ToUpper(f.Severity))
	case "high":
		severityStyled = severityHigh.Render(strings.ToUpper(f.Severity))
	case "medium":
		severityStyled = severityMedium.Render(strings.ToUpper(f.Severity))
	case "low":
		severityStyled = severityLow.Render(strings.ToUpper(f.Severity))
	default:
		severityStyled = severityInfo.Render(strings.ToUpper(f.Severity))
	}

	b.WriteString(fmt.Sprintf("Type:       %s\n", f.Type))
	b.WriteString(fmt.Sprintf("Severity:   %s\n", severityStyled))
	b.WriteString(fmt.Sprintf("Confidence: %s\n", f.Confidence))
	b.WriteString(fmt.Sprintf("Endpoint:   %s %s\n", f.Method, f.Endpoint))

	if f.Parameter != "" {
		b.WriteString(fmt.Sprintf("Parameter:  %s\n", f.Parameter))
	}

	b.WriteString("\n" + headerStyle.Render("Description") + "\n")
	b.WriteString(f.Description + "\n")

	if f.Evidence != nil {
		b.WriteString("\n" + headerStyle.Render("Evidence") + "\n")
		var evidenceText strings.Builder
		if f.Evidence.Request != nil {
			evidenceText.WriteString(fmt.Sprintf("Request: %s %s\n", f.Evidence.Request.Method, f.Evidence.Request.URL))
		}
		if f.Evidence.Response != nil {
			evidenceText.WriteString(fmt.Sprintf("Response: %d %s\n", f.Evidence.Response.StatusCode, f.Evidence.Response.Status))
			if f.Evidence.Response.Body != "" {
				body := f.Evidence.Response.Body
				if len(body) > 200 {
					body = body[:200] + "..."
				}
				evidenceText.WriteString(fmt.Sprintf("Body: %s\n", body))
			}
		}
		if len(f.Evidence.MatchedData) > 0 {
			evidenceText.WriteString(fmt.Sprintf("Matched: %s\n", strings.Join(f.Evidence.MatchedData, ", ")))
		}
		b.WriteString(boxStyle.Render(evidenceText.String()) + "\n")
	}

	if f.Remediation != "" {
		b.WriteString("\n" + headerStyle.Render("Remediation") + "\n")
		b.WriteString(f.Remediation + "\n")
	}

	return b.String()
}

// RenderHelp renders styled help text.
func (v *StyledView) RenderHelp() string {
	var b strings.Builder

	b.WriteString(headerStyle.Render("INDAGO Interactive Mode") + "\n\n")

	helpItems := []struct {
		key  string
		desc string
	}{
		{"Tab", "Cycle through views"},
		{"1/2/3/?", "Switch to Progress/Findings/Triage/Help"},
		{"Up/k", "Move selection up"},
		{"Down/j", "Move selection down"},
		{"Enter", "View selected finding in Triage"},
		{"", ""},
		{"p", "Pause/Resume scan"},
		{"q", "Quit"},
		{"", ""},
		{"t", "Mark finding as True Positive"},
		{"f", "Mark finding as False Positive"},
		{"s", "Skip finding (no decision)"},
	}

	for _, item := range helpItems {
		if item.key == "" {
			b.WriteString("\n")
			continue
		}
		key := helpKeyStyle.Render(fmt.Sprintf("%-10s", item.key))
		desc := helpDescStyle.Render(item.desc)
		b.WriteString(fmt.Sprintf("  %s %s\n", key, desc))
	}

	return b.String()
}

// RenderFooter renders the styled footer.
func (v *StyledView) RenderFooter() string {
	return footerStyle.Render("Press 'q' to quit | 'p' to pause | Tab to switch views")
}

// RenderStats renders scan statistics.
func (v *StyledView) RenderStats() string {
	v.model.mu.RLock()
	defer v.model.mu.RUnlock()

	return fmt.Sprintf(
		"Requests/sec: %.1f | Findings: %d | Current: %s",
		v.model.requestsPerSec,
		len(v.model.findings),
		v.model.currentEndpoint,
	)
}

// SeverityColor returns the lipgloss color for a severity level.
func SeverityColor(severity string) lipgloss.Color {
	switch strings.ToLower(severity) {
	case "critical":
		return lipgloss.Color("196")
	case "high":
		return lipgloss.Color("208")
	case "medium":
		return lipgloss.Color("226")
	case "low":
		return lipgloss.Color("39")
	default:
		return lipgloss.Color("245")
	}
}
