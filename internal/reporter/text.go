// Package reporter provides output formatting for scan results
package reporter

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/su1ph3r/indago/pkg/types"
)

// TextReporter generates Nmap-style text reports
type TextReporter struct {
	options ReportOptions
	noColor bool
}

// NewTextReporter creates a new text reporter
func NewTextReporter(options ReportOptions) *TextReporter {
	return &TextReporter{options: options}
}

// NewTextReporterWithColor creates a new text reporter with color control
func NewTextReporterWithColor(options ReportOptions, noColor bool) *TextReporter {
	return &TextReporter{options: options, noColor: noColor}
}

// Format returns the format name
func (r *TextReporter) Format() string {
	return "text"
}

// Extension returns the file extension
func (r *TextReporter) Extension() string {
	return "txt"
}

// Generate generates a text report
func (r *TextReporter) Generate(result *types.ScanResult) ([]byte, error) {
	var buf strings.Builder
	if err := r.Write(result, &buf); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// Write writes the text report to a writer
func (r *TextReporter) Write(result *types.ScanResult, w io.Writer) error {
	// Header
	r.writeHeader(w, result)

	// Scan info
	r.writeScanInfo(w, result)

	// Summary table
	r.writeSummary(w, result)

	// Findings detail
	r.writeFindings(w, result)

	// Footer
	r.writeFooter(w, result)

	return nil
}

func (r *TextReporter) writeHeader(w io.Writer, result *types.ScanResult) {
	fmt.Fprintf(w, "\n")
	v := r.options.Version
	if v == "" {
		v = "unknown"
	}
	fmt.Fprintf(w, "Starting Indago %s ( https://github.com/su1ph3r/indago )\n", v)
	fmt.Fprintf(w, "Scan report for %s\n", result.Target)
	fmt.Fprintf(w, "Scan started at %s\n", result.StartTime.Format("2006-01-02 15:04 MST"))
	fmt.Fprintf(w, "\n")
}

func (r *TextReporter) writeScanInfo(w io.Writer, result *types.ScanResult) {
	fmt.Fprintf(w, "Scanned %d endpoints in %s (%d requests)\n",
		result.Endpoints,
		formatDuration(result.Duration),
		result.Requests)
	fmt.Fprintf(w, "\n")
}

func (r *TextReporter) writeSummary(w io.Writer, result *types.ScanResult) {
	fmt.Fprintf(w, "VULNERABILITY SUMMARY\n")
	fmt.Fprintf(w, "%-12s %s\n", "SEVERITY", "COUNT")

	// Print each severity with optional color
	severities := []struct {
		name  string
		count int
		color string
	}{
		{"CRITICAL", result.Summary.CriticalFindings, "\033[1;31m"},
		{"HIGH", result.Summary.HighFindings, "\033[31m"},
		{"MEDIUM", result.Summary.MediumFindings, "\033[33m"},
		{"LOW", result.Summary.LowFindings, "\033[34m"},
		{"INFO", result.Summary.InfoFindings, "\033[36m"},
	}

	for _, sev := range severities {
		if r.noColor {
			fmt.Fprintf(w, "%-12s %d\n", sev.name, sev.count)
		} else {
			fmt.Fprintf(w, "%s%-12s%s %d\n", sev.color, sev.name, "\033[0m", sev.count)
		}
	}

	fmt.Fprintf(w, "%-12s %d\n", "TOTAL", result.Summary.TotalFindings)
	fmt.Fprintf(w, "\n")
}

func (r *TextReporter) writeFindings(w io.Writer, result *types.ScanResult) {
	if len(result.Findings) == 0 {
		fmt.Fprintf(w, "No vulnerabilities found.\n")
		return
	}

	fmt.Fprintf(w, "FINDINGS DETAIL\n")
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 70))

	// Group by severity
	severityOrder := []string{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
		types.SeverityInfo,
	}

	findingsBySeverity := make(map[string][]types.Finding)
	for _, f := range result.Findings {
		findingsBySeverity[f.Severity] = append(findingsBySeverity[f.Severity], f)
	}

	for _, severity := range severityOrder {
		findings := findingsBySeverity[severity]
		if len(findings) == 0 {
			continue
		}

		for _, f := range findings {
			r.writeFinding(w, f)
		}
	}
}

func (r *TextReporter) writeFinding(w io.Writer, f types.Finding) {
	// Severity tag with optional color
	severityTag := fmt.Sprintf("[%s]", strings.ToUpper(f.Severity))
	if !r.noColor {
		severityTag = fmt.Sprintf("%s[%s]%s", SeverityColor(f.Severity), strings.ToUpper(f.Severity), ResetColor())
	}

	fmt.Fprintf(w, "%s %s\n", severityTag, f.Title)
	fmt.Fprintf(w, "    Endpoint:   %s %s\n", f.Method, f.Endpoint)
	fmt.Fprintf(w, "    Type:       %s\n", f.Type)

	if f.Parameter != "" {
		fmt.Fprintf(w, "    Parameter:  %s\n", f.Parameter)
	}

	if f.Confidence != "" {
		fmt.Fprintf(w, "    Confidence: %s\n", f.Confidence)
	}

	if f.Description != "" {
		desc := f.Description
		if len(desc) > 200 {
			desc = desc[:197] + "..."
		}
		fmt.Fprintf(w, "    Description: %s\n", desc)
	}

	if f.Evidence != nil && f.Evidence.Response != nil && f.Evidence.Response.StatusCode > 0 {
		fmt.Fprintf(w, "    Response:   %d\n", f.Evidence.Response.StatusCode)
	}

	if f.Evidence != nil && len(f.Evidence.MatchedData) > 0 {
		fmt.Fprintf(w, "    Matched:    %s\n", fmt.Sprintf("%v", f.Evidence.MatchedData))
	}

	if f.Remediation != "" {
		rem := f.Remediation
		if len(rem) > 200 {
			rem = rem[:197] + "..."
		}
		fmt.Fprintf(w, "    Remediation: %s\n", rem)
	}

	if f.CWE != "" {
		fmt.Fprintf(w, "    CWE:        %s\n", f.CWE)
	}

	if f.CVSS > 0 {
		fmt.Fprintf(w, "    CVSS:       %.1f\n", f.CVSS)
	}

	if f.Verification != nil {
		verifiedTag := "UNVERIFIED"
		if f.Verification.Verified {
			verifiedTag = "VERIFIED"
		}
		fmt.Fprintf(w, "    Verified:   %s (%s)\n", verifiedTag, f.Verification.Exploitability)
		if f.Verification.Analysis != "" {
			analysis := f.Verification.Analysis
			if len(analysis) > 120 {
				analysis = analysis[:117] + "..."
			}
			fmt.Fprintf(w, "    Analysis:   %s\n", analysis)
		}
	}

	// Add curl command for replication
	curlCmd := GenerateCurlFromFinding(&f)
	if curlCmd != "" {
		// Truncate long curl commands for display
		displayCmd := curlCmd
		if len(displayCmd) > 100 {
			displayCmd = displayCmd[:97] + "..."
		}
		fmt.Fprintf(w, "    Replicate:  %s\n", displayCmd)
	}

	fmt.Fprintf(w, "\n")
}

func (r *TextReporter) writeFooter(w io.Writer, result *types.ScanResult) {
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 70))
	fmt.Fprintf(w, "Scan completed at %s\n", result.EndTime.Format("2006-01-02 15:04 MST"))
	fmt.Fprintf(w, "Indago done: %d endpoints scanned, %d findings\n",
		result.Endpoints,
		result.Summary.TotalFindings)
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		mins := int(d.Minutes())
		secs := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm%02ds", mins, secs)
	}
	hours := int(d.Hours())
	mins := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh%02dm", hours, mins)
}
