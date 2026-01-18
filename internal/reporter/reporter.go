// Package reporter provides output formatting for scan results
package reporter

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// Reporter interface for generating reports
type Reporter interface {
	// Generate generates a report from scan results
	Generate(result *types.ScanResult) ([]byte, error)

	// Write writes the report to a writer
	Write(result *types.ScanResult, w io.Writer) error

	// Format returns the report format name
	Format() string

	// Extension returns the file extension for this format
	Extension() string
}

// NewReporter creates a reporter based on format
func NewReporter(format string, options ReportOptions) (Reporter, error) {
	switch strings.ToLower(format) {
	case "json":
		return NewJSONReporter(options), nil
	case "html":
		return NewHTMLReporter(options), nil
	case "markdown", "md":
		return NewMarkdownReporter(options), nil
	case "sarif":
		return NewSARIFReporter(options), nil
	default:
		return nil, fmt.Errorf("unsupported report format: %s", format)
	}
}

// ReportOptions contains options for report generation
type ReportOptions struct {
	IncludeRaw    bool   // Include raw request/response
	IncludeConfig bool   // Include scan configuration
	Verbose       bool   // Verbose output
	Title         string // Custom report title
	OutputDir     string // Output directory for additional files
}

// DefaultOptions returns default report options
func DefaultOptions() ReportOptions {
	return ReportOptions{
		IncludeRaw:    true,
		IncludeConfig: true,
		Verbose:       false,
		Title:         "Indago Security Scan Report",
	}
}

// WriteToFile writes a report to a file
func WriteToFile(reporter Reporter, result *types.ScanResult, filename string) error {
	// Ensure directory exists
	dir := filepath.Dir(filename)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	return reporter.Write(result, file)
}

// MultiReporter generates reports in multiple formats
type MultiReporter struct {
	reporters []Reporter
}

// NewMultiReporter creates a multi-format reporter
func NewMultiReporter(formats []string, options ReportOptions) (*MultiReporter, error) {
	mr := &MultiReporter{
		reporters: make([]Reporter, 0, len(formats)),
	}

	for _, format := range formats {
		r, err := NewReporter(format, options)
		if err != nil {
			return nil, err
		}
		mr.reporters = append(mr.reporters, r)
	}

	return mr, nil
}

// WriteAll writes reports in all configured formats
func (mr *MultiReporter) WriteAll(result *types.ScanResult, basePath string) error {
	for _, r := range mr.reporters {
		filename := basePath + "." + r.Extension()
		if err := WriteToFile(r, result, filename); err != nil {
			return fmt.Errorf("failed to write %s report: %w", r.Format(), err)
		}
	}
	return nil
}

// SeverityColor returns ANSI color code for severity
func SeverityColor(severity string) string {
	switch severity {
	case types.SeverityCritical:
		return "\033[1;31m" // Bold red
	case types.SeverityHigh:
		return "\033[31m" // Red
	case types.SeverityMedium:
		return "\033[33m" // Yellow
	case types.SeverityLow:
		return "\033[34m" // Blue
	case types.SeverityInfo:
		return "\033[36m" // Cyan
	default:
		return "\033[0m" // Reset
	}
}

// ResetColor returns ANSI reset code
func ResetColor() string {
	return "\033[0m"
}

// SeverityIcon returns an icon for severity
func SeverityIcon(severity string) string {
	switch severity {
	case types.SeverityCritical:
		return "[!!!]"
	case types.SeverityHigh:
		return "[!!]"
	case types.SeverityMedium:
		return "[!]"
	case types.SeverityLow:
		return "[.]"
	case types.SeverityInfo:
		return "[i]"
	default:
		return "[-]"
	}
}

// TruncateString truncates a string to max length
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// EscapeHTML escapes HTML special characters
func EscapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

// EscapeMarkdown escapes Markdown special characters
func EscapeMarkdown(s string) string {
	chars := []string{"\\", "`", "*", "_", "{", "}", "[", "]", "(", ")", "#", "+", "-", ".", "!"}
	for _, c := range chars {
		s = strings.ReplaceAll(s, c, "\\"+c)
	}
	return s
}
