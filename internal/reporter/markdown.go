package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// MarkdownReporter generates Markdown reports
type MarkdownReporter struct {
	options ReportOptions
}

// NewMarkdownReporter creates a new Markdown reporter
func NewMarkdownReporter(options ReportOptions) *MarkdownReporter {
	return &MarkdownReporter{options: options}
}

// Format returns the format name
func (r *MarkdownReporter) Format() string {
	return "markdown"
}

// Extension returns the file extension
func (r *MarkdownReporter) Extension() string {
	return "md"
}

// Generate generates a Markdown report
func (r *MarkdownReporter) Generate(result *types.ScanResult) ([]byte, error) {
	var buf strings.Builder
	if err := r.Write(result, &buf); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// Write writes the Markdown report to a writer
func (r *MarkdownReporter) Write(result *types.ScanResult, w io.Writer) error {
	// Title
	fmt.Fprintf(w, "# %s\n\n", r.options.Title)

	// Summary
	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "| Metric | Value |\n")
	fmt.Fprintf(w, "|--------|-------|\n")
	fmt.Fprintf(w, "| Target | `%s` |\n", result.Target)
	fmt.Fprintf(w, "| Scan ID | `%s` |\n", result.ScanID)
	fmt.Fprintf(w, "| Start Time | %s |\n", result.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "| End Time | %s |\n", result.EndTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "| Duration | %s |\n", result.Duration)
	fmt.Fprintf(w, "| Endpoints Scanned | %d |\n", result.Endpoints)
	fmt.Fprintf(w, "| Requests Made | %d |\n", result.Requests)
	fmt.Fprintf(w, "\n")

	// Severity breakdown
	fmt.Fprintf(w, "### Findings by Severity\n\n")
	fmt.Fprintf(w, "| Severity | Count |\n")
	fmt.Fprintf(w, "|----------|-------|\n")
	fmt.Fprintf(w, "| Critical | %d |\n", result.Summary.CriticalFindings)
	fmt.Fprintf(w, "| High | %d |\n", result.Summary.HighFindings)
	fmt.Fprintf(w, "| Medium | %d |\n", result.Summary.MediumFindings)
	fmt.Fprintf(w, "| Low | %d |\n", result.Summary.LowFindings)
	fmt.Fprintf(w, "| Info | %d |\n", result.Summary.InfoFindings)
	fmt.Fprintf(w, "| **Total** | **%d** |\n", result.Summary.TotalFindings)
	fmt.Fprintf(w, "\n")

	// Findings
	fmt.Fprintf(w, "## Findings\n\n")

	if len(result.Findings) == 0 {
		fmt.Fprintf(w, "_No findings detected._\n\n")
	} else {
		// Group by severity
		findingsBySeverity := map[string][]types.Finding{
			types.SeverityCritical: {},
			types.SeverityHigh:     {},
			types.SeverityMedium:   {},
			types.SeverityLow:      {},
			types.SeverityInfo:     {},
		}

		for _, f := range result.Findings {
			findingsBySeverity[f.Severity] = append(findingsBySeverity[f.Severity], f)
		}

		severityOrder := []string{
			types.SeverityCritical,
			types.SeverityHigh,
			types.SeverityMedium,
			types.SeverityLow,
			types.SeverityInfo,
		}

		for _, severity := range severityOrder {
			findings := findingsBySeverity[severity]
			if len(findings) == 0 {
				continue
			}

			fmt.Fprintf(w, "### %s Severity (%d)\n\n", strings.Title(severity), len(findings))

			for i, f := range findings {
				fmt.Fprintf(w, "#### %d. %s\n\n", i+1, f.Title)

				// Details table
				fmt.Fprintf(w, "| Property | Value |\n")
				fmt.Fprintf(w, "|----------|-------|\n")
				fmt.Fprintf(w, "| Type | `%s` |\n", f.Type)
				fmt.Fprintf(w, "| Confidence | %s |\n", f.Confidence)
				fmt.Fprintf(w, "| Endpoint | `%s %s` |\n", f.Method, f.Endpoint)
				if f.Parameter != "" {
					fmt.Fprintf(w, "| Parameter | `%s` |\n", f.Parameter)
				}
				if f.CWE != "" {
					fmt.Fprintf(w, "| CWE | %s |\n", f.CWE)
				}
				if f.CVSS > 0 {
					fmt.Fprintf(w, "| CVSS | %.1f |\n", f.CVSS)
				}
				fmt.Fprintf(w, "\n")

				// Description
				fmt.Fprintf(w, "**Description:**\n\n%s\n\n", f.Description)

				// Payload
				if f.Payload != "" {
					fmt.Fprintf(w, "**Payload:**\n\n```\n%s\n```\n\n", TruncateString(f.Payload, 500))
				}

				// Evidence
				if r.options.IncludeRaw && f.Evidence != nil {
					fmt.Fprintf(w, "<details>\n<summary>Evidence</summary>\n\n")

					if f.Evidence.Request != nil {
						fmt.Fprintf(w, "**Request:**\n```http\n%s %s\n", f.Evidence.Request.Method, f.Evidence.Request.URL)
						for k, v := range f.Evidence.Request.Headers {
							fmt.Fprintf(w, "%s: %s\n", k, v)
						}
						if f.Evidence.Request.Body != "" {
							fmt.Fprintf(w, "\n%s\n", TruncateString(f.Evidence.Request.Body, 500))
						}
						fmt.Fprintf(w, "```\n\n")
					}

					if f.Evidence.Response != nil {
						fmt.Fprintf(w, "**Response:**\n```http\nHTTP/1.1 %d %s\n", f.Evidence.Response.StatusCode, f.Evidence.Response.Status)
						for k, v := range f.Evidence.Response.Headers {
							fmt.Fprintf(w, "%s: %s\n", k, v)
						}
						fmt.Fprintf(w, "\n%s\n", TruncateString(f.Evidence.Response.Body, 1000))
						fmt.Fprintf(w, "```\n\n")
					}

					fmt.Fprintf(w, "</details>\n\n")
				}

				// Remediation
				if f.Remediation != "" {
					fmt.Fprintf(w, "**Remediation:**\n\n%s\n\n", f.Remediation)
				}

				fmt.Fprintf(w, "---\n\n")
			}
		}
	}

	// Footer
	fmt.Fprintf(w, "---\n\n")
	fmt.Fprintf(w, "_Report generated by Indago - AI-Powered API Security Fuzzer_\n")

	return nil
}
