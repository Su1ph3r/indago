package reporter

import (
	"encoding/json"
	"io"

	"github.com/su1ph3r/indago/pkg/types"
)

// JSONReporter generates JSON reports
type JSONReporter struct {
	options ReportOptions
}

// NewJSONReporter creates a new JSON reporter
func NewJSONReporter(options ReportOptions) *JSONReporter {
	return &JSONReporter{options: options}
}

// Format returns the format name
func (r *JSONReporter) Format() string {
	return "json"
}

// Extension returns the file extension
func (r *JSONReporter) Extension() string {
	return "json"
}

// Generate generates a JSON report
func (r *JSONReporter) Generate(result *types.ScanResult) ([]byte, error) {
	// Create a filtered result if needed
	output := r.prepareOutput(result)
	return json.MarshalIndent(output, "", "  ")
}

// Write writes the JSON report to a writer
func (r *JSONReporter) Write(result *types.ScanResult, w io.Writer) error {
	data, err := r.Generate(result)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// prepareOutput prepares the output structure
func (r *JSONReporter) prepareOutput(result *types.ScanResult) interface{} {
	// Sort findings by severity (critical first)
	SortFindingsBySeverity(result.Findings)

	if r.options.IncludeRaw && r.options.IncludeConfig {
		return result
	}

	// Create a filtered copy
	output := &JSONOutput{
		ScanID:    result.ScanID,
		Target:    result.Target,
		StartTime: result.StartTime.Format("2006-01-02T15:04:05Z07:00"),
		EndTime:   result.EndTime.Format("2006-01-02T15:04:05Z07:00"),
		Duration:  result.Duration.String(),
		Summary:   result.Summary,
		Endpoints: result.Endpoints,
		Requests:  result.Requests,
	}

	// Filter findings
	for _, f := range result.Findings {
		finding := JSONFinding{
			ID:          f.ID,
			Type:        f.Type,
			Severity:    f.Severity,
			Confidence:  f.Confidence,
			Title:       f.Title,
			Description: f.Description,
			Endpoint:    f.Endpoint,
			Method:      f.Method,
			Parameter:   f.Parameter,
			Payload:     f.Payload,
			CWE:         f.CWE,
			CVSS:        f.CVSS,
			Remediation: f.Remediation,
			Timestamp:   f.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
		}

		if r.options.IncludeRaw && f.Evidence != nil {
			finding.Evidence = &JSONEvidence{
				MatchedData: f.Evidence.MatchedData,
				Anomalies:   f.Evidence.Anomalies,
			}
			if f.Evidence.Request != nil {
				finding.Evidence.Request = &JSONRequest{
					Method:  f.Evidence.Request.Method,
					URL:     f.Evidence.Request.URL,
					Headers: f.Evidence.Request.Headers,
					Body:    f.Evidence.Request.Body,
				}
			}
			if f.Evidence.Response != nil {
				finding.Evidence.Response = &JSONResponse{
					StatusCode: f.Evidence.Response.StatusCode,
					Headers:    f.Evidence.Response.Headers,
					Body:       f.Evidence.Response.Body,
				}
			}
		}

		// Add curl command and replicate steps
		finding.CurlCommand = GenerateCurlFromFinding(&f)
		finding.ReplicateSteps = GenerateReplicateSteps(&f)

		output.Findings = append(output.Findings, finding)
	}

	if r.options.IncludeConfig {
		output.Config = result.Config
	}

	return output
}

// JSONOutput is the JSON output structure
type JSONOutput struct {
	ScanID    string             `json:"scan_id"`
	Target    string             `json:"target"`
	StartTime string             `json:"start_time"`
	EndTime   string             `json:"end_time"`
	Duration  string             `json:"duration"`
	Summary   *types.ScanSummary `json:"summary"`
	Findings  []JSONFinding      `json:"findings"`
	Endpoints int                `json:"endpoints_scanned"`
	Requests  int                `json:"requests_made"`
	Config    *types.ScanConfig  `json:"config,omitempty"`
}

// JSONFinding is a simplified finding structure
type JSONFinding struct {
	ID             string        `json:"id"`
	Type           string        `json:"type"`
	Severity       string        `json:"severity"`
	Confidence     string        `json:"confidence"`
	Title          string        `json:"title"`
	Description    string        `json:"description"`
	Endpoint       string        `json:"endpoint"`
	Method         string        `json:"method"`
	Parameter      string        `json:"parameter,omitempty"`
	Payload        string        `json:"payload,omitempty"`
	CWE            string        `json:"cwe,omitempty"`
	CVSS           float64       `json:"cvss,omitempty"`
	Remediation    string        `json:"remediation,omitempty"`
	Timestamp      string        `json:"timestamp"`
	Evidence       *JSONEvidence `json:"evidence,omitempty"`
	CurlCommand    string        `json:"curl_command,omitempty"`
	ReplicateSteps []string      `json:"replicate_steps,omitempty"`
}

// JSONEvidence is a simplified evidence structure
type JSONEvidence struct {
	Request     *JSONRequest  `json:"request,omitempty"`
	Response    *JSONResponse `json:"response,omitempty"`
	MatchedData []string      `json:"matched_data,omitempty"`
	Anomalies   []string      `json:"anomalies,omitempty"`
}

// JSONRequest is a simplified request structure
type JSONRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// JSONResponse is a simplified response structure
type JSONResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
}
