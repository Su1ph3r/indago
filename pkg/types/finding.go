package types

import (
	"time"
)

// Finding represents a discovered vulnerability or anomaly
type Finding struct {
	ID          string    `json:"id" yaml:"id"`
	Type        string    `json:"type" yaml:"type"`
	Severity    string    `json:"severity" yaml:"severity"` // critical, high, medium, low, info
	Confidence  string    `json:"confidence" yaml:"confidence"` // high, medium, low
	Title       string    `json:"title" yaml:"title"`
	Description string    `json:"description" yaml:"description"`
	Endpoint    string    `json:"endpoint" yaml:"endpoint"`
	Method      string    `json:"method" yaml:"method"`
	Parameter   string    `json:"parameter,omitempty" yaml:"parameter,omitempty"`
	Payload     string    `json:"payload,omitempty" yaml:"payload,omitempty"`
	Evidence    *Evidence `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Remediation string    `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	References  []string  `json:"references,omitempty" yaml:"references,omitempty"`
	CWE         string    `json:"cwe,omitempty" yaml:"cwe,omitempty"`
	CVSS        float64   `json:"cvss,omitempty" yaml:"cvss,omitempty"`
	Timestamp   time.Time `json:"timestamp" yaml:"timestamp"`
	Tags         []string          `json:"tags,omitempty" yaml:"tags,omitempty"`
	Verification *VerificationMeta `json:"verification,omitempty" yaml:"verification,omitempty"`
}

// VerificationMeta contains LLM verification results for a finding
type VerificationMeta struct {
	Verified           bool                 `json:"verified" yaml:"verified"`
	LLMConfidence      string               `json:"llm_confidence" yaml:"llm_confidence"`
	OriginalConfidence string               `json:"original_confidence" yaml:"original_confidence"`
	Exploitability     string               `json:"exploitability" yaml:"exploitability"`
	Analysis           string               `json:"analysis" yaml:"analysis"`
	SuggestedPayloads  []string             `json:"suggested_payloads,omitempty" yaml:"suggested_payloads,omitempty"`
	RelatedIssues      []string             `json:"related_issues,omitempty" yaml:"related_issues,omitempty"`
	ProviderName       string               `json:"provider_name" yaml:"provider_name"`
	ModelName          string               `json:"model_name" yaml:"model_name"`
	ConfirmationPasses []ConfirmationResult `json:"confirmation_passes,omitempty" yaml:"confirmation_passes,omitempty"`
}

// ConfirmationResult records the outcome of a single confirmation pass
type ConfirmationResult struct {
	PassNumber         int    `json:"pass_number"`
	PayloadsExecuted   int    `json:"payloads_executed"`
	ConfirmingFindings int    `json:"confirming_findings"`
	FinalExploitability string `json:"final_exploitability"`
	FinalConfidence    string `json:"final_confidence"`
	CombinedAnalysis   string `json:"combined_analysis"`
}

// Evidence contains proof of the finding
type Evidence struct {
	Request       *HTTPRequest  `json:"request" yaml:"request"`
	Response      *HTTPResponse `json:"response" yaml:"response"`
	MatchedData   []string      `json:"matched_data,omitempty" yaml:"matched_data,omitempty"`
	Anomalies     []string      `json:"anomalies,omitempty" yaml:"anomalies,omitempty"`
	BaselineResp  *HTTPResponse `json:"baseline_response,omitempty" yaml:"baseline_response,omitempty"`
	Screenshots   []string      `json:"screenshots,omitempty" yaml:"screenshots,omitempty"`
}

// HTTPRequest represents an HTTP request
type HTTPRequest struct {
	Method  string            `json:"method" yaml:"method"`
	URL     string            `json:"url" yaml:"url"`
	Headers map[string]string `json:"headers" yaml:"headers"`
	Body    string            `json:"body,omitempty" yaml:"body,omitempty"`
}

// HTTPResponse represents an HTTP response
type HTTPResponse struct {
	StatusCode    int               `json:"status_code" yaml:"status_code"`
	Status        string            `json:"status" yaml:"status"`
	Headers       map[string]string `json:"headers" yaml:"headers"`
	Body          string            `json:"body" yaml:"body"`
	ContentLength int64             `json:"content_length" yaml:"content_length"`
	ResponseTime  time.Duration     `json:"response_time" yaml:"response_time"`
}

// Severity constants
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Confidence constants
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// ScanResult contains the complete scan results
type ScanResult struct {
	ScanID      string        `json:"scan_id" yaml:"scan_id"`
	Target      string        `json:"target" yaml:"target"`
	StartTime   time.Time     `json:"start_time" yaml:"start_time"`
	EndTime     time.Time     `json:"end_time" yaml:"end_time"`
	Duration    time.Duration `json:"duration" yaml:"duration"`
	Findings    []Finding     `json:"findings" yaml:"findings"`
	Summary     *ScanSummary  `json:"summary" yaml:"summary"`
	Stats       *ScanStats    `json:"stats,omitempty" yaml:"stats,omitempty"`
	Endpoints   int           `json:"endpoints_scanned" yaml:"endpoints_scanned"`
	Requests    int           `json:"requests_made" yaml:"requests_made"`
	Errors      []ScanError   `json:"errors,omitempty" yaml:"errors,omitempty"`
	Config      *ScanConfig   `json:"config,omitempty" yaml:"config,omitempty"`
}

// ScanSummary provides statistics about the scan
type ScanSummary struct {
	TotalFindings    int            `json:"total_findings" yaml:"total_findings"`
	BySeverity       map[string]int `json:"by_severity" yaml:"by_severity"`
	ByType           map[string]int `json:"by_type" yaml:"by_type"`
	ByConfidence     map[string]int `json:"by_confidence" yaml:"by_confidence"`
	CriticalFindings int            `json:"critical_findings" yaml:"critical_findings"`
	HighFindings     int            `json:"high_findings" yaml:"high_findings"`
	MediumFindings   int            `json:"medium_findings" yaml:"medium_findings"`
	LowFindings      int            `json:"low_findings" yaml:"low_findings"`
	InfoFindings     int            `json:"info_findings" yaml:"info_findings"`
}

// ScanError represents an error during scanning
type ScanError struct {
	Endpoint  string    `json:"endpoint" yaml:"endpoint"`
	Error     string    `json:"error" yaml:"error"`
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
	Retried   bool      `json:"retried" yaml:"retried"`
}

// ScanConfig captures the configuration used for the scan
type ScanConfig struct {
	Provider     string   `json:"provider" yaml:"provider"`
	Model        string   `json:"model,omitempty" yaml:"model,omitempty"`
	InputFile    string   `json:"input_file" yaml:"input_file"`
	InputType    string   `json:"input_type" yaml:"input_type"`
	AttackTypes  []string `json:"attack_types,omitempty" yaml:"attack_types,omitempty"`
	Concurrency  int      `json:"concurrency" yaml:"concurrency"`
	RateLimit    float64  `json:"rate_limit" yaml:"rate_limit"`
	Timeout      int      `json:"timeout" yaml:"timeout"`
	ProxyURL     string   `json:"proxy_url,omitempty" yaml:"proxy_url,omitempty"`
}

// ScanStats provides timing and performance metrics for a scan
type ScanStats struct {
	TotalRequests     int           `json:"total_requests" yaml:"total_requests"`
	SuccessfulReqs    int           `json:"successful_requests" yaml:"successful_requests"`
	FailedReqs        int           `json:"failed_requests" yaml:"failed_requests"`
	TotalDuration     time.Duration `json:"total_duration" yaml:"total_duration"`
	AvgResponseTime   time.Duration `json:"avg_response_time" yaml:"avg_response_time"`
	MinResponseTime   time.Duration `json:"min_response_time" yaml:"min_response_time"`
	MaxResponseTime   time.Duration `json:"max_response_time" yaml:"max_response_time"`
	RequestsPerSecond float64       `json:"requests_per_second" yaml:"requests_per_second"`
	BytesSent         int64         `json:"bytes_sent" yaml:"bytes_sent"`
	BytesReceived     int64         `json:"bytes_received" yaml:"bytes_received"`
}

// NewScanStats creates a new ScanStats with default values
func NewScanStats() *ScanStats {
	return &ScanStats{
		MinResponseTime: time.Hour, // Initialize to large value
	}
}

// Update updates stats with a new request result
func (s *ScanStats) Update(duration time.Duration, success bool, respSize int64) {
	s.TotalRequests++
	if success {
		s.SuccessfulReqs++
	} else {
		s.FailedReqs++
	}

	s.BytesReceived += respSize

	if duration < s.MinResponseTime {
		s.MinResponseTime = duration
	}
	if duration > s.MaxResponseTime {
		s.MaxResponseTime = duration
	}
}

// Finalize calculates final statistics
func (s *ScanStats) Finalize(totalDuration time.Duration) {
	s.TotalDuration = totalDuration

	if totalDuration.Seconds() > 0 {
		s.RequestsPerSecond = float64(s.TotalRequests) / totalDuration.Seconds()
	}

	if s.SuccessfulReqs > 0 {
		// Calculate average response time (simplified)
		s.AvgResponseTime = totalDuration / time.Duration(s.SuccessfulReqs)
	}

	// Reset min if no requests were made
	if s.TotalRequests == 0 {
		s.MinResponseTime = 0
	}
}

// NewScanSummary creates a summary from findings
func NewScanSummary(findings []Finding) *ScanSummary {
	summary := &ScanSummary{
		TotalFindings: len(findings),
		BySeverity:    make(map[string]int),
		ByType:        make(map[string]int),
		ByConfidence:  make(map[string]int),
	}

	for _, f := range findings {
		summary.BySeverity[f.Severity]++
		summary.ByType[f.Type]++
		summary.ByConfidence[f.Confidence]++

		switch f.Severity {
		case SeverityCritical:
			summary.CriticalFindings++
		case SeverityHigh:
			summary.HighFindings++
		case SeverityMedium:
			summary.MediumFindings++
		case SeverityLow:
			summary.LowFindings++
		case SeverityInfo:
			summary.InfoFindings++
		}
	}

	return summary
}
