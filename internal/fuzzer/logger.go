// Package fuzzer provides the core fuzzing engine
package fuzzer

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

// RequestLogger logs HTTP requests and responses to a file
type RequestLogger struct {
	mu      sync.Mutex
	file    *os.File
	encoder *json.Encoder
	count   int
	enabled bool
}

// LogEntry represents a logged request/response pair
type LogEntry struct {
	Timestamp    time.Time              `json:"timestamp"`
	RequestNum   int                    `json:"request_num"`
	Method       string                 `json:"method"`
	URL          string                 `json:"url"`
	Endpoint     string                 `json:"endpoint"`
	Parameter    string                 `json:"parameter,omitempty"`
	PayloadType  string                 `json:"payload_type,omitempty"`
	PayloadValue string                 `json:"payload_value,omitempty"`
	Request      *LoggedRequest         `json:"request,omitempty"`
	Response     *LoggedResponse        `json:"response,omitempty"`
	Duration     string                 `json:"duration"`
	Error        string                 `json:"error,omitempty"`
}

// LoggedRequest contains request details for logging
type LoggedRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// LoggedResponse contains response details for logging
type LoggedResponse struct {
	StatusCode    int               `json:"status_code"`
	Status        string            `json:"status"`
	Headers       map[string]string `json:"headers,omitempty"`
	ContentLength int64             `json:"content_length"`
	ResponseTime  string            `json:"response_time"`
	BodyPreview   string            `json:"body_preview,omitempty"`
}

// NewRequestLogger creates a new request logger
func NewRequestLogger(filePath string) (*RequestLogger, error) {
	if filePath == "" {
		return &RequestLogger{enabled: false}, nil
	}

	file, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create log file: %w", err)
	}

	// Write opening bracket for JSON array
	file.WriteString("[\n")

	return &RequestLogger{
		file:    file,
		encoder: json.NewEncoder(file),
		enabled: true,
	}, nil
}

// Log writes a request/response to the log file
func (l *RequestLogger) Log(result *FuzzResult) error {
	if !l.enabled || l.file == nil {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.count++

	entry := LogEntry{
		Timestamp:  result.Timestamp,
		RequestNum: l.count,
		Duration:   result.Duration.String(),
	}

	if result.Request != nil {
		req := result.Request
		entry.Method = req.Endpoint.Method
		entry.URL = req.Endpoint.FullPath()
		entry.Endpoint = req.Endpoint.Path
		entry.PayloadType = req.Payload.Type
		entry.PayloadValue = req.Payload.Value

		if req.Param != nil {
			entry.Parameter = req.Param.Name
		}

		entry.Request = &LoggedRequest{
			Method:  req.Endpoint.Method,
			URL:     req.Endpoint.FullPath(),
			Headers: req.Endpoint.Headers,
		}
	}

	if result.Response != nil {
		resp := result.Response
		entry.Response = &LoggedResponse{
			StatusCode:    resp.StatusCode,
			Status:        resp.Status,
			Headers:       resp.Headers,
			ContentLength: resp.ContentLength,
			ResponseTime:  resp.ResponseTime.String(),
		}

		// Include body preview (truncated)
		if len(resp.Body) > 0 {
			preview := resp.Body
			if len(preview) > 500 {
				preview = preview[:500] + "..."
			}
			entry.Response.BodyPreview = preview
		}
	}

	if result.Error != nil {
		entry.Error = result.Error.Error()
	}

	// Write comma separator after first entry
	if l.count > 1 {
		l.file.WriteString(",\n")
	}

	data, err := json.MarshalIndent(entry, "  ", "  ")
	if err != nil {
		return err
	}

	_, err = l.file.Write(append([]byte("  "), data...))
	return err
}

// Close closes the log file
func (l *RequestLogger) Close() error {
	if !l.enabled || l.file == nil {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Write closing bracket for JSON array
	l.file.WriteString("\n]\n")

	return l.file.Close()
}

// Count returns the number of logged entries
func (l *RequestLogger) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}

// DryRunSimulator simulates fuzzing without making actual requests
type DryRunSimulator struct {
	endpoints []types.Endpoint
	requests  []payloads.FuzzRequest
}

// NewDryRunSimulator creates a simulator for dry run mode
func NewDryRunSimulator() *DryRunSimulator {
	return &DryRunSimulator{}
}

// SimulateResult describes what would happen for a request
type SimulateResult struct {
	Endpoint    string
	Method      string
	Parameter   string
	Position    string
	PayloadType string
	Payload     string
	Description string
}

// Simulate returns what would be tested without making requests
func (d *DryRunSimulator) Simulate(requests []payloads.FuzzRequest) []SimulateResult {
	var results []SimulateResult

	for _, req := range requests {
		result := SimulateResult{
			Endpoint:    req.Endpoint.Path,
			Method:      req.Endpoint.Method,
			Position:    req.Position,
			PayloadType: req.Payload.Type,
			Payload:     req.Payload.Value,
			Description: req.Payload.Description,
		}

		if req.Param != nil {
			result.Parameter = req.Param.Name
		}

		results = append(results, result)
	}

	return results
}

// GroupByEndpoint groups simulation results by endpoint
func (d *DryRunSimulator) GroupByEndpoint(results []SimulateResult) map[string][]SimulateResult {
	grouped := make(map[string][]SimulateResult)

	for _, r := range results {
		key := r.Method + " " + r.Endpoint
		grouped[key] = append(grouped[key], r)
	}

	return grouped
}

// Summary returns a summary of what would be tested
type DryRunSummary struct {
	TotalRequests   int
	UniqueEndpoints int
	ByAttackType    map[string]int
	ByEndpoint      map[string]int
	ByParameter     map[string]int
}

// GetSummary returns a summary of the dry run
func (d *DryRunSimulator) GetSummary(results []SimulateResult) *DryRunSummary {
	summary := &DryRunSummary{
		TotalRequests: len(results),
		ByAttackType:  make(map[string]int),
		ByEndpoint:    make(map[string]int),
		ByParameter:   make(map[string]int),
	}

	endpoints := make(map[string]bool)

	for _, r := range results {
		key := r.Method + " " + r.Endpoint
		endpoints[key] = true
		summary.ByAttackType[r.PayloadType]++
		summary.ByEndpoint[key]++
		if r.Parameter != "" {
			summary.ByParameter[r.Parameter]++
		}
	}

	summary.UniqueEndpoints = len(endpoints)

	return summary
}
