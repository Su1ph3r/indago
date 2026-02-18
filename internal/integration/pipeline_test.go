//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/su1ph3r/indago/internal/detector"
	"github.com/su1ph3r/indago/internal/fuzzer"
	"github.com/su1ph3r/indago/internal/parser"
	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/internal/reporter"
	"github.com/su1ph3r/indago/pkg/types"
)

// minimalOpenAPISpec is a minimal OpenAPI 3.0 spec with endpoints designed to
// trigger different detector paths (SQL errors, data leaks, normal responses).
const minimalOpenAPISpec = `openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
servers:
  - url: REPLACE_BASE_URL
paths:
  /users/{user_id}:
    get:
      operationId: getUser
      summary: Get user by ID
      parameters:
        - name: user_id
          in: path
          required: true
          schema:
            type: string
            example: "123"
      responses:
        "200":
          description: OK
  /search:
    get:
      operationId: searchItems
      summary: Search items
      parameters:
        - name: q
          in: query
          required: true
          schema:
            type: string
            example: "test"
      responses:
        "200":
          description: OK
  /login:
    post:
      operationId: loginUser
      summary: User login
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                password:
                  type: string
              required:
                - username
                - password
      responses:
        "200":
          description: OK
`

// testServer creates an httptest server that returns configurable responses.
// Requests to /search with SQL-injection-like payloads return a SQL error body.
// Requests to /users/* with certain payloads return sensitive data leak responses.
// All other requests return a normal 200 OK.
func testServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check query params and path for SQL injection markers
		rawQuery := r.URL.RawQuery
		path := r.URL.Path

		// Simulate SQL error on /search with single-quote payloads
		if strings.HasPrefix(path, "/search") && strings.Contains(rawQuery, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error": "SQL syntax error near MySQL: Unclosed quotation mark after the character string"}`)
			return
		}

		// Simulate data leak on /users paths with IDOR-like numeric IDs
		if strings.HasPrefix(path, "/users/") {
			segment := strings.TrimPrefix(path, "/users/")
			// If the segment looks like a manipulated ID (numeric but not the example "123"), return extra data
			if segment != "" && segment != "123" && isNumericish(segment) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"id": "%s", "email": "admin@example.com", "ssn": "123-45-6789", "password_hash": "$2a$10$abc"}`, segment)
				return
			}
		}

		// Normal response
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status": "ok"}`)
	}))
}

// isNumericish returns true if the string starts with a digit or is a common IDOR probe value.
func isNumericish(s string) bool {
	if len(s) == 0 {
		return false
	}
	c := s[0]
	return c >= '0' && c <= '9'
}

// TestFullPipeline exercises the complete scan pipeline end-to-end:
// parse -> generate payloads -> fuzz -> detect -> report.
func TestFullPipeline(t *testing.T) {
	// --- 1. Start test server ---
	ts := testServer()
	defer ts.Close()

	// --- 2. Write OpenAPI spec to temp file with server URL injected ---
	specContent := strings.Replace(minimalOpenAPISpec, "REPLACE_BASE_URL", ts.URL, 1)
	tmpDir := t.TempDir()
	specFile := filepath.Join(tmpDir, "api.yaml")
	if err := os.WriteFile(specFile, []byte(specContent), 0644); err != nil {
		t.Fatalf("failed to write spec file: %v", err)
	}

	// --- 3. Parse the OpenAPI spec ---
	p, err := parser.NewParser(specFile, "")
	if err != nil {
		t.Fatalf("failed to create parser: %v", err)
	}
	endpoints, err := p.Parse()
	if err != nil {
		t.Fatalf("failed to parse spec: %v", err)
	}
	if len(endpoints) == 0 {
		t.Fatal("parser returned zero endpoints")
	}
	t.Logf("Parsed %d endpoints", len(endpoints))

	// Verify expected endpoints exist
	endpointPaths := make(map[string]bool)
	for _, ep := range endpoints {
		endpointPaths[ep.Method+":"+ep.Path] = true
		t.Logf("  %s %s (params: %d)", ep.Method, ep.Path, len(ep.Parameters))
	}
	for _, want := range []string{"GET:/users/{user_id}", "GET:/search", "POST:/login"} {
		if !endpointPaths[want] {
			t.Errorf("expected endpoint %s not found in parsed results", want)
		}
	}

	// --- 4. Generate payloads (heuristic mode, no LLM) ---
	attackCfg := types.AttackSettings{
		Enabled:            []string{}, // all attacks
		Disabled:           []string{},
		MaxPayloadsPerType: 5, // keep small for test speed
		IDOR: types.IDORSettings{
			IDRange:   3,
			TestUUIDs: false,
			SwapUsers: false,
		},
		Injection: types.InjectionSettings{
			SQLi:    true,
			NoSQLi:  true,
			Command: true,
			SSTI:    true,
		},
	}
	gen := payloads.NewGenerator(nil, attackCfg, "")

	ctx := context.Background()
	var allRequests []payloads.FuzzRequest
	for _, ep := range endpoints {
		reqs := gen.GenerateForEndpoint(ctx, ep)
		allRequests = append(allRequests, reqs...)
	}
	if len(allRequests) == 0 {
		t.Fatal("payload generator produced zero fuzz requests")
	}
	t.Logf("Generated %d fuzz requests", len(allRequests))

	// --- 5. Configure and run the fuzzer engine ---
	cfg := *types.DefaultConfig()
	cfg.Scan.Concurrency = 5
	cfg.Scan.RateLimit = 100 // high for tests
	cfg.Scan.Timeout = 10 * time.Second
	cfg.Scan.MaxRetries = 0
	cfg.Scan.FollowRedirects = false

	engine := fuzzer.NewEngine(cfg)
	resultsCh := engine.Fuzz(ctx, allRequests)

	// --- 6. Collect results and analyze with detector ---
	analyzer := detector.NewAnalyzer()
	var allFindings []types.Finding
	var resultCount int

	for result := range resultsCh {
		resultCount++
		if result.Error != nil {
			continue
		}
		findings := analyzer.AnalyzeResult(result, nil)
		allFindings = append(allFindings, findings...)
	}

	t.Logf("Processed %d fuzz results", resultCount)
	t.Logf("Detected %d findings", len(allFindings))

	if resultCount == 0 {
		t.Fatal("fuzzer returned zero results")
	}

	// We expect at least some findings because our test server returns SQL error
	// responses for injection payloads on /search.
	if len(allFindings) == 0 {
		t.Error("expected at least one finding from SQL error responses, got zero")
	}

	// Log finding details for visibility
	for i, f := range allFindings {
		t.Logf("  Finding %d: [%s] %s - %s (endpoint: %s, param: %s)",
			i+1, f.Severity, f.Type, f.Title, f.Endpoint, f.Parameter)
	}

	// --- 7. Build ScanResult and write JSON report ---
	scanResult := &types.ScanResult{
		ScanID:    "integration-test-001",
		Target:    ts.URL,
		StartTime: time.Now().Add(-1 * time.Minute),
		EndTime:   time.Now(),
		Duration:  1 * time.Minute,
		Findings:  allFindings,
		Summary:   types.NewScanSummary(allFindings),
		Endpoints: len(endpoints),
		Requests:  resultCount,
	}

	jsonReporter, err := reporter.NewReporter("json", reporter.DefaultOptions())
	if err != nil {
		t.Fatalf("failed to create JSON reporter: %v", err)
	}

	// Write to buffer to validate JSON structure
	var buf bytes.Buffer
	if err := jsonReporter.Write(scanResult, &buf); err != nil {
		t.Fatalf("JSON reporter Write failed: %v", err)
	}

	// Validate JSON is well-formed
	if !json.Valid(buf.Bytes()) {
		t.Fatal("JSON report output is not valid JSON")
	}

	// Write to temp file as additional verification
	reportFile := filepath.Join(tmpDir, "report.json")
	if err := reporter.WriteToFile(jsonReporter, scanResult, reportFile); err != nil {
		t.Fatalf("WriteToFile failed: %v", err)
	}

	// Verify file exists and is non-empty
	info, err := os.Stat(reportFile)
	if err != nil {
		t.Fatalf("report file stat failed: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("report file is empty")
	}
	t.Logf("JSON report written: %s (%d bytes)", reportFile, info.Size())

	// --- 8. Verify JSON report content ---
	reportData, err := os.ReadFile(reportFile)
	if err != nil {
		t.Fatalf("failed to read report file: %v", err)
	}
	var reportObj map[string]interface{}
	if err := json.Unmarshal(reportData, &reportObj); err != nil {
		t.Fatalf("failed to unmarshal report JSON: %v", err)
	}

	// Check that essential fields are present
	for _, field := range []string{"scan_id", "target", "findings", "summary"} {
		if _, ok := reportObj[field]; !ok {
			t.Errorf("report JSON missing expected field: %s", field)
		}
	}

	// Verify summary counts match findings
	if summary, ok := reportObj["summary"].(map[string]interface{}); ok {
		if total, ok := summary["total_findings"].(float64); ok {
			if int(total) != len(allFindings) {
				t.Errorf("summary total_findings=%d, want %d", int(total), len(allFindings))
			}
		}
	}

	t.Log("Integration test pipeline completed successfully")
}

// TestPipelineNoFindings verifies the pipeline works cleanly when the target
// returns only normal responses (no vulnerabilities detected).
func TestPipelineNoFindings(t *testing.T) {
	// Server that always returns 200 OK with benign body
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status": "ok"}`)
	}))
	defer ts.Close()

	specContent := strings.Replace(minimalOpenAPISpec, "REPLACE_BASE_URL", ts.URL, 1)
	tmpDir := t.TempDir()
	specFile := filepath.Join(tmpDir, "api.yaml")
	if err := os.WriteFile(specFile, []byte(specContent), 0644); err != nil {
		t.Fatalf("failed to write spec: %v", err)
	}

	p, err := parser.NewParser(specFile, "")
	if err != nil {
		t.Fatalf("parser creation failed: %v", err)
	}
	endpoints, err := p.Parse()
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	attackCfg := types.AttackSettings{
		MaxPayloadsPerType: 3,
		Enabled:            []string{types.AttackSQLi}, // only SQLi to keep fast
		Injection:          types.InjectionSettings{SQLi: true},
	}
	gen := payloads.NewGenerator(nil, attackCfg, "")

	ctx := context.Background()
	var allRequests []payloads.FuzzRequest
	for _, ep := range endpoints {
		allRequests = append(allRequests, gen.GenerateForEndpoint(ctx, ep)...)
	}

	cfg := *types.DefaultConfig()
	cfg.Scan.Concurrency = 3
	cfg.Scan.RateLimit = 100
	cfg.Scan.Timeout = 10 * time.Second
	cfg.Scan.MaxRetries = 0
	cfg.Scan.FollowRedirects = false

	engine := fuzzer.NewEngine(cfg)
	resultsCh := engine.Fuzz(ctx, allRequests)

	analyzer := detector.NewAnalyzer()
	var findings []types.Finding
	for result := range resultsCh {
		if result.Error == nil {
			findings = append(findings, analyzer.AnalyzeResult(result, nil)...)
		}
	}

	// With a clean 200 OK server, we expect few or no true findings.
	// Some heuristic detectors may still fire (e.g., anomaly on status changes),
	// but we should not get SQL injection findings.
	for _, f := range findings {
		if f.Type == types.AttackSQLi {
			t.Errorf("unexpected SQLi finding from clean server: %s", f.Title)
		}
	}

	// Verify report generation still works with zero/few findings
	scanResult := &types.ScanResult{
		ScanID:    "integration-test-clean",
		Target:    ts.URL,
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Findings:  findings,
		Summary:   types.NewScanSummary(findings),
		Endpoints: len(endpoints),
		Requests:  len(allRequests),
	}

	jsonReporter, err := reporter.NewReporter("json", reporter.DefaultOptions())
	if err != nil {
		t.Fatalf("reporter creation failed: %v", err)
	}

	var buf bytes.Buffer
	if err := jsonReporter.Write(scanResult, &buf); err != nil {
		t.Fatalf("reporter write failed: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Fatal("JSON output is not valid")
	}

	t.Logf("Clean pipeline test completed: %d findings from clean server", len(findings))
}

// TestMultipleReportFormats verifies that all reporter formats produce valid output
// from the same scan result.
func TestMultipleReportFormats(t *testing.T) {
	// Construct a minimal ScanResult with one synthetic finding
	finding := types.Finding{
		ID:         "test-001",
		Type:       types.AttackSQLi,
		Severity:   types.SeverityHigh,
		Confidence: types.ConfidenceHigh,
		Title:      "SQL Injection in search parameter",
		Description: "The 'q' parameter is vulnerable to SQL injection.",
		Endpoint:   "/search",
		Method:     "GET",
		Parameter:  "q",
		Payload:    "' OR 1=1--",
		CWE:        "CWE-89",
		Timestamp:  time.Now(),
		Evidence: &types.Evidence{
			Request: &types.HTTPRequest{
				Method:  "GET",
				URL:     "http://localhost/search?q=' OR 1=1--",
				Headers: map[string]string{"User-Agent": "Indago/1.0"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 500,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       `{"error": "SQL syntax error near MySQL"}`,
			},
			MatchedData: []string{"SQL syntax error near MySQL"},
		},
	}

	scanResult := &types.ScanResult{
		ScanID:    "format-test",
		Target:    "http://localhost",
		StartTime: time.Now().Add(-30 * time.Second),
		EndTime:   time.Now(),
		Duration:  30 * time.Second,
		Findings:  []types.Finding{finding},
		Summary:   types.NewScanSummary([]types.Finding{finding}),
		Endpoints: 1,
		Requests:  10,
	}

	formats := []string{"json", "text", "markdown", "html", "sarif"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			r, err := reporter.NewReporter(format, reporter.DefaultOptions())
			if err != nil {
				t.Fatalf("failed to create %s reporter: %v", format, err)
			}

			var buf bytes.Buffer
			if err := r.Write(scanResult, &buf); err != nil {
				t.Fatalf("%s reporter Write failed: %v", format, err)
			}
			if buf.Len() == 0 {
				t.Fatalf("%s reporter produced empty output", format)
			}

			// For JSON and SARIF, verify valid JSON
			if format == "json" || format == "sarif" {
				if !json.Valid(buf.Bytes()) {
					t.Errorf("%s output is not valid JSON:\n%s", format, buf.String()[:min(500, buf.Len())])
				}
			}

			t.Logf("%s reporter produced %d bytes", format, buf.Len())
		})
	}
}
