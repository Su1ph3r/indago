// Package detector provides response analysis and vulnerability detection
package detector

import (
	"regexp"
	"strings"
	"time"

	"github.com/su1ph3r/indago/internal/fuzzer"
	"github.com/su1ph3r/indago/pkg/types"
)

// Analyzer analyzes fuzzing results to detect vulnerabilities
type Analyzer struct {
	anomalyDetector  *AnomalyDetector
	errorDetector    *ErrorPatternDetector
	leakDetector     *DataLeakDetector
	baselineCache    map[string]*types.HTTPResponse
}

// NewAnalyzer creates a new response analyzer
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		anomalyDetector:  NewAnomalyDetector(),
		errorDetector:    NewErrorPatternDetector(),
		leakDetector:     NewDataLeakDetector(),
		baselineCache:    make(map[string]*types.HTTPResponse),
	}
}

// AnalyzeResult analyzes a fuzz result and returns any findings
func (a *Analyzer) AnalyzeResult(result *fuzzer.FuzzResult, baseline *types.HTTPResponse) []types.Finding {
	var findings []types.Finding

	if result.Error != nil || result.Response == nil {
		return findings
	}

	resp := result.Response
	req := result.Request

	// Store baseline for later comparisons
	endpointKey := req.Endpoint.Method + ":" + req.Endpoint.Path
	if baseline != nil {
		a.baselineCache[endpointKey] = baseline
	} else {
		baseline = a.baselineCache[endpointKey]
	}

	// Run all detectors
	findings = append(findings, a.anomalyDetector.Detect(result, baseline)...)
	findings = append(findings, a.errorDetector.Detect(resp, req)...)
	findings = append(findings, a.leakDetector.Detect(resp, req)...)

	// Add evidence to all findings
	for i := range findings {
		findings[i].Evidence = &types.Evidence{
			Request: &types.HTTPRequest{
				Method:  req.Endpoint.Method,
				URL:     req.Endpoint.FullPath(),
				Headers: req.Endpoint.Headers,
			},
			Response:     resp,
			BaselineResp: baseline,
		}
		findings[i].Timestamp = result.Timestamp
		findings[i].Endpoint = req.Endpoint.Path
		findings[i].Method = req.Endpoint.Method
		if req.Param != nil {
			findings[i].Parameter = req.Param.Name
		}
		findings[i].Payload = req.Payload.Value
	}

	return findings
}

// SetBaseline sets the baseline response for an endpoint
func (a *Analyzer) SetBaseline(endpoint types.Endpoint, response *types.HTTPResponse) {
	key := endpoint.Method + ":" + endpoint.Path
	a.baselineCache[key] = response
}

// DetectionRule represents a detection rule
type DetectionRule struct {
	Name        string
	Description string
	Type        string
	Severity    string
	Pattern     *regexp.Regexp
	Condition   func(resp *types.HTTPResponse) bool
	CWE         string
	Remediation string
}

// Match checks if a response matches the rule
func (r *DetectionRule) Match(resp *types.HTTPResponse) bool {
	if r.Pattern != nil {
		if r.Pattern.MatchString(resp.Body) {
			return true
		}
	}

	if r.Condition != nil {
		return r.Condition(resp)
	}

	return false
}

// ToFinding converts a rule match to a finding
func (r *DetectionRule) ToFinding() types.Finding {
	return types.Finding{
		ID:          generateID(),
		Type:        r.Type,
		Severity:    r.Severity,
		Confidence:  types.ConfidenceHigh,
		Title:       r.Name,
		Description: r.Description,
		CWE:         r.CWE,
		Remediation: r.Remediation,
	}
}

// generateID generates a unique finding ID
func generateID() string {
	return time.Now().Format("20060102150405.000000")
}

// InjectionIndicators holds indicators of successful injection
type InjectionIndicators struct {
	SQLErrorPatterns      []*regexp.Regexp
	NoSQLErrorPatterns    []*regexp.Regexp
	CommandErrorPatterns  []*regexp.Regexp
	PathTraversalPatterns []*regexp.Regexp
	XSSReflectionPattern  func(payload string) *regexp.Regexp
}

// NewInjectionIndicators creates injection indicators
func NewInjectionIndicators() *InjectionIndicators {
	return &InjectionIndicators{
		SQLErrorPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)SQL syntax.*MySQL`),
			regexp.MustCompile(`(?i)Warning.*mysql_`),
			regexp.MustCompile(`(?i)PostgreSQL.*ERROR`),
			regexp.MustCompile(`(?i)Warning.*pg_`),
			regexp.MustCompile(`(?i)ORA-\d{5}`),
			regexp.MustCompile(`(?i)Microsoft.*ODBC.*SQL Server`),
			regexp.MustCompile(`(?i)\[Microsoft\]\[ODBC`),
			regexp.MustCompile(`(?i)SQLite.*error`),
			regexp.MustCompile(`(?i)Unclosed quotation mark`),
			regexp.MustCompile(`(?i)quoted string not properly terminated`),
			regexp.MustCompile(`(?i)syntax error at or near`),
			regexp.MustCompile(`(?i)mysql_fetch|mysql_num_rows`),
			regexp.MustCompile(`(?i)SQLSTATE\[\d+\]`),
		},
		NoSQLErrorPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)MongoError`),
			regexp.MustCompile(`(?i)MongoDB.*error`),
			regexp.MustCompile(`(?i)CouchDB.*error`),
			regexp.MustCompile(`(?i)\$where.*not allowed`),
			regexp.MustCompile(`(?i)operator.*requires`),
		},
		CommandErrorPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)uid=\d+.*gid=\d+`),
			regexp.MustCompile(`(?i)root:x:0:0:`),
			regexp.MustCompile(`(?i)/bin/bash`),
			regexp.MustCompile(`(?i)command not found`),
			regexp.MustCompile(`(?i)Permission denied`),
			regexp.MustCompile(`(?i)No such file or directory`),
			regexp.MustCompile(`(?i)sh: \d+:`),
		},
		PathTraversalPatterns: []*regexp.Regexp{
			regexp.MustCompile(`root:.*:0:0:`),
			regexp.MustCompile(`\[boot loader\]`),
			regexp.MustCompile(`\[extensions\]`),
			regexp.MustCompile(`<?php`),
			regexp.MustCompile(`<%@`),
		},
	}
}

// CheckSQLInjection checks for SQL injection indicators
func (i *InjectionIndicators) CheckSQLInjection(body string) bool {
	for _, pattern := range i.SQLErrorPatterns {
		if pattern.MatchString(body) {
			return true
		}
	}
	return false
}

// CheckNoSQLInjection checks for NoSQL injection indicators
func (i *InjectionIndicators) CheckNoSQLInjection(body string) bool {
	for _, pattern := range i.NoSQLErrorPatterns {
		if pattern.MatchString(body) {
			return true
		}
	}
	return false
}

// CheckCommandInjection checks for command injection indicators
func (i *InjectionIndicators) CheckCommandInjection(body string) bool {
	for _, pattern := range i.CommandErrorPatterns {
		if pattern.MatchString(body) {
			return true
		}
	}
	return false
}

// CheckPathTraversal checks for path traversal indicators
func (i *InjectionIndicators) CheckPathTraversal(body string) bool {
	for _, pattern := range i.PathTraversalPatterns {
		if pattern.MatchString(body) {
			return true
		}
	}
	return false
}

// CheckXSSReflection checks if a payload is reflected in the response
func (i *InjectionIndicators) CheckXSSReflection(body, payload string) bool {
	// Check for direct reflection
	if strings.Contains(body, payload) {
		return true
	}

	// Check for partially encoded reflection
	encodedPayloads := []string{
		strings.ReplaceAll(payload, "<", "&lt;"),
		strings.ReplaceAll(payload, ">", "&gt;"),
		strings.ReplaceAll(payload, "\"", "&quot;"),
	}

	for _, ep := range encodedPayloads {
		if strings.Contains(body, ep) {
			return true
		}
	}

	return false
}
