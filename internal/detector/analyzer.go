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
	anomalyDetector      *AnomalyDetector
	errorDetector        *ErrorPatternDetector
	leakDetector         *DataLeakDetector
	enumerationDetector  *EnumerationDetector
	headerDetector       *SecurityHeaderDetector
	baselineCache        map[string]*types.HTTPResponse
}

// NewAnalyzer creates a new response analyzer
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		anomalyDetector:     NewAnomalyDetector(),
		errorDetector:       NewErrorPatternDetector(),
		leakDetector:        NewDataLeakDetector(),
		enumerationDetector: NewEnumerationDetector(),
		headerDetector:      NewSecurityHeaderDetector(),
		baselineCache:       make(map[string]*types.HTTPResponse),
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

	// Run all detectors (pass baseline to suppress pre-existing patterns)
	findings = append(findings, a.anomalyDetector.Detect(result, baseline)...)
	findings = append(findings, a.errorDetector.Detect(resp, req, baseline)...)
	findings = append(findings, a.leakDetector.Detect(resp, req, baseline)...)
	findings = append(findings, a.enumerationDetector.Detect(result, baseline)...)

	// Passive: check security headers (prefer baseline; fall back to fuzz response)
	headerResp := baseline
	if headerResp == nil {
		headerResp = resp
	}
	findings = append(findings, a.headerDetector.Detect(headerResp, req.Endpoint.Method, req.Endpoint.Path)...)

	// Add evidence to all findings
	for i := range findings {
		// Use the actual HTTP request if captured by the fuzzer, otherwise fall back to endpoint data
		var evidenceReq *types.HTTPRequest
		if result.ActualRequest != nil {
			evidenceReq = result.ActualRequest
		} else {
			evidenceReq = &types.HTTPRequest{
				Method:  req.Endpoint.Method,
				URL:     req.Endpoint.FullPath(),
				Headers: req.Endpoint.Headers,
			}
		}

		// Preserve any MatchedData already set by detectors
		var existingMatchedData []string
		if findings[i].Evidence != nil {
			existingMatchedData = findings[i].Evidence.MatchedData
		}

		findings[i].Evidence = &types.Evidence{
			Request:      evidenceReq,
			Response:     resp,
			MatchedData:  existingMatchedData,
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

// MatchWithData checks if a response matches the rule and returns the matched text
func (r *DetectionRule) MatchWithData(resp *types.HTTPResponse) (bool, string) {
	if r.Pattern != nil {
		if m := r.Pattern.FindString(resp.Body); m != "" {
			return true, m
		}
	}

	if r.Condition != nil {
		return r.Condition(resp), ""
	}

	return false, ""
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

// ToFindingWithData converts a rule match to a finding with matched data evidence
func (r *DetectionRule) ToFindingWithData(matchedData []string) types.Finding {
	f := r.ToFinding()
	if len(matchedData) > 0 {
		f.Evidence = &types.Evidence{
			MatchedData: matchedData,
		}
	}
	return f
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
	LDAPErrorPatterns     []*regexp.Regexp
	XPathErrorPatterns    []*regexp.Regexp
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
			regexp.MustCompile(`uid=\d+.*gid=\d+`),
			regexp.MustCompile(`root:x:0:0:`),
			regexp.MustCompile(`/bin/(ba)?sh`),
			regexp.MustCompile(`sh: \d+:`),
		},
		PathTraversalPatterns: []*regexp.Regexp{
			regexp.MustCompile(`root:.*:0:0:`),
			regexp.MustCompile(`\[boot loader\]`),
			regexp.MustCompile(`\[extensions\]`),
			regexp.MustCompile(`<?php`),
			regexp.MustCompile(`<%@`),
		},
		LDAPErrorPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)LDAP error`),
			regexp.MustCompile(`(?i)invalid DN syntax`),
			regexp.MustCompile(`(?i)javax\.naming`),
			regexp.MustCompile(`(?i)ldap_search`),
			regexp.MustCompile(`(?i)Invalid LDAP filter`),
			regexp.MustCompile(`(?i)Bad search filter`),
		},
		XPathErrorPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)XPathException`),
			regexp.MustCompile(`(?i)Invalid XPath`),
			regexp.MustCompile(`(?i)XPATH syntax error`),
			regexp.MustCompile(`(?i)javax\.xml\.xpath`),
			regexp.MustCompile(`(?i)lxml\.etree\.XPathEvalError`),
			regexp.MustCompile(`(?i)SimpleXMLElement::xpath`),
		},
	}
}

// CheckSQLInjection checks for SQL injection indicators and returns matched patterns
func (i *InjectionIndicators) CheckSQLInjection(body string) (bool, []string) {
	var matched []string
	for _, pattern := range i.SQLErrorPatterns {
		if m := pattern.FindString(body); m != "" {
			matched = append(matched, m)
		}
	}
	return len(matched) > 0, matched
}

// CheckNoSQLInjection checks for NoSQL injection indicators and returns matched patterns
func (i *InjectionIndicators) CheckNoSQLInjection(body string) (bool, []string) {
	var matched []string
	for _, pattern := range i.NoSQLErrorPatterns {
		if m := pattern.FindString(body); m != "" {
			matched = append(matched, m)
		}
	}
	return len(matched) > 0, matched
}

// CheckCommandInjection checks for command injection indicators and returns matched patterns
func (i *InjectionIndicators) CheckCommandInjection(body string) (bool, []string) {
	var matched []string
	for _, pattern := range i.CommandErrorPatterns {
		if m := pattern.FindString(body); m != "" {
			matched = append(matched, m)
		}
	}
	return len(matched) > 0, matched
}

// CheckPathTraversal checks for path traversal indicators and returns matched patterns
func (i *InjectionIndicators) CheckPathTraversal(body string) (bool, []string) {
	var matched []string
	for _, pattern := range i.PathTraversalPatterns {
		if m := pattern.FindString(body); m != "" {
			matched = append(matched, m)
		}
	}
	return len(matched) > 0, matched
}

// CheckLDAPInjection checks for LDAP injection indicators and returns matched patterns
func (i *InjectionIndicators) CheckLDAPInjection(body string) (bool, []string) {
	var matched []string
	for _, pattern := range i.LDAPErrorPatterns {
		if m := pattern.FindString(body); m != "" {
			matched = append(matched, m)
		}
	}
	return len(matched) > 0, matched
}

// CheckXPathInjection checks for XPath injection indicators and returns matched patterns
func (i *InjectionIndicators) CheckXPathInjection(body string) (bool, []string) {
	var matched []string
	for _, pattern := range i.XPathErrorPatterns {
		if m := pattern.FindString(body); m != "" {
			matched = append(matched, m)
		}
	}
	return len(matched) > 0, matched
}

// CheckXSSReflection checks if a payload is reflected in the response without encoding.
// Encoded output (&lt;, &gt;, &quot;) means the defense IS working — not a vulnerability.
func (i *InjectionIndicators) CheckXSSReflection(body, payload, contentType string) bool {
	// Skip detection for JSON APIs — JSON responses echo input by design
	// and reflected XSS does not apply in a JSON Content-Type context.
	if strings.Contains(strings.ToLower(contentType), "application/json") {
		return false
	}

	// Only trigger on raw/unencoded payload reflection
	return strings.Contains(body, payload)
}
