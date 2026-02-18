package detector

import (
	"regexp"
	"testing"
	"time"

	"github.com/su1ph3r/indago/internal/fuzzer"
	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

func TestNewAnalyzer(t *testing.T) {
	a := NewAnalyzer()

	if a == nil {
		t.Fatal("NewAnalyzer returned nil")
	}
	if a.anomalyDetector == nil {
		t.Error("anomalyDetector is nil")
	}
	if a.errorDetector == nil {
		t.Error("errorDetector is nil")
	}
	if a.leakDetector == nil {
		t.Error("leakDetector is nil")
	}
}

func TestAnalyzer_AnalyzeResult_NoResponse(t *testing.T) {
	a := NewAnalyzer()

	result := &fuzzer.FuzzResult{
		Request: &payloads.FuzzRequest{
			Endpoint: types.Endpoint{Method: "GET", Path: "/test"},
		},
		Response: nil,
		Error:    nil,
	}

	findings := a.AnalyzeResult(result, nil)

	if len(findings) != 0 {
		t.Errorf("expected no findings for nil response, got %d", len(findings))
	}
}

func TestAnalyzer_AnalyzeResult_WithError(t *testing.T) {
	a := NewAnalyzer()

	result := &fuzzer.FuzzResult{
		Request: &payloads.FuzzRequest{
			Endpoint: types.Endpoint{Method: "GET", Path: "/test"},
		},
		Response: &types.HTTPResponse{StatusCode: 200},
		Error:    &testError{msg: "connection timeout"},
	}

	findings := a.AnalyzeResult(result, nil)

	if len(findings) != 0 {
		t.Errorf("expected no findings when error is present, got %d", len(findings))
	}
}

func TestAnalyzer_AnalyzeResult_AddsEvidence(t *testing.T) {
	a := NewAnalyzer()

	endpoint := types.Endpoint{
		Method:  "GET",
		Path:    "/users/1",
		BaseURL: "https://api.example.com",
	}

	result := &fuzzer.FuzzResult{
		Request: &payloads.FuzzRequest{
			Endpoint: endpoint,
			Param:    &types.Parameter{Name: "id"},
			Payload:  payloads.Payload{Value: "' OR 1=1 --", Type: types.AttackSQLi},
		},
		Response: &types.HTTPResponse{
			StatusCode: 500,
			Body:       "SQL syntax error near '",
		},
		Timestamp: time.Now(),
	}

	findings := a.AnalyzeResult(result, nil)

	for _, f := range findings {
		if f.Evidence == nil {
			t.Error("finding should have evidence attached")
			continue
		}
		if f.Evidence.Request == nil {
			t.Error("evidence should have request")
		}
		if f.Evidence.Response == nil {
			t.Error("evidence should have response")
		}
		if f.Endpoint != endpoint.Path {
			t.Errorf("finding endpoint = %s, expected %s", f.Endpoint, endpoint.Path)
		}
		if f.Method != endpoint.Method {
			t.Errorf("finding method = %s, expected %s", f.Method, endpoint.Method)
		}
	}
}

func TestAnalyzer_SetBaseline(t *testing.T) {
	a := NewAnalyzer()

	endpoint := types.Endpoint{
		Method: "GET",
		Path:   "/test",
	}

	response := &types.HTTPResponse{
		StatusCode: 200,
		Body:       "normal response",
	}

	a.SetBaseline(endpoint, response)

	key := endpoint.Method + ":" + endpoint.Path
	cached := a.baselineCache[key]

	if cached == nil {
		t.Error("baseline was not cached")
	}
	if cached.Body != response.Body {
		t.Errorf("cached body = %s, expected %s", cached.Body, response.Body)
	}
}

func TestDetectionRule_Match(t *testing.T) {
	tests := []struct {
		name     string
		rule     DetectionRule
		response *types.HTTPResponse
		expected bool
	}{
		{
			name: "pattern match",
			rule: DetectionRule{
				Pattern: regexp.MustCompile(`SQL syntax`),
			},
			response: &types.HTTPResponse{Body: "Error: SQL syntax error"},
			expected: true,
		},
		{
			name: "pattern no match",
			rule: DetectionRule{
				Pattern: regexp.MustCompile(`SQL syntax`),
			},
			response: &types.HTTPResponse{Body: "OK"},
			expected: false,
		},
		{
			name: "condition match",
			rule: DetectionRule{
				Condition: func(resp *types.HTTPResponse) bool {
					return resp.StatusCode == 500
				},
			},
			response: &types.HTTPResponse{StatusCode: 500},
			expected: true,
		},
		{
			name: "condition no match",
			rule: DetectionRule{
				Condition: func(resp *types.HTTPResponse) bool {
					return resp.StatusCode == 500
				},
			},
			response: &types.HTTPResponse{StatusCode: 200},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.Match(tt.response)
			if result != tt.expected {
				t.Errorf("Match() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestDetectionRule_ToFinding(t *testing.T) {
	rule := DetectionRule{
		Name:        "SQL Injection",
		Description: "SQL injection vulnerability detected",
		Type:        types.AttackSQLi,
		Severity:    types.SeverityHigh,
		CWE:         "CWE-89",
		Remediation: "Use parameterized queries",
	}

	finding := rule.ToFinding()

	if finding.Title != rule.Name {
		t.Errorf("Title = %s, expected %s", finding.Title, rule.Name)
	}
	if finding.Description != rule.Description {
		t.Errorf("Description = %s, expected %s", finding.Description, rule.Description)
	}
	if finding.Type != rule.Type {
		t.Errorf("Type = %s, expected %s", finding.Type, rule.Type)
	}
	if finding.Severity != rule.Severity {
		t.Errorf("Severity = %s, expected %s", finding.Severity, rule.Severity)
	}
	if finding.CWE != rule.CWE {
		t.Errorf("CWE = %s, expected %s", finding.CWE, rule.CWE)
	}
}

func TestInjectionIndicators_CheckSQLInjection(t *testing.T) {
	indicators := NewInjectionIndicators()

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"MySQL error", "You have an error in your SQL syntax near MySQL", true},
		{"PostgreSQL error", "PostgreSQL ERROR: syntax error", true},
		{"Oracle error", "ORA-00933: SQL command not properly ended", true},
		{"SQLite error", "SQLite error: no such column", true},
		{"SQLSTATE", "SQLSTATE[42000]: Syntax error", true},
		{"clean response", "Welcome to the application", false},
		{"JSON response", `{"status": "ok", "data": []}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _ := indicators.CheckSQLInjection(tt.body)
			if result != tt.expected {
				t.Errorf("CheckSQLInjection(%q) = %v, expected %v", tt.body, result, tt.expected)
			}
		})
	}
}

func TestInjectionIndicators_CheckNoSQLInjection(t *testing.T) {
	indicators := NewInjectionIndicators()

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"MongoError", "MongoError: bad query", true},
		{"MongoDB error", "MongoDB error: invalid operator", true},
		{"$where error", "$where not allowed", true},
		{"clean response", "User not found", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _ := indicators.CheckNoSQLInjection(tt.body)
			if result != tt.expected {
				t.Errorf("CheckNoSQLInjection(%q) = %v, expected %v", tt.body, result, tt.expected)
			}
		})
	}
}

func TestInjectionIndicators_CheckCommandInjection(t *testing.T) {
	indicators := NewInjectionIndicators()

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"uid/gid output", "uid=1000(user) gid=1000(user)", true},
		{"passwd file", "root:x:0:0:root:/root:/bin/bash", true},
		{"sh error", "sh: 1: unknown: not found", true},
		{"permission denied is not cmd injection", "Permission denied", false},
		{"command not found is not cmd injection", "command not found", false},
		{"no such file is not cmd injection", "No such file or directory", false},
		{"clean response", "File processed successfully", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _ := indicators.CheckCommandInjection(tt.body)
			if result != tt.expected {
				t.Errorf("CheckCommandInjection(%q) = %v, expected %v", tt.body, result, tt.expected)
			}
		})
	}
}

func TestInjectionIndicators_CheckXSSReflection(t *testing.T) {
	indicators := NewInjectionIndicators()

	tests := []struct {
		name        string
		body        string
		payload     string
		contentType string
		expected    bool
	}{
		{"direct reflection", "<html><script>alert(1)</script></html>", "<script>alert(1)</script>", "text/html", true},
		{"no reflection", "<html>Hello World</html>", "<script>alert(1)</script>", "text/html", false},
		{"encoded reflection is not vuln", "<html>&lt;script&gt;alert(1)&lt;/script&gt;</html>", "<script>alert(1)</script>", "text/html", false},
		{"json content type skipped", `{"input":"<script>alert(1)</script>"}`, "<script>alert(1)</script>", "application/json", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := indicators.CheckXSSReflection(tt.body, tt.payload, tt.contentType)
			if result != tt.expected {
				t.Errorf("CheckXSSReflection() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// Helper types

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestInjectionIndicators_CheckLDAPInjection(t *testing.T) {
	indicators := NewInjectionIndicators()

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"ldap error", "LDAP error: invalid query", true},
		{"invalid dn syntax", "Error: invalid DN syntax", true},
		{"javax naming", "javax.naming.NamingException: connection refused", true},
		{"ldap search function", "ldap_search(): Search error", true},
		{"invalid ldap filter", "Invalid LDAP filter expression", true},
		{"bad search filter", "Bad search filter: (&(uid=*))", true},
		{"clean response", "Search results: 5 items found", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _ := indicators.CheckLDAPInjection(tt.body)
			if result != tt.expected {
				t.Errorf("CheckLDAPInjection(%q) = %v, expected %v", tt.body, result, tt.expected)
			}
		})
	}
}

func TestInjectionIndicators_CheckXPathInjection(t *testing.T) {
	indicators := NewInjectionIndicators()

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"xpath exception", "XPathException: invalid expression", true},
		{"invalid xpath", "Error: Invalid XPath query", true},
		{"xpath syntax error", "XPATH syntax error near position 5", true},
		{"javax xml xpath", "javax.xml.xpath.XPathExpressionException", true},
		{"lxml xpath error", "lxml.etree.XPathEvalError: invalid expression", true},
		{"simplexmlelement", "SimpleXMLElement::xpath(): error", true},
		{"clean response", "XML document parsed successfully", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _ := indicators.CheckXPathInjection(tt.body)
			if result != tt.expected {
				t.Errorf("CheckXPathInjection(%q) = %v, expected %v", tt.body, result, tt.expected)
			}
		})
	}
}

func TestInjectionIndicators_CheckPathTraversal(t *testing.T) {
	indicators := NewInjectionIndicators()

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"etc passwd", "root:x:0:0:root:/root:/bin/bash", true},
		{"boot loader", "[boot loader]\ntimeout=30", true},
		{"extensions section", "[extensions]\n; some config", true},
		{"php tag", "<?php echo 'hello'; ?>", true},
		{"asp tag", "<%@ Page Language=\"C#\" %>", true},
		{"clean response", "File not found", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _ := indicators.CheckPathTraversal(tt.body)
			if result != tt.expected {
				t.Errorf("CheckPathTraversal(%q) = %v, expected %v", tt.body, result, tt.expected)
			}
		})
	}
}
