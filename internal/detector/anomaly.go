package detector

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/su1ph3r/indago/internal/fuzzer"
	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

// ssrfServicePattern represents a service fingerprint regex pattern
type ssrfServicePattern struct {
	name       string
	pattern    *regexp.Regexp
	severity   string
	confidence string
}

// ssrfServicePatterns are compiled once at package init to avoid per-call regex compilation
var ssrfServicePatterns = []ssrfServicePattern{
	{name: "Redis Protocol", pattern: regexp.MustCompile(`(?m)^(\+OK|\$\d+|-ERR)`), severity: types.SeverityHigh, confidence: types.ConfidenceHigh},
	{name: "Internal Admin Interface", pattern: regexp.MustCompile(`<title>.*(?:Admin|Login|Dashboard|Jenkins|GitLab).*</title>`), severity: types.SeverityHigh, confidence: types.ConfidenceMedium},
	{name: "Framework Error Page", pattern: regexp.MustCompile(`(?:Flask|Django|Tomcat|Node\.js|Express).*(?:Traceback|Exception|Error:|at )`), severity: types.SeverityMedium, confidence: types.ConfidenceMedium},
	{name: "Internal Hostname/IP", pattern: regexp.MustCompile(`(?:localhost|127\.0\.0\.1|192\.168\.|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2[0-9]|3[01])\.|\.local|\.internal)`), severity: types.SeverityHigh, confidence: types.ConfidenceMedium},
	{name: "AWS S3 Error", pattern: regexp.MustCompile(`<Error><Code>|x-amz-request-id`), severity: types.SeverityMedium, confidence: types.ConfidenceMedium},
}

// getHeaderCaseInsensitive performs a case-insensitive header lookup
func getHeaderCaseInsensitive(headers map[string]string, key string) string {
	lowerKey := strings.ToLower(key)
	for k, v := range headers {
		if strings.ToLower(k) == lowerKey {
			return v
		}
	}
	return ""
}

// AnomalyDetector detects anomalies in responses
type AnomalyDetector struct {
	comparator   *fuzzer.ResponseComparator
	indicators   *InjectionIndicators
	thresholds   AnomalyThresholds
}

// AnomalyThresholds defines thresholds for anomaly detection
type AnomalyThresholds struct {
	StatusCodeDiff     int
	ContentLengthDiff  int64
	ResponseTimeDiff   float64 // seconds
	SimilarityThreshold float64
}

// DefaultThresholds returns default anomaly thresholds
func DefaultThresholds() AnomalyThresholds {
	return AnomalyThresholds{
		StatusCodeDiff:     100,
		ContentLengthDiff:  1000,
		ResponseTimeDiff:   3.0,
		SimilarityThreshold: 0.7,
	}
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		comparator:  fuzzer.NewResponseComparator(0.1),
		indicators:  NewInjectionIndicators(),
		thresholds:  DefaultThresholds(),
	}
}

// Detect detects anomalies in a fuzz result
func (d *AnomalyDetector) Detect(result *fuzzer.FuzzResult, baseline *types.HTTPResponse) []types.Finding {
	var findings []types.Finding

	if result.Response == nil {
		return findings
	}

	resp := result.Response
	req := result.Request

	// Check for injection-specific indicators based on payload type
	switch req.Payload.Type {
	case types.AttackSQLi:
		if found, sqlMatches := d.indicators.CheckSQLInjection(resp.Body); found {
			// Check if the SQL error contains parameterized query evidence.
			// If the error shows prepared statement placeholders, the app is using
			// parameterized queries and is NOT vulnerable to SQL injection.
			// The real finding is information disclosure (stack trace / SQL error exposure).
			if resp.StatusCode >= 500 && containsParameterizedQuery(resp.Body) {
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        "information_disclosure",
					Severity:    types.SeverityMedium,
					Confidence:  types.ConfidenceHigh,
					Title:       "SQL Stack Trace Exposure (Parameterized Query)",
					Description: "SQL error messages with parameterized query placeholders found in response. The application uses prepared statements (not vulnerable to SQL injection), but exposes SQL stack traces that reveal database structure and query logic.",
					CWE:         "CWE-209",
					Remediation: "Suppress detailed SQL error messages in production. Return generic error responses and log details server-side.",
					Evidence:    &types.Evidence{MatchedData: sqlMatches},
				})
			} else {
				// Graduated confidence: HIGH if we have corroborating signals
				// (status code changed vs baseline OR multiple patterns matched),
				// MEDIUM if only a single SQL error pattern matched without baseline.
				sqliConfidence := types.ConfidenceMedium
				if len(sqlMatches) > 1 {
					sqliConfidence = types.ConfidenceHigh
				} else if baseline != nil && baseline.StatusCode != resp.StatusCode {
					sqliConfidence = types.ConfidenceHigh
				}
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        types.AttackSQLi,
					Severity:    types.SeverityHigh,
					Confidence:  sqliConfidence,
					Title:       "SQL Injection Detected",
					Description: "SQL error messages found in response, indicating potential SQL injection vulnerability",
					CWE:         "CWE-89",
					Remediation: "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
					Evidence:    &types.Evidence{MatchedData: sqlMatches},
				})
			}
		}

	case types.AttackNoSQLi:
		if found, nosqlMatches := d.indicators.CheckNoSQLInjection(resp.Body); found {
			// Single error pattern match = MEDIUM; multiple patterns = HIGH
			nosqlConfidence := types.ConfidenceMedium
			if len(nosqlMatches) > 1 {
				nosqlConfidence = types.ConfidenceHigh
			}
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackNoSQLi,
				Severity:    types.SeverityHigh,
				Confidence:  nosqlConfidence,
				Title:       "NoSQL Injection Detected",
				Description: "NoSQL error messages found in response, indicating potential NoSQL injection vulnerability",
				CWE:         "CWE-943",
				Remediation: "Validate and sanitize all user input. Use proper query builders and avoid eval-like constructs.",
				Evidence:    &types.Evidence{MatchedData: nosqlMatches},
			})
		}

	case types.AttackCommandInject:
		if found, cmdMatches := d.indicators.CheckCommandInjection(resp.Body); found {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackCommandInject,
				Severity:    types.SeverityCritical,
				Confidence:  types.ConfidenceHigh,
				Title:       "Command Injection Detected",
				Description: "System command output found in response, indicating command injection vulnerability",
				CWE:         "CWE-78",
				Remediation: "Avoid executing system commands with user input. If necessary, use allowlists and proper escaping.",
				Evidence:    &types.Evidence{MatchedData: cmdMatches},
			})
		}

	case types.AttackPathTraversal:
		if found, pathMatches := d.indicators.CheckPathTraversal(resp.Body); found {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackPathTraversal,
				Severity:    types.SeverityHigh,
				Confidence:  types.ConfidenceHigh,
				Title:       "Path Traversal Detected",
				Description: "File content found in response, indicating path traversal vulnerability",
				CWE:         "CWE-22",
				Remediation: "Validate file paths against an allowlist. Use canonical path resolution and sandbox file access.",
				Evidence:    &types.Evidence{MatchedData: pathMatches},
			})
		}

	case types.AttackXSS:
		contentType := resp.Headers["Content-Type"]
		if contentType == "" {
			contentType = resp.Headers["content-type"]
		}
		if d.indicators.CheckXSSReflection(resp.Body, req.Payload.Value, contentType) {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackXSS,
				Severity:    types.SeverityMedium,
				Confidence:  types.ConfidenceHigh,
				Title:       "Potential XSS - Payload Reflected",
				Description: "Input payload is reflected in the response without proper encoding",
				CWE:         "CWE-79",
				Remediation: "Implement proper output encoding based on context (HTML, JavaScript, URL, CSS).",
				Evidence:    &types.Evidence{MatchedData: []string{fmt.Sprintf("Reflected payload: %s", req.Payload.Value)}},
			})
		}

	case types.AttackMethodTampering:
		method, _ := req.Payload.Metadata["override_method"]
		if method == "TRACE" && resp.StatusCode == 200 {
			// TRACE is genuinely dangerous for cross-site tracing (XST) attacks
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackMethodTampering,
				Severity:    types.SeverityMedium,
				Confidence:  types.ConfidenceHigh,
				Title:       "TRACE Method Enabled",
				Description: "TRACE method is enabled, which can be used for cross-site tracing (XST) attacks",
				CWE:         "CWE-693",
				Remediation: "Disable TRACE method in production. Return 405 Method Not Allowed.",
			})
		}
		// For non-TRACE methods: only flag via baseline comparison (handled in compareWithBaseline)

	case types.AttackOpenRedirect:
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Headers["Location"]
			if location == "" {
				location = resp.Headers["location"]
			}
			if containsAttackerDomain(location) {
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        types.AttackOpenRedirect,
					Severity:    types.SeverityMedium,
					Confidence:  types.ConfidenceHigh,
					Title:       "Open Redirect Detected",
					Description: "The endpoint redirects to an attacker-controlled URL via the Location header",
					CWE:         "CWE-601",
					Remediation: "Validate redirect URLs against an allowlist of trusted domains. Never redirect to user-supplied URLs without validation.",
				})
			}
		}

	case types.AttackSSRF:
		ssrfFindings := d.detectSSRF(result, baseline)
		findings = append(findings, ssrfFindings...)

	case types.AttackSSTI:
		// SSTI generators send mathematically verifiable payloads
		payload := req.Payload.Value
		bodyStr := resp.Body
		detected := false
		// Check for {{7*7}} or ${7*7} → "49" (only if template syntax was consumed, not echoed)
		// Also require "49" to be absent from baseline to avoid false positives on pages with prices, IDs, etc.
		if (strings.Contains(payload, "{{7*7}}") || strings.Contains(payload, "${7*7}")) &&
			strings.Contains(bodyStr, "49") &&
			!strings.Contains(bodyStr, "{{7*7}}") && !strings.Contains(bodyStr, "${7*7}") &&
			(baseline == nil || !strings.Contains(baseline.Body, "49")) {
			detected = true
		}
		// Check for {{'7'*7}} → "7777777"
		if strings.Contains(payload, "{{'7'*7}}") && strings.Contains(bodyStr, "7777777") &&
			(baseline == nil || !strings.Contains(baseline.Body, "7777777")) {
			detected = true
		}
		if detected {
			sstiMatchData := []string{fmt.Sprintf("Payload: %s evaluated server-side", payload)}
			if strings.Contains(bodyStr, "49") {
				sstiMatchData = append(sstiMatchData, "Expression result: 49 (from 7*7)")
			}
			if strings.Contains(bodyStr, "7777777") {
				sstiMatchData = append(sstiMatchData, "Expression result: 7777777 (from '7'*7)")
			}
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackSSTI,
				Severity:    types.SeverityCritical,
				Confidence:  types.ConfidenceHigh,
				Title:       "Server-Side Template Injection (SSTI)",
				Description: "Template expression was evaluated by the server, confirming SSTI vulnerability",
				CWE:         "CWE-1336",
				Remediation: "Never pass user input directly into template engines. Use sandboxed template rendering.",
				Evidence:    &types.Evidence{MatchedData: sstiMatchData},
			})
		}
		// Check for template engine error messages
		sstiErrors := []string{"TemplateSyntaxError", "UndefinedError", "Jinja2", "Twig", "Freemarker"}
		for _, errStr := range sstiErrors {
			if strings.Contains(bodyStr, errStr) {
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        types.AttackSSTI,
					Severity:    types.SeverityHigh,
					Confidence:  types.ConfidenceMedium,
					Title:       "SSTI - Template Engine Error Exposed",
					Description: "Template engine error message found in response, suggesting potential SSTI",
					CWE:         "CWE-1336",
					Remediation: "Never pass user input directly into template engines. Suppress template error details in production.",
					Evidence:    &types.Evidence{MatchedData: []string{fmt.Sprintf("Template engine error: %s", errStr)}},
				})
				break
			}
		}

	case types.AttackLDAP:
		if found, ldapMatches := d.indicators.CheckLDAPInjection(resp.Body); found {
			// Single error pattern = MEDIUM; multiple patterns = HIGH
			ldapConfidence := types.ConfidenceMedium
			if len(ldapMatches) > 1 {
				ldapConfidence = types.ConfidenceHigh
			}
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackLDAP,
				Severity:    types.SeverityHigh,
				Confidence:  ldapConfidence,
				Title:       "LDAP Injection Detected",
				Description: "LDAP error messages found in response, indicating potential LDAP injection vulnerability",
				CWE:         "CWE-90",
				Remediation: "Validate and escape all user input before including in LDAP queries. Use parameterized LDAP searches.",
				Evidence:    &types.Evidence{MatchedData: ldapMatches},
			})
		}

	case types.AttackXPath:
		if found, xpathMatches := d.indicators.CheckXPathInjection(resp.Body); found {
			// Single error pattern = MEDIUM; multiple patterns = HIGH
			xpathConfidence := types.ConfidenceMedium
			if len(xpathMatches) > 1 {
				xpathConfidence = types.ConfidenceHigh
			}
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackXPath,
				Severity:    types.SeverityHigh,
				Confidence:  xpathConfidence,
				Title:       "XPath Injection Detected",
				Description: "XPath error messages found in response, indicating potential XPath injection vulnerability",
				CWE:         "CWE-643",
				Remediation: "Use parameterized XPath queries. Validate and sanitize user input before including in XPath expressions.",
				Evidence:    &types.Evidence{MatchedData: xpathMatches},
			})
		}

	case types.AttackGraphQLIntrospect:
		if strings.Contains(resp.Body, "__schema") || (strings.Contains(resp.Body, "__type") && strings.Contains(resp.Body, "fields")) {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackGraphQLIntrospect,
				Severity:    types.SeverityMedium,
				Confidence:  types.ConfidenceHigh,
				Title:       "GraphQL Introspection Enabled",
				Description: "GraphQL introspection is enabled, exposing the full API schema to attackers",
				CWE:         "CWE-200",
				Remediation: "Disable introspection in production. Use schema allowlists to limit exposed types.",
			})
		}

	case types.AttackGraphQLDepth:
		bodyLower := strings.ToLower(resp.Body)
		// Check for timing-based DoS
		if baseline != nil && baseline.ResponseTime > 0 && resp.ResponseTime > baseline.ResponseTime*3 {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackGraphQLDepth,
				Severity:    types.SeverityMedium,
				Confidence:  types.ConfidenceMedium,
				Title:       "GraphQL Deep Query DoS",
				Description: "Deep nested query caused significantly slower response time, suggesting potential denial of service",
				CWE:         "CWE-400",
				Remediation: "Implement query depth limiting and query complexity analysis.",
			})
		}
		// Check for depth limit errors (informational - server has protection)
		depthErrors := []string{"maximum query depth", "query complexity", "max depth exceeded", "query too complex"}
		for _, errStr := range depthErrors {
			if strings.Contains(bodyLower, errStr) {
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        types.AttackGraphQLDepth,
					Severity:    types.SeverityInfo,
					Confidence:  types.ConfidenceHigh,
					Title:       "GraphQL Depth Limiting Detected",
					Description: "Server implements query depth limiting, which is a positive security control",
				})
				break
			}
		}
		// Check for server errors from deep queries
		if resp.StatusCode >= 500 {
			crashErrors := []string{"stack overflow", "recursion", "maximum call stack"}
			for _, errStr := range crashErrors {
				if strings.Contains(bodyLower, errStr) {
					findings = append(findings, types.Finding{
						ID:          generateID(),
						Type:        types.AttackGraphQLDepth,
						Severity:    types.SeverityHigh,
						Confidence:  types.ConfidenceHigh,
						Title:       "GraphQL Deep Query Server Crash",
						Description: "Deep nested query caused a server error with recursion indicators, confirming DoS vulnerability",
						CWE:         "CWE-400",
						Remediation: "Implement query depth limits. Add query complexity scoring and reject complex queries.",
					})
					break
				}
			}
		}

	case types.AttackGraphQLBatch:
		bodyLower := strings.ToLower(resp.Body)
		// Check for timing-based batch DoS
		if baseline != nil && baseline.ResponseTime > 0 && resp.ResponseTime > baseline.ResponseTime*3 {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackGraphQLBatch,
				Severity:    types.SeverityMedium,
				Confidence:  types.ConfidenceMedium,
				Title:       "GraphQL Batch Query DoS",
				Description: "Batched query caused significantly slower response time, suggesting potential denial of service",
				CWE:         "CWE-400",
				Remediation: "Implement batch query limits. Restrict the number of operations per request.",
			})
		}
		// Check if response is a JSON array (batch response accepted)
		trimmed := strings.TrimSpace(resp.Body)
		if len(trimmed) > 1 && trimmed[0] == '[' && trimmed[len(trimmed)-1] == ']' {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackGraphQLBatch,
				Severity:    types.SeverityLow,
				Confidence:  types.ConfidenceMedium,
				Title:       "GraphQL Batch Queries Accepted",
				Description: "Server accepts batched GraphQL queries, which can be abused for DoS or rate limit bypass",
				CWE:         "CWE-400",
				Remediation: "Limit the number of queries allowed in a single batch request. Implement query cost analysis.",
			})
		}
		// Check for batch limit errors (server has protection)
		batchErrors := []string{"batch limit", "too many operations", "max batch size", "query limit exceeded"}
		for _, errStr := range batchErrors {
			if strings.Contains(bodyLower, errStr) {
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        types.AttackGraphQLBatch,
					Severity:    types.SeverityInfo,
					Confidence:  types.ConfidenceHigh,
					Title:       "GraphQL Batch Limiting Detected",
					Description: "Server implements batch query limiting, which is a positive security control",
				})
				break
			}
		}

	case types.AttackGraphQLAlias:
		bodyLower := strings.ToLower(resp.Body)
		// Check for timing-based alias DoS
		if baseline != nil && baseline.ResponseTime > 0 && resp.ResponseTime > baseline.ResponseTime*3 {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackGraphQLAlias,
				Severity:    types.SeverityMedium,
				Confidence:  types.ConfidenceMedium,
				Title:       "GraphQL Alias Overloading DoS",
				Description: "Query with many aliases caused significantly slower response time, suggesting potential denial of service",
				CWE:         "CWE-400",
				Remediation: "Implement alias count limits and query complexity analysis.",
			})
		}
		// Check for field suggestion patterns (information disclosure)
		suggestionPatterns := []string{"did you mean", "unknown field", "cannot query field", "field not found"}
		for _, pattern := range suggestionPatterns {
			if strings.Contains(bodyLower, pattern) {
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        types.AttackGraphQLAlias,
					Severity:    types.SeverityLow,
					Confidence:  types.ConfidenceHigh,
					Title:       "GraphQL Field Suggestion Disclosure",
					Description: "Server exposes field suggestions in error messages, which can aid schema enumeration",
					CWE:         "CWE-200",
					Remediation: "Disable field suggestions in production. Avoid exposing schema details in error messages.",
				})
				break
			}
		}
		// Check for alias limit errors (server has protection)
		aliasErrors := []string{"alias limit", "too many aliases", "max aliases exceeded"}
		for _, errStr := range aliasErrors {
			if strings.Contains(bodyLower, errStr) {
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        types.AttackGraphQLAlias,
					Severity:    types.SeverityInfo,
					Confidence:  types.ConfidenceHigh,
					Title:       "GraphQL Alias Limiting Detected",
					Description: "Server implements alias count limiting, which is a positive security control",
				})
				break
			}
		}

	case types.AttackMassAssignment:
		// Login/auth endpoints don't persist request body fields — skip mass assignment
		epLower := strings.ToLower(req.Endpoint.Path)
		if strings.Contains(epLower, "login") || strings.Contains(epLower, "signin") ||
			strings.Contains(epLower, "auth/token") || strings.Contains(epLower, "oauth") {
			break
		}

		field, hasField := req.Payload.Metadata["field"]
		value := req.Payload.Metadata["value"]
		if hasField && field != "" {
			fieldLower := strings.ToLower(field)
			isAdminRelevant := isAdminRelevantField(fieldLower)
			isGenericField := isGenericFormField(fieldLower)

			if isAdminRelevant {
				// Admin-relevant fields: flag on any 200/201 response (silent acceptance is dangerous)
				if resp.StatusCode == 200 || resp.StatusCode == 201 {
					confidence := types.ConfidenceMedium
					description := "The server accepted an injected privilege-related field, indicating mass assignment vulnerability"
					if value != "" && strings.Contains(resp.Body, value) {
						confidence = types.ConfidenceHigh
						description = "The server accepted an injected privilege-related field with the attacker-supplied value, confirming mass assignment vulnerability"
					}
					findings = append(findings, types.Finding{
						ID:          generateID(),
						Type:        types.AttackMassAssignment,
						Severity:    types.SeverityHigh,
						Confidence:  confidence,
						Title:       "Mass Assignment Vulnerability",
						Description: description,
						CWE:         "CWE-915",
						Remediation: "Use allowlists for accepted fields. Never bind user input directly to model objects.",
					})
				}
			} else if isGenericField {
				// Generic form fields: only flag if the response body contains evidence
				// that both the parameter name AND the payload value were accepted
				bodyLower := strings.ToLower(resp.Body)
				paramLower := fieldLower
				valueLower := strings.ToLower(value)
				if !strings.Contains(bodyLower, paramLower) || (valueLower != "" && !strings.Contains(bodyLower, valueLower)) {
					// No evidence the field was accepted — skip
					break
				}
				// Evidence found — flag it as evidence-based mass assignment
				if (resp.StatusCode == 200 || resp.StatusCode == 201) && strings.Contains(resp.Body, field) {
					confidence := types.ConfidenceMedium
					description := "The server accepted and returned a user-editable field with the attacker-supplied value, which may indicate mass assignment if the field should not be writable"
					if value != "" && strings.Contains(resp.Body, value) {
						confidence = types.ConfidenceHigh
					}
					findings = append(findings, types.Finding{
						ID:          generateID(),
						Type:        types.AttackMassAssignment,
						Severity:    types.SeverityHigh,
						Confidence:  confidence,
						Title:       "Mass Assignment Vulnerability",
						Description: description,
						CWE:         "CWE-915",
						Remediation: "Use allowlists for accepted fields. Never bind user input directly to model objects.",
					})
				}
			} else {
				// All other fields: flag on 200/201 but with low confidence
				if (resp.StatusCode == 200 || resp.StatusCode == 201) && strings.Contains(resp.Body, field) {
					confidence := types.ConfidenceLow
					description := "The server accepted and returned an injected field, which may indicate mass assignment vulnerability"
					if value != "" && strings.Contains(resp.Body, value) {
						confidence = types.ConfidenceMedium
						description = "The server accepted an injected field with the attacker-supplied value, indicating potential mass assignment vulnerability"
					}
					findings = append(findings, types.Finding{
						ID:          generateID(),
						Type:        types.AttackMassAssignment,
						Severity:    types.SeverityHigh,
						Confidence:  confidence,
						Title:       "Mass Assignment Vulnerability",
						Description: description,
						CWE:         "CWE-915",
						Remediation: "Use allowlists for accepted fields. Never bind user input directly to model objects.",
					})
				}
			}
		}

	case types.AttackXXE:
		bodyLower := strings.ToLower(resp.Body)
		// Check for file content indicators from XXE file read
		xxeFileIndicators := []string{"root:x:0:0", "root:*:0:0", "[boot loader]", "[operating systems]", "for 16-bit app support"}
		for _, indicator := range xxeFileIndicators {
			if strings.Contains(bodyLower, strings.ToLower(indicator)) {
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        types.AttackXXE,
					Severity:    types.SeverityCritical,
					Confidence:  types.ConfidenceHigh,
					Title:       "XXE - Local File Read",
					Description: "Response contains file content indicators, confirming XML External Entity file read vulnerability",
					CWE:         "CWE-611",
					Remediation: "Disable external entity processing in XML parsers. Use safe parser configurations (e.g., disallow DTDs).",
				})
				break
			}
		}
		// Check for XML parsing errors suggesting XXE processing
		xxeErrors := []string{"SAXParseException", "DOMException", "lxml.etree", "XMLSyntaxError",
			"simplexml_load", "DOMDocument", "xml.etree.ElementTree", "ENTITY", "DOCTYPE"}
		for _, errStr := range xxeErrors {
			if strings.Contains(resp.Body, errStr) {
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        types.AttackXXE,
					Severity:    types.SeverityMedium,
					Confidence:  types.ConfidenceMedium,
					Title:       "XXE - XML Parser Error Exposed",
					Description: "XML parser error message found in response, suggesting the server processes XML entities",
					CWE:         "CWE-611",
					Remediation: "Disable external entity processing. Suppress parser error details in production.",
				})
				break
			}
		}

	case types.AttackSmuggling:
		// Smuggling detection is inherently low-confidence via standard HTTP clients
		bodyLower := strings.ToLower(resp.Body)
		smugglingIndicators := []string{"400 bad request", "invalid request", "request timeout"}
		for _, indicator := range smugglingIndicators {
			if strings.Contains(bodyLower, indicator) && resp.StatusCode != 400 {
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        types.AttackSmuggling,
					Severity:    types.SeverityMedium,
					Confidence:  types.ConfidenceLow,
					Title:       "Potential HTTP Request Smuggling",
					Description: "Response contains error indicators that may suggest request smuggling. Manual verification recommended with raw TCP connections.",
					CWE:         "CWE-444",
					Remediation: "Ensure front-end and back-end servers agree on request boundaries. Normalize Transfer-Encoding and Content-Length handling.",
				})
				break
			}
		}
		// Check for CRLF injection success
		if strings.Contains(resp.Body, "X-Injected: true") || strings.Contains(resp.Body, "X-Injected:true") {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackSmuggling,
				Severity:    types.SeverityHigh,
				Confidence:  types.ConfidenceHigh,
				Title:       "HTTP Header Injection (CRLF)",
				Description: "Injected header was reflected in the response, confirming CRLF injection vulnerability",
				CWE:         "CWE-113",
				Remediation: "Sanitize all user input before including in HTTP headers. Strip CR and LF characters.",
			})
		}

	case types.AttackDeserialization:
		// Check for deserialization execution indicators (stack traces with gadget classes)
		javaGadgets := []string{"CommonsCollections", "InvokerTransformer", "ChainedTransformer",
			"java.io.InvalidClassException", "java.io.ObjectStreamException", "ClassNotFoundException"}
		for _, gadget := range javaGadgets {
			if strings.Contains(resp.Body, gadget) {
				// If the gadget name appears in the sent payload, it's just reflection, not deserialization
				if strings.Contains(req.Payload.Value, gadget) {
					continue
				}
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        types.AttackDeserialization,
					Severity:    types.SeverityCritical,
					Confidence:  types.ConfidenceHigh,
					Title:       "Insecure Deserialization - Java",
					Description: "Java deserialization class reference found in response, indicating the server processes serialized objects",
					CWE:         "CWE-502",
					Remediation: "Avoid deserializing untrusted data. Use allowlists for permitted classes. Prefer safe formats like JSON.",
				})
				break
			}
		}
		// Python deserialization errors
		pythonErrors := []string{"UnpicklingError", "yaml.constructor"}
		for _, errStr := range pythonErrors {
			if strings.Contains(resp.Body, errStr) {
				// If the indicator appears in the sent payload, it's just reflection
				if strings.Contains(req.Payload.Value, errStr) {
					continue
				}
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        types.AttackDeserialization,
					Severity:    types.SeverityHigh,
					Confidence:  types.ConfidenceMedium,
					Title:       "Insecure Deserialization - Python",
					Description: "Python deserialization error found in response, suggesting the server processes serialized Python objects",
					CWE:         "CWE-502",
					Remediation: "Never use unsafe deserialization on untrusted input. Use safe alternatives like json or yaml.safe_load.",
				})
				break
			}
		}
		// PHP deserialization indicators
		bodyLower := strings.ToLower(resp.Body)
		payloadLower := strings.ToLower(req.Payload.Value)
		phpUnserialize := strings.Contains(bodyLower, "unserialize()") && !strings.Contains(payloadLower, "unserialize()")
		phpWakeup := strings.Contains(resp.Body, "__wakeup") && !strings.Contains(req.Payload.Value, "__wakeup")
		phpDestruct := strings.Contains(resp.Body, "__destruct") && !strings.Contains(req.Payload.Value, "__destruct")
		if phpUnserialize || phpWakeup || phpDestruct {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackDeserialization,
				Severity:    types.SeverityHigh,
				Confidence:  types.ConfidenceMedium,
				Title:       "Insecure Deserialization - PHP",
				Description: "PHP deserialization indicator found in response, suggesting the server processes serialized PHP objects",
				CWE:         "CWE-502",
				Remediation: "Avoid using unserialize() on user input. Use JSON for data exchange.",
			})
		}
		// .NET deserialization
		dotnetBinary := strings.Contains(resp.Body, "BinaryFormatter") && !strings.Contains(req.Payload.Value, "BinaryFormatter")
		dotnetObject := strings.Contains(resp.Body, "ObjectStateFormatter") && !strings.Contains(req.Payload.Value, "ObjectStateFormatter")
		dotnetType := strings.Contains(resp.Body, "TypeNameHandling") && !strings.Contains(req.Payload.Value, "TypeNameHandling")
		if dotnetBinary || dotnetObject || dotnetType {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackDeserialization,
				Severity:    types.SeverityHigh,
				Confidence:  types.ConfidenceMedium,
				Title:       "Insecure Deserialization - .NET",
				Description: ".NET deserialization class reference found in response",
				CWE:         "CWE-502",
				Remediation: "Avoid BinaryFormatter and related insecure deserializers. Use JSON with strict type handling.",
			})
		}

	case types.AttackCachePoisoning:
		// Check for cache headers indicating the response was cached
		cacheHit := false
		for header, value := range resp.Headers {
			h := strings.ToLower(header)
			v := strings.ToLower(value)
			if (h == "x-cache" && strings.Contains(v, "hit")) ||
				(h == "cf-cache-status" && strings.Contains(v, "hit")) ||
				(h == "age" && value != "0") {
				cacheHit = true
				break
			}
		}
		// Check if injected content is reflected
		bodyLower := strings.ToLower(resp.Body)
		injectedContent := strings.Contains(bodyLower, "evil.com") || strings.Contains(bodyLower, "attacker.com")
		if cacheHit && injectedContent {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackCachePoisoning,
				Severity:    types.SeverityHigh,
				Confidence:  types.ConfidenceHigh,
				Title:       "Cache Poisoning - Injected Content Cached",
				Description: "Attacker-controlled content was reflected in a cached response, confirming cache poisoning vulnerability",
				CWE:         "CWE-349",
				Remediation: "Ensure cache keys include all relevant headers. Validate and sanitize unkeyed inputs.",
			})
		} else if injectedContent {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackCachePoisoning,
				Severity:    types.SeverityMedium,
				Confidence:  types.ConfidenceMedium,
				Title:       "Potential Cache Poisoning - Content Reflection",
				Description: "Attacker-controlled content from unkeyed headers was reflected in the response",
				CWE:         "CWE-349",
				Remediation: "Validate and sanitize values from forwarding headers. Include relevant headers in cache keys.",
			})
		}

	case types.AttackWebSocket:
		// WebSocket-specific detection
		if resp.StatusCode == 101 {
			origin := req.Payload.Metadata["origin"]
			if origin != "" {
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        types.AttackWebSocket,
					Severity:    types.SeverityHigh,
					Confidence:  types.ConfidenceHigh,
					Title:       "WebSocket Cross-Origin Accepted",
					Description: "WebSocket endpoint accepted a connection from a cross-origin source, enabling potential hijacking",
					CWE:         "CWE-346",
					Remediation: "Validate the Origin header on WebSocket handshakes. Only accept connections from trusted origins.",
				})
			}
			stripAuth := req.Payload.Metadata["strip_auth"]
			if stripAuth == "true" {
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        types.AttackWebSocket,
					Severity:    types.SeverityCritical,
					Confidence:  types.ConfidenceHigh,
					Title:       "WebSocket Authentication Bypass",
					Description: "WebSocket endpoint accepted a connection without authentication credentials",
					CWE:         "CWE-287",
					Remediation: "Require authentication for WebSocket connections. Validate tokens during the handshake.",
				})
			}
		}
		// Check for injection via WebSocket messages
		if strings.Contains(resp.Body, "<script>") || strings.Contains(resp.Body, "alert(1)") {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackWebSocket,
				Severity:    types.SeverityMedium,
				Confidence:  types.ConfidenceMedium,
				Title:       "WebSocket Message Injection - XSS",
				Description: "XSS payload sent via WebSocket was reflected in the response without sanitization",
				CWE:         "CWE-79",
				Remediation: "Sanitize and validate all WebSocket message content before processing or reflecting.",
			})
		}

	case types.AttackJWT:
		if resp.StatusCode == 200 || resp.StatusCode == 204 {
			attack := req.Payload.Metadata["attack"]
			switch attack {
			case "algorithm_confusion":
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        types.AttackJWT,
					Severity:    types.SeverityCritical,
					Confidence:  types.ConfidenceHigh,
					Title:       "JWT Algorithm Confusion (alg:none)",
					Description: "Server accepted a JWT with algorithm set to 'none', bypassing signature verification entirely",
					CWE:         "CWE-345",
					Remediation: "Reject JWTs with alg:none. Use a strict allowlist for accepted algorithms.",
				})
			case "missing_signature", "empty_signature", "null_signature", "truncated_signature", "invalid_signature":
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        types.AttackJWT,
					Severity:    types.SeverityCritical,
					Confidence:  types.ConfidenceHigh,
					Title:       "JWT Signature Bypass",
					Description: "Server accepted a JWT with a missing or invalid signature",
					CWE:         "CWE-345",
					Remediation: "Always validate JWT signatures. Reject tokens with missing, empty, or invalid signatures.",
				})
			case "claim_manipulation":
				// Only flag if baseline returned auth failure but this succeeded
				if baseline != nil && (baseline.StatusCode == 401 || baseline.StatusCode == 403) {
					findings = append(findings, types.Finding{
						ID:          generateID(),
						Type:        types.AttackJWT,
						Severity:    types.SeverityHigh,
						Confidence:  types.ConfidenceHigh,
						Title:       "JWT Claim Manipulation - Privilege Escalation",
						Description: "Modified JWT claims (e.g., role, scope) resulted in elevated access",
						CWE:         "CWE-287",
						Remediation: "Validate all JWT claims server-side. Do not trust client-supplied role or scope claims.",
					})
				}
			case "weak_secret":
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        types.AttackJWT,
					Severity:    types.SeverityHigh,
					Confidence:  types.ConfidenceHigh,
					Title:       "JWT Weak Signing Secret",
					Description: "Server accepted a JWT signed with a commonly-used weak secret",
					CWE:         "CWE-521",
					Remediation: "Use strong, randomly generated secrets for JWT signing. Minimum 256-bit entropy.",
				})
			}
		}
	}

	// Compare with baseline if available
	if baseline != nil {
		findings = append(findings, d.compareWithBaseline(result, baseline)...)
	}

	// Check status code anomalies
	findings = append(findings, d.checkStatusCodeAnomalies(resp, req)...)

	// Rate limit detection
	if resp.StatusCode == 429 {
		findings = append(findings, types.Finding{
			ID:          generateID(),
			Type:        "rate_limit",
			Severity:    types.SeverityInfo,
			Confidence:  types.ConfidenceHigh,
			Title:       "Rate Limiting Detected",
			Description: "Server returned 429 Too Many Requests, indicating active rate limiting",
		})
	}
	retryAfter := resp.Headers["Retry-After"]
	if retryAfter == "" {
		retryAfter = resp.Headers["retry-after"]
	}
	if retryAfter != "" {
		findings = append(findings, types.Finding{
			ID:          generateID(),
			Type:        "rate_limit",
			Severity:    types.SeverityInfo,
			Confidence:  types.ConfidenceHigh,
			Title:       "Retry-After Header Present",
			Description: fmt.Sprintf("Server specified Retry-After: %s", retryAfter),
		})
	}
	rateLimitRemaining := resp.Headers["X-RateLimit-Remaining"]
	if rateLimitRemaining == "" {
		rateLimitRemaining = resp.Headers["x-ratelimit-remaining"]
	}
	if rateLimitRemaining == "0" {
		findings = append(findings, types.Finding{
			ID:          generateID(),
			Type:        "rate_limit",
			Severity:    types.SeverityInfo,
			Confidence:  types.ConfidenceHigh,
			Title:       "Rate Limit Exhausted",
			Description: "X-RateLimit-Remaining is 0, indicating the rate limit quota has been exhausted",
		})
	}

	return findings
}

// detectSSRF performs comprehensive SSRF detection with multiple signals
func (d *AnomalyDetector) detectSSRF(result *fuzzer.FuzzResult, baseline *types.HTTPResponse) []types.Finding {
	var findings []types.Finding
	resp := result.Response

	// Run all detection methods
	if f := d.detectSSRFCloudMetadata(resp, baseline); f != nil {
		findings = append(findings, *f)
	}
	if f := d.detectSSRFDNSError(resp, baseline); f != nil {
		findings = append(findings, *f)
	}
	if f := d.detectSSRFStatusAnomaly(result, baseline); f != nil {
		findings = append(findings, *f)
	}
	if f := d.detectSSRFTimingAnomaly(result, baseline); f != nil {
		findings = append(findings, *f)
	}
	if f := d.detectSSRFContentAnomaly(result, baseline); f != nil {
		findings = append(findings, *f)
	}
	if f := d.detectSSRFServiceFingerprint(resp, baseline); f != nil {
		findings = append(findings, *f)
	}

	// Deduplicate findings with identical evidence
	return deduplicateFindings(findings)
}

// detectSSRFCloudMetadata checks for cloud metadata indicators (with baseline comparison)
func (d *AnomalyDetector) detectSSRFCloudMetadata(resp *types.HTTPResponse, baseline *types.HTTPResponse) *types.Finding {
	bodyLower := strings.ToLower(resp.Body)
	baselineBodyLower := ""
	if baseline != nil {
		baselineBodyLower = strings.ToLower(baseline.Body)
	}

	ssrfIndicators := []string{"ami-id", "instance-id", "iam/security-credentials", "169.254.169.254"}
	var ssrfMatchedIndicators []string
	for _, indicator := range ssrfIndicators {
		if strings.Contains(bodyLower, indicator) {
			// Only flag if baseline doesn't contain the same indicator (avoid false positives)
			if baseline == nil || !strings.Contains(baselineBodyLower, indicator) {
				ssrfMatchedIndicators = append(ssrfMatchedIndicators, fmt.Sprintf("Cloud metadata indicator: %s", indicator))
			}
		}
	}

	if len(ssrfMatchedIndicators) > 0 {
		return &types.Finding{
			ID:          generateID(),
			Type:        types.AttackSSRF,
			Severity:    types.SeverityCritical,
			Confidence:  types.ConfidenceHigh,
			Title:       "SSRF - Cloud Metadata Access",
			Description: "Response contains cloud metadata indicators, suggesting server-side request forgery to internal services",
			CWE:         "CWE-918",
			Remediation: "Validate and sanitize all user-supplied URLs. Block requests to internal/metadata IPs. Use allowlists for external requests.",
			Evidence:    &types.Evidence{MatchedData: ssrfMatchedIndicators},
		}
	}
	return nil
}

// detectSSRFDNSError checks for DNS resolution errors (with baseline comparison)
func (d *AnomalyDetector) detectSSRFDNSError(resp *types.HTTPResponse, baseline *types.HTTPResponse) *types.Finding {
	bodyLower := strings.ToLower(resp.Body)
	baselineBodyLower := ""
	if baseline != nil {
		baselineBodyLower = strings.ToLower(baseline.Body)
	}

	dnsErrors := []string{"resolve host", "name resolution", "no such host", "getaddrinfo"}
	for _, errStr := range dnsErrors {
		if strings.Contains(bodyLower, errStr) {
			// Only flag if baseline doesn't contain the same error pattern
			if baseline == nil || !strings.Contains(baselineBodyLower, errStr) {
				return &types.Finding{
					ID:          generateID(),
					Type:        types.AttackSSRF,
					Severity:    types.SeverityMedium,
					Confidence:  types.ConfidenceMedium,
					Title:       "SSRF - DNS Resolution Error Leak",
					Description: "DNS resolution error leaked in response, indicating the server attempted to resolve the attacker-supplied URL",
					CWE:         "CWE-918",
					Remediation: "Do not expose DNS resolution errors to users. Validate URLs before making server-side requests.",
					Evidence:    &types.Evidence{MatchedData: []string{fmt.Sprintf("DNS error pattern: %s", errStr)}},
				}
			}
		}
	}
	return nil
}

// detectSSRFStatusAnomaly detects suspicious status code changes indicating SSRF
func (d *AnomalyDetector) detectSSRFStatusAnomaly(result *fuzzer.FuzzResult, baseline *types.HTTPResponse) *types.Finding {
	if baseline == nil {
		return nil
	}

	resp := result.Response
	baselineStatus := baseline.StatusCode
	fuzzStatus := resp.StatusCode

	// Pattern 1: Baseline 200 → Fuzz 500/502/503 (server error reaching internal service)
	if baselineStatus == 200 && (fuzzStatus == 500 || fuzzStatus == 502 || fuzzStatus == 503) {
		return &types.Finding{
			ID:          generateID(),
			Type:        types.AttackSSRF,
			Severity:    types.SeverityHigh,
			Confidence:  types.ConfidenceMedium,
			Title:       "SSRF - Server Error on Internal Request",
			Description: fmt.Sprintf("Status changed from %d to %d, suggesting the server attempted to reach an internal service", baselineStatus, fuzzStatus),
			CWE:         "CWE-918",
			Remediation: "Validate and sanitize all user-supplied URLs. Block requests to internal/private IP ranges.",
			Evidence:    &types.Evidence{MatchedData: []string{fmt.Sprintf("Status transition: %d → %d", baselineStatus, fuzzStatus)}},
		}
	}

	// Pattern 2: Baseline 4xx → Fuzz 200 (accessed previously-forbidden resource)
	if baselineStatus >= 400 && baselineStatus < 500 && fuzzStatus == 200 {
		return &types.Finding{
			ID:          generateID(),
			Type:        types.AttackSSRF,
			Severity:    types.SeverityCritical,
			Confidence:  types.ConfidenceHigh,
			Title:       "SSRF - Access to Previously Forbidden Resource",
			Description: fmt.Sprintf("Status changed from %d to %d, indicating successful access to a previously restricted resource", baselineStatus, fuzzStatus),
			CWE:         "CWE-918",
			Remediation: "Implement strict URL validation and allowlists. Never trust user-supplied URLs for server-side requests.",
			Evidence:    &types.Evidence{MatchedData: []string{fmt.Sprintf("Status transition: %d → %d", baselineStatus, fuzzStatus)}},
		}
	}

	// Pattern 3: Baseline 200 → Fuzz 401/403 with WWW-Authenticate (hit internal service requiring auth)
	if baselineStatus == 200 && (fuzzStatus == 401 || fuzzStatus == 403) {
		authHeader := getHeaderCaseInsensitive(resp.Headers, "www-authenticate")
		if authHeader != "" {
			evidence := []string{fmt.Sprintf("Status transition: %d → %d", baselineStatus, fuzzStatus)}
			evidence = append(evidence, fmt.Sprintf("WWW-Authenticate header: %s", authHeader))
			return &types.Finding{
				ID:          generateID(),
				Type:        types.AttackSSRF,
				Severity:    types.SeverityHigh,
				Confidence:  types.ConfidenceMedium,
				Title:       "SSRF - Internal Service Authentication Challenge",
				Description: "Server received authentication challenge from internal service, confirming SSRF capability",
				CWE:         "CWE-918",
				Remediation: "Block requests to internal services. Implement URL allowlists for external resources only.",
				Evidence:    &types.Evidence{MatchedData: evidence},
			}
		}
	}

	return nil
}

// detectSSRFTimingAnomaly detects slow responses indicating internal network probes
func (d *AnomalyDetector) detectSSRFTimingAnomaly(result *fuzzer.FuzzResult, baseline *types.HTTPResponse) *types.Finding {
	if baseline == nil || baseline.ResponseTime == 0 {
		return nil
	}

	// Fuzz response time ≥ 3 seconds AND baseline < 1 second: likely internal network probe
	if result.Duration >= 3*time.Second && baseline.ResponseTime < 1*time.Second {
		timingRatio := float64(result.Duration) / float64(baseline.ResponseTime)
		if timingRatio >= 3.0 {
			delta := result.Duration - baseline.ResponseTime
			return &types.Finding{
				ID:          generateID(),
				Type:        types.AttackSSRF,
				Severity:    types.SeverityMedium,
				Confidence:  types.ConfidenceMedium,
				Title:       "SSRF - Timing Anomaly",
				Description: "Response time significantly increased, suggesting internal network probe or timeout",
				CWE:         "CWE-918",
				Remediation: "Validate URLs against allowlists. Implement timeouts for server-side requests.",
				Evidence: &types.Evidence{MatchedData: []string{
					fmt.Sprintf("Baseline: %v, Fuzz: %v (delta: +%v, ratio: %.1fx)", baseline.ResponseTime, result.Duration, delta, timingRatio),
				}},
			}
		}
	}

	return nil
}

// detectSSRFContentAnomaly detects significant content-length increases suggesting data exposure
func (d *AnomalyDetector) detectSSRFContentAnomaly(result *fuzzer.FuzzResult, baseline *types.HTTPResponse) *types.Finding {
	if baseline == nil {
		return nil
	}

	fuzzLen := result.Response.ContentLength
	baseLen := baseline.ContentLength

	if baseLen <= 0 || fuzzLen <= 0 {
		return nil // Avoid division by zero or negative sentinel values
	}

	lengthRatio := float64(fuzzLen) / float64(baseLen)
	lengthDelta := fuzzLen - baseLen

	// Fuzz content-length ≥ 10x baseline AND absolute difference ≥ 1KB
	if lengthRatio >= 10.0 && lengthDelta >= 1024 {
		return &types.Finding{
			ID:          generateID(),
			Type:        types.AttackSSRF,
			Severity:    types.SeverityMedium,
			Confidence:  types.ConfidenceMedium,
			Title:       "SSRF - Content Length Anomaly",
			Description: "Response size significantly increased, suggesting data exposure from internal service",
			CWE:         "CWE-918",
			Remediation: "Validate and filter server-side request responses. Implement size limits and content-type restrictions.",
			Evidence: &types.Evidence{MatchedData: []string{
				fmt.Sprintf("Baseline: %d bytes, Fuzz: %d bytes (delta: +%d, ratio: %.1fx)", baseLen, fuzzLen, lengthDelta, lengthRatio),
			}},
		}
	}

	return nil
}

// detectSSRFServiceFingerprint detects internal service response patterns
func (d *AnomalyDetector) detectSSRFServiceFingerprint(resp *types.HTTPResponse, baseline *types.HTTPResponse) *types.Finding {
	for _, p := range ssrfServicePatterns {
		if p.pattern.MatchString(resp.Body) {
			// Only flag if baseline doesn't match the same pattern
			if baseline == nil || !p.pattern.MatchString(baseline.Body) {
				// Extract matched text for evidence (limit to 100 chars)
				matched := p.pattern.FindString(resp.Body)
				if len(matched) > 100 {
					matched = matched[:100] + "..."
				}

				return &types.Finding{
					ID:          generateID(),
					Type:        types.AttackSSRF,
					Severity:    p.severity,
					Confidence:  p.confidence,
					Title:       fmt.Sprintf("SSRF - %s Detected", p.name),
					Description: fmt.Sprintf("Response contains fingerprint of internal service: %s", p.name),
					CWE:         "CWE-918",
					Remediation: "Block all requests to internal services and private IP ranges. Implement strict URL allowlists.",
					Evidence:    &types.Evidence{MatchedData: []string{fmt.Sprintf("Service fingerprint: %s", matched)}},
				}
			}
		}
	}

	return nil
}

// deduplicateFindings removes findings with identical evidence strings
func deduplicateFindings(findings []types.Finding) []types.Finding {
	if len(findings) <= 1 {
		return findings
	}

	seen := make(map[string]bool)
	result := make([]types.Finding, 0, len(findings))

	for _, f := range findings {
		// Create key from evidence data
		key := ""
		if f.Evidence != nil && len(f.Evidence.MatchedData) > 0 {
			key = strings.Join(f.Evidence.MatchedData, "|")
		} else {
			key = f.Title + "|" + f.Description
		}

		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}

	return result
}

// compareWithBaseline compares the response with a baseline
func (d *AnomalyDetector) compareWithBaseline(result *fuzzer.FuzzResult, baseline *types.HTTPResponse) []types.Finding {
	var findings []types.Finding

	comparison := d.comparator.Compare(baseline, result.Response)

	if !comparison.StatusCodeMatch {
		// Status code changed significantly
		if comparison.StatusCodeDiff > 0 && result.Response.StatusCode >= 500 {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        "error_triggered",
				Severity:    types.SeverityMedium,
				Confidence:  types.ConfidenceMedium,
				Title:       "Server Error Triggered",
				Description: "The payload caused the server to return an error response",
			})
		}

		// Auth status flip detection (baseline returned 401/403, fuzz got 200)
		if baseline.StatusCode == 401 || baseline.StatusCode == 403 {
			if result.Response.StatusCode >= 200 && result.Response.StatusCode < 300 {
				switch result.Request.Payload.Type {
				case types.AttackBOLA:
					// Skip BOLA on collection/listing endpoints that have no path parameter.
					// Endpoints like GET /users/v1 return 401 without auth and 200 with auth —
					// that's normal authentication, not broken object-level authorization.
					// BOLA requires a per-user object (path parameter like /users/{id}).
					endpointPath := result.Request.Endpoint.Path
					hasPathParam := strings.Contains(endpointPath, "{")
					if !hasPathParam && result.Request.Payload.Value != "" {
						segments := strings.Split(endpointPath, "/")
						for _, seg := range segments {
							if seg != "" && seg == result.Request.Payload.Value {
								hasPathParam = true
								break
							}
						}
					}
					if endpointPath == "" || !hasPathParam {
						break // Skip BOLA on collection endpoints
					}
					findings = append(findings, types.Finding{
						ID:          generateID(),
						Type:        types.AttackBOLA,
						Severity:    types.SeverityCritical,
						Confidence:  types.ConfidenceHigh,
						Title:       "Broken Object Level Authorization (BOLA)",
						Description: "Access to another user's object succeeded where baseline was denied, indicating broken authorization",
						CWE:         "CWE-639",
						Remediation: "Implement object-level authorization checks. Verify the requesting user owns the resource.",
					})
				case types.AttackBFLA:
					findings = append(findings, types.Finding{
						ID:          generateID(),
						Type:        types.AttackBFLA,
						Severity:    types.SeverityCritical,
						Confidence:  types.ConfidenceHigh,
						Title:       "Broken Function Level Authorization (BFLA)",
						Description: "Access to a privileged function succeeded where baseline was denied, indicating broken function-level authorization",
						CWE:         "CWE-285",
						Remediation: "Implement function-level authorization. Enforce role-based access controls on all administrative endpoints.",
					})
				default:
					findings = append(findings, types.Finding{
						ID:          generateID(),
						Type:        types.AttackAuthBypass,
						Severity:    types.SeverityCritical,
						Confidence:  types.ConfidenceHigh,
						Title:       "Authentication Bypass Detected",
						Description: "Payload resulted in successful access to a protected resource",
						CWE:         "CWE-287",
						Remediation: "Implement proper authentication checks on all protected endpoints.",
					})
				}
			}
		}
	}

	// 2xx→2xx BOLA detection via content comparison
	// When both baseline and fuzz response return success but content differs,
	// it may indicate access to a different user's object
	if baseline.StatusCode >= 200 && baseline.StatusCode < 300 &&
		result.Response.StatusCode >= 200 && result.Response.StatusCode < 300 {
		if result.Request.Payload.Type == types.AttackBOLA || result.Request.Payload.Type == types.AttackIDOR {
			baselineBody := baseline.Body
			fuzzBody := result.Response.Body
			method := strings.ToUpper(result.Request.Endpoint.Method)
			endpointPath := result.Request.Endpoint.Path

			// Skip collection/listing endpoints that have no path parameter.
			// Endpoints like GET /users/v1 or GET /books/v1 return shared resources
			// with no per-user object — identical responses are expected behavior,
			// not broken authorization. Only flag endpoints with path parameters
			// like /users/v1/{username} where object-level access matters.
			// Also skip empty endpoint paths (data quality issue).
			//
			// We check two patterns:
			// 1. Template parameters: path contains "{" (e.g. /users/{id})
			// 2. Concrete parameters: the payload value appears as a path segment
			//    (e.g. /users/v1/victim where payload is "victim")
			hasPathParam := strings.Contains(endpointPath, "{")
			if !hasPathParam && result.Request.Payload.Value != "" {
				// Check if the payload value appears as a segment in the path
				segments := strings.Split(endpointPath, "/")
				for _, seg := range segments {
					if seg != "" && seg == result.Request.Payload.Value {
						hasPathParam = true
						break
					}
				}
			}
			isCollectionEndpoint := endpointPath == "" || !hasPathParam

			if baselineBody != "" && fuzzBody != "" && baselineBody != fuzzBody {
				// If this is a collection endpoint (no path parameter) and responses
				// are very similar, skip — it's a shared listing, not BOLA.
				if isCollectionEndpoint {
					similarity := computeSimilarity(baselineBody, fuzzBody)
					if similarity > 0.95 {
						// Near-identical responses on a collection endpoint — skip
						goto skipBOLA
					}
				}

				confidence := types.ConfidenceMedium
				severity := types.SeverityHigh

				if (strings.HasPrefix(strings.TrimSpace(fuzzBody), "{") || strings.HasPrefix(strings.TrimSpace(fuzzBody), "[")) &&
					(strings.HasPrefix(strings.TrimSpace(baselineBody), "{") || strings.HasPrefix(strings.TrimSpace(baselineBody), "[")) {
					confidence = types.ConfidenceHigh
					severity = types.SeverityCritical
				}

				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        result.Request.Payload.Type,
					Severity:    severity,
					Confidence:  confidence,
					Title:       "Potential BOLA: Different Object Data Returned",
					Description: fmt.Sprintf("Substituting object identifier returned different content (baseline: %d bytes, fuzz: %d bytes). This suggests access to another user's object without proper authorization checks.", len(baselineBody), len(fuzzBody)),
					CWE:         "CWE-639",
					Remediation: "Implement object-level authorization checks. Verify the requesting user owns or is authorized to access the requested resource. Use --diff-auth with multiple user tokens for definitive confirmation.",
				})
			}

			// State-changing methods (PUT, DELETE, PATCH): identical success responses
			// for different users IS the vulnerability. If User B can PUT/DELETE/PATCH
			// User A's resource and gets the same success response, authorization is broken.
			// This includes 204 No Content where both bodies are empty — a 2xx with empty
			// body on a state-changing method means the operation succeeded.
			if (method == "PUT" || method == "DELETE" || method == "PATCH") && baselineBody == fuzzBody {
				// Skip collection endpoints with identical responses on GET-like reads.
				// But for state-changing methods, only skip if it's a collection endpoint
				// with no path parameter — these cannot target a specific object.
				if isCollectionEndpoint {
					goto skipBOLA
				}

				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        result.Request.Payload.Type,
					Severity:    types.SeverityHigh,
					Confidence:  types.ConfidenceHigh,
					Title:       "BOLA: State-Changing Operation Succeeded for Different User",
					Description: fmt.Sprintf("%s request with a substituted object identifier returned identical success response (baseline: %d, fuzz: %d), indicating the server does not verify resource ownership for state-changing operations.", method, baseline.StatusCode, result.Response.StatusCode),
					CWE:         "CWE-639",
					Remediation: "Implement object-level authorization checks for all state-changing operations. Verify the requesting user owns the resource before allowing modifications or deletions.",
				})
			}
		skipBOLA:
		}
	}

	// 4xx/5xx → 2xx BOLA detection for state-changing methods
	// When the baseline returns an error (e.g. 400 missing body) but the fuzz request
	// with a different identifier succeeds (2xx), the server is not enforcing ownership.
	if baseline.StatusCode >= 400 &&
		result.Response.StatusCode >= 200 && result.Response.StatusCode < 300 {
		if result.Request.Payload.Type == types.AttackBOLA || result.Request.Payload.Type == types.AttackIDOR {
			method := strings.ToUpper(result.Request.Endpoint.Method)
			if method == "PUT" || method == "DELETE" || method == "PATCH" {
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        result.Request.Payload.Type,
					Severity:    types.SeverityHigh,
					Confidence:  types.ConfidenceHigh,
					Title:       "BOLA: State-Changing Operation Succeeded with Different Identifier",
					Description: fmt.Sprintf("%s request with a substituted identifier returned success (fuzz: %d) while baseline returned error (baseline: %d), indicating the server does not enforce resource ownership for state-changing operations.", method, result.Response.StatusCode, baseline.StatusCode),
					CWE:         "CWE-639",
					Remediation: "Implement object-level authorization checks for all state-changing operations. Verify the requesting user owns the resource before allowing modifications or deletions.",
				})
			}
		}
	}

	// Content length changed significantly
	if comparison.ContentLengthDiff > d.thresholds.ContentLengthDiff {
		findings = append(findings, types.Finding{
			ID:          generateID(),
			Type:        "content_anomaly",
			Severity:    types.SeverityLow,
			Confidence:  types.ConfidenceLow,
			Title:       "Response Content Anomaly",
			Description: "Response size differs significantly from baseline, which may indicate information disclosure",
		})
	}

	// Time-based blind injection detection
	if result.Response.ResponseTime > 0 && baseline.ResponseTime > 0 {
		timingThreshold := time.Duration(d.thresholds.ResponseTimeDiff * float64(time.Second))
		if result.Response.ResponseTime > baseline.ResponseTime+timingThreshold {
			payloadLower := strings.ToLower(result.Request.Payload.Value)
			isTimingPayload := strings.Contains(payloadLower, "sleep") ||
				strings.Contains(payloadLower, "waitfor") ||
				strings.Contains(payloadLower, "pg_sleep") ||
				strings.Contains(payloadLower, "benchmark(")

			if isTimingPayload {
				blindType := result.Request.Payload.Type
				cwe := "CWE-89" // default SQL injection
				switch blindType {
				case types.AttackCommandInject:
					cwe = "CWE-78"
				case types.AttackNoSQLi:
					cwe = "CWE-943"
				case types.AttackLDAP:
					cwe = "CWE-90"
				case types.AttackXPath:
					cwe = "CWE-643"
				case types.AttackSSTI:
					cwe = "CWE-1336"
				}
				// Time-based blind: response time exceeded threshold but no other
				// confirming indicators = MEDIUM confidence
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        blindType,
					Severity:    types.SeverityHigh,
					Confidence:  types.ConfidenceMedium,
					Title:       "Blind Time-Based Injection Detected",
					Description: "Response time significantly exceeded baseline after injecting a time-delay payload, indicating blind injection vulnerability",
					CWE:         cwe,
					Remediation: "Use parameterized queries. Never concatenate user input into queries or commands.",
				})
			}
		}
	}

	return findings
}

// parameterizedQueryPatterns matches common parameterized query placeholder styles.
// These indicate the application uses prepared statements, not string concatenation.
var parameterizedQueryPatterns = []*regexp.Regexp{
	// Generic positional placeholders: VALUES (?, ?, ?) or WHERE id = ? or AND status = ?
	regexp.MustCompile(`(?i)(?:VALUES|SET|WHERE|AND|OR)\s*(?:\(?\s*\w*\s*=?\s*)?(?:\?\s*,\s*)*\?`),
	// PostgreSQL-style: $1, $2, etc.
	regexp.MustCompile(`\$\d+`),
	// Oracle/named parameter style: :param_name in SQL context
	regexp.MustCompile(`(?i)(?:VALUES|SET|WHERE|AND|OR)\s*(?:\(?\s*\w*\s*=?\s*)?(?::\w+\s*,\s*)*:\w+`),
	// Python DB-API style: %s in SQL context
	regexp.MustCompile(`(?i)(?:VALUES|SET|WHERE|AND|OR)\s*(?:\(?\s*\w*\s*=?\s*)?(?:%s\s*,\s*)*%s`),
}

// containsParameterizedQuery checks if the response body contains evidence of
// parameterized/prepared statement placeholders in SQL statements.
func containsParameterizedQuery(body string) bool {
	for _, pattern := range parameterizedQueryPatterns {
		if pattern.MatchString(body) {
			return true
		}
	}
	return false
}

// containsAttackerDomain checks if a URL's hostname matches an attacker-controlled domain.
func containsAttackerDomain(location string) bool {
	u, err := url.Parse(location)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	attackerDomains := []string{"evil.com", "evil-cors-test.com"}
	for _, domain := range attackerDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

// isAdminRelevantField checks if a field name indicates a privilege-related attribute
// that would constitute a real mass assignment vulnerability if accepted.
func isAdminRelevantField(fieldLower string) bool {
	adminKeywords := []string{
		"admin", "role", "privilege", "permission", "is_admin", "isadmin",
		"level", "group", "scope", "superuser", "staff", "moderator",
		"verified", "active", "enabled", "disabled", "banned", "locked",
		"tier", "plan", "subscription", "credit", "balance",
	}
	for _, keyword := range adminKeywords {
		if strings.Contains(fieldLower, keyword) {
			return true
		}
	}
	return false
}

// isGenericFormField checks if a field name is a normal user-editable form field
// that should not be flagged as mass assignment.
func isGenericFormField(fieldLower string) bool {
	genericFields := []string{
		"email", "password", "username", "name", "first_name", "last_name",
		"firstname", "lastname", "phone", "address", "city", "state", "zip",
		"country", "bio", "avatar", "profile", "description", "title",
		"website", "url", "company", "organization", "department",
		"book_title", "book_name", "display_name", "nickname",
	}
	for _, field := range genericFields {
		if fieldLower == field {
			return true
		}
	}
	return false
}

// computeSimilarity returns a similarity ratio (0.0 to 1.0) between two strings.
// Uses a simple length-based heuristic combined with prefix/suffix matching.
// Returns 1.0 for identical strings, 0.0 for completely different strings.
func computeSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	// Length ratio as a baseline
	shorter, longer := len(a), len(b)
	if shorter > longer {
		shorter, longer = longer, shorter
	}
	lengthRatio := float64(shorter) / float64(longer)

	// Count matching characters from the start
	prefixMatch := 0
	limit := shorter
	for i := 0; i < limit; i++ {
		if a[i] == b[i] {
			prefixMatch++
		} else {
			break
		}
	}

	// Count matching characters from the end
	suffixMatch := 0
	for i := 0; i < limit-prefixMatch; i++ {
		if a[len(a)-1-i] == b[len(b)-1-i] {
			suffixMatch++
		} else {
			break
		}
	}

	matchRatio := float64(prefixMatch+suffixMatch) / float64(longer)

	// Weighted combination: length similarity + content match
	return (lengthRatio + matchRatio) / 2.0
}

// checkStatusCodeAnomalies checks for interesting status code patterns
func (d *AnomalyDetector) checkStatusCodeAnomalies(resp *types.HTTPResponse, req *payloads.FuzzRequest) []types.Finding {
	var findings []types.Finding

	switch {
	case resp.StatusCode >= 500:
		// Status code change without injection-specific indicators = LOW confidence
		findings = append(findings, types.Finding{
			ID:          generateID(),
			Type:        "server_error",
			Severity:    types.SeverityLow,
			Confidence:  types.ConfidenceLow,
			Title:       "Server Error Triggered",
			Description: "The application returned a server error, which may indicate improper error handling",
			CWE:         "CWE-209",
		})
	}

	return findings
}
