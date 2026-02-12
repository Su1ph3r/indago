package detector

import (
	"net/url"
	"strings"

	"github.com/su1ph3r/indago/internal/fuzzer"
	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

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
		if d.indicators.CheckSQLInjection(resp.Body) {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackSQLi,
				Severity:    types.SeverityHigh,
				Confidence:  types.ConfidenceHigh,
				Title:       "SQL Injection Detected",
				Description: "SQL error messages found in response, indicating potential SQL injection vulnerability",
				CWE:         "CWE-89",
				Remediation: "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
			})
		}

	case types.AttackNoSQLi:
		if d.indicators.CheckNoSQLInjection(resp.Body) {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackNoSQLi,
				Severity:    types.SeverityHigh,
				Confidence:  types.ConfidenceHigh,
				Title:       "NoSQL Injection Detected",
				Description: "NoSQL error messages found in response, indicating potential NoSQL injection vulnerability",
				CWE:         "CWE-943",
				Remediation: "Validate and sanitize all user input. Use proper query builders and avoid eval-like constructs.",
			})
		}

	case types.AttackCommandInject:
		if d.indicators.CheckCommandInjection(resp.Body) {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackCommandInject,
				Severity:    types.SeverityCritical,
				Confidence:  types.ConfidenceHigh,
				Title:       "Command Injection Detected",
				Description: "System command output found in response, indicating command injection vulnerability",
				CWE:         "CWE-78",
				Remediation: "Avoid executing system commands with user input. If necessary, use allowlists and proper escaping.",
			})
		}

	case types.AttackPathTraversal:
		if d.indicators.CheckPathTraversal(resp.Body) {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackPathTraversal,
				Severity:    types.SeverityHigh,
				Confidence:  types.ConfidenceHigh,
				Title:       "Path Traversal Detected",
				Description: "File content found in response, indicating path traversal vulnerability",
				CWE:         "CWE-22",
				Remediation: "Validate file paths against an allowlist. Use canonical path resolution and sandbox file access.",
			})
		}

	case types.AttackXSS:
		if d.indicators.CheckXSSReflection(resp.Body, req.Payload.Value) {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackXSS,
				Severity:    types.SeverityMedium,
				Confidence:  types.ConfidenceMedium,
				Title:       "Potential XSS - Payload Reflected",
				Description: "Input payload is reflected in the response without proper encoding",
				CWE:         "CWE-79",
				Remediation: "Implement proper output encoding based on context (HTML, JavaScript, URL, CSS).",
			})
		}

	case types.AttackMethodTampering:
		if resp.StatusCode == 200 || resp.StatusCode == 204 {
			confidence := types.ConfidenceMedium
			desc := "Endpoint accepted an unexpected HTTP method"
			if method, ok := req.Payload.Metadata["override_method"]; ok && method == "TRACE" && resp.StatusCode == 200 {
				confidence = types.ConfidenceHigh
				desc = "TRACE method is enabled, which can be used for cross-site tracing (XST) attacks"
			}
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackMethodTampering,
				Severity:    types.SeverityMedium,
				Confidence:  confidence,
				Title:       "HTTP Method Tampering Accepted",
				Description: desc,
				CWE:         "CWE-650",
				Remediation: "Explicitly reject unexpected HTTP methods. Disable TRACE in production. Return 405 Method Not Allowed for unsupported methods.",
			})
		}

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

	case types.AttackContentTypeConfusion:
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			findings = append(findings, types.Finding{
				ID:          generateID(),
				Type:        types.AttackContentTypeConfusion,
				Severity:    types.SeverityLow,
				Confidence:  types.ConfidenceLow,
				Title:       "Content-Type Confusion Accepted",
				Description: "The endpoint accepted a request with a mismatched Content-Type header without returning an error",
				CWE:         "CWE-436",
				Remediation: "Validate the Content-Type header and reject requests with unexpected types. Return 415 Unsupported Media Type for mismatched content types.",
			})
		}
	}

	// Compare with baseline if available
	if baseline != nil {
		findings = append(findings, d.compareWithBaseline(result, baseline)...)
	}

	// Check status code anomalies
	findings = append(findings, d.checkStatusCodeAnomalies(resp, req)...)

	return findings
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

		// Success status when auth required
		if baseline.StatusCode == 401 || baseline.StatusCode == 403 {
			if result.Response.StatusCode == 200 {
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

	return findings
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

// checkStatusCodeAnomalies checks for interesting status code patterns
func (d *AnomalyDetector) checkStatusCodeAnomalies(resp *types.HTTPResponse, req *payloads.FuzzRequest) []types.Finding {
	var findings []types.Finding

	switch {
	case resp.StatusCode == 200 && req.Payload.Type == types.AttackIDOR:
		// Successful access with IDOR payload - might be legit or a vulnerability
		findings = append(findings, types.Finding{
			ID:          generateID(),
			Type:        types.AttackIDOR,
			Severity:    types.SeverityMedium,
			Confidence:  types.ConfidenceLow,
			Title:       "Potential IDOR - Resource Access",
			Description: "Modified ID parameter resulted in successful resource access. Manual verification required.",
			CWE:         "CWE-639",
			Remediation: "Implement proper authorization checks to ensure users can only access their own resources.",
		})

	case resp.StatusCode >= 500:
		findings = append(findings, types.Finding{
			ID:          generateID(),
			Type:        "server_error",
			Severity:    types.SeverityLow,
			Confidence:  types.ConfidenceHigh,
			Title:       "Server Error Triggered",
			Description: "The application returned a server error, which may indicate improper error handling",
			CWE:         "CWE-209",
		})
	}

	return findings
}
