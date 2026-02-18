package detector

import (
	"regexp"
	"strings"

	"github.com/su1ph3r/indago/internal/fuzzer"
	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

// EnumerationDetector detects user/resource enumeration via differential responses
type EnumerationDetector struct {
	authPathPatterns []*regexp.Regexp
	enumPatterns     []*regexp.Regexp
}

// NewEnumerationDetector creates a new enumeration detector
func NewEnumerationDetector() *EnumerationDetector {
	return &EnumerationDetector{
		authPathPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)/login`),
			regexp.MustCompile(`(?i)/signin`),
			regexp.MustCompile(`(?i)/sign-in`),
			regexp.MustCompile(`(?i)/auth`),
			regexp.MustCompile(`(?i)/authenticate`),
			regexp.MustCompile(`(?i)/register`),
			regexp.MustCompile(`(?i)/signup`),
			regexp.MustCompile(`(?i)/sign-up`),
			regexp.MustCompile(`(?i)/forgot[-_]?password`),
			regexp.MustCompile(`(?i)/reset[-_]?password`),
			regexp.MustCompile(`(?i)/recover`),
		},
		enumPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)user(name)?\s+(not\s+found|does\s+not\s+exist|doesn't\s+exist|is\s+not\s+registered|unknown)`),
			regexp.MustCompile(`(?i)account\s+(not\s+found|does\s+not\s+exist|doesn't\s+exist)`),
			regexp.MustCompile(`(?i)no\s+(such\s+)?user`),
			regexp.MustCompile(`(?i)invalid\s+user(name)?`),
			regexp.MustCompile(`(?i)email\s+(not\s+found|does\s+not\s+exist|doesn't\s+exist|is\s+not\s+registered)`),
			regexp.MustCompile(`(?i)wrong\s+password`),
			regexp.MustCompile(`(?i)incorrect\s+password`),
			regexp.MustCompile(`(?i)password\s+(is\s+)?(not\s+valid|incorrect|wrong)`),
			regexp.MustCompile(`(?i)password\s+is\s+not\s+correct`),
		},
	}
}

// Detect checks for enumeration indicators in fuzz results
func (d *EnumerationDetector) Detect(result *fuzzer.FuzzResult, baseline *types.HTTPResponse) []types.Finding {
	var findings []types.Finding

	if result.Response == nil {
		return findings
	}

	resp := result.Response
	req := result.Request

	if !d.isAuthEndpoint(req) {
		return findings
	}

	bodyLower := strings.ToLower(resp.Body)

	// Check for enumeration-revealing error messages in the response
	if d.hasEnumerationPattern(resp.Body) {
		// Suppress if baseline has the same pattern
		if baseline != nil && d.hasEnumerationPattern(baseline.Body) {
			return findings
		}
		findings = append(findings, types.Finding{
			ID:          generateID(),
			Type:        types.AttackEnumeration,
			Severity:    types.SeverityMedium,
			Confidence:  types.ConfidenceMedium,
			Title:       "User Enumeration via Differential Error Messages",
			Description: "Authentication endpoint returns different error messages for valid and invalid usernames, enabling attackers to enumerate valid accounts",
			CWE:         "CWE-204",
			Remediation: "Use generic error messages for authentication failures (e.g., 'Invalid username or password'). Do not reveal whether the username or password was incorrect.",
		})
		return findings
	}

	// Check for differential responses between fuzz and baseline that indicate enumeration
	if baseline != nil {
		findings = append(findings, d.checkDifferentialResponse(resp, baseline, bodyLower, req)...)
	}

	// Fallback: on auth endpoints, if both fuzz and baseline return 2xx
	// but with meaningfully different bodies, this indicates differential
	// behavior that can be used for enumeration
	if len(findings) == 0 && baseline != nil &&
		resp.StatusCode >= 200 && resp.StatusCode < 300 &&
		baseline.StatusCode >= 200 && baseline.StatusCode < 300 &&
		resp.Body != baseline.Body && len(resp.Body) > 10 && len(baseline.Body) > 10 {
		findings = append(findings, types.Finding{
			ID:          generateID(),
			Type:        types.AttackEnumeration,
			Severity:    types.SeverityMedium,
			Confidence:  types.ConfidenceLow,
			Title:       "User Enumeration via Differential Response Content",
			Description: "Authentication endpoint returns different response content for different inputs with identical status codes, potentially enabling attackers to enumerate valid accounts.",
			CWE:         "CWE-204",
			Remediation: "Return identical responses for all authentication failures.",
		})
	}

	// Registration endpoints inherently reveal username availability (e.g.,
	// "username already exists" vs success). This is expected behavior per
	// OWASP guidelines — login endpoints should not leak this, but registration
	// endpoints must. Downgrade to informational rather than suppressing entirely.
	if isRegistrationEndpoint(req.Endpoint.Path) {
		for i := range findings {
			findings[i].Severity = types.SeverityInfo
			findings[i].Confidence = types.ConfidenceLow
			findings[i].Description += " Note: Registration endpoints inherently reveal username availability. This is expected behavior in most applications."
		}
	}

	return findings
}

// isAuthEndpoint checks if the request targets an authentication-related endpoint
func (d *EnumerationDetector) isAuthEndpoint(req *payloads.FuzzRequest) bool {
	path := strings.ToLower(req.Endpoint.Path)
	for _, pattern := range d.authPathPatterns {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

// hasEnumerationPattern checks if the response body contains enumeration-revealing messages
func (d *EnumerationDetector) hasEnumerationPattern(body string) bool {
	for _, pattern := range d.enumPatterns {
		if pattern.MatchString(body) {
			return true
		}
	}
	return false
}

// checkDifferentialResponse detects enumeration via differences between fuzz and baseline responses
func (d *EnumerationDetector) checkDifferentialResponse(resp, baseline *types.HTTPResponse, bodyLower string, req *payloads.FuzzRequest) []types.Finding {
	var findings []types.Finding

	// Different status codes on an auth endpoint for different inputs suggest enumeration
	if resp.StatusCode != baseline.StatusCode &&
		isClientError(resp.StatusCode) && isClientError(baseline.StatusCode) {
		findings = append(findings, types.Finding{
			ID:          generateID(),
			Type:        types.AttackEnumeration,
			Severity:    types.SeverityMedium,
			Confidence:  types.ConfidenceMedium,
			Title:       "User Enumeration via Status Code Difference",
			Description: "Authentication endpoint returns different HTTP status codes for different inputs, which may allow attackers to distinguish valid from invalid usernames",
			CWE:         "CWE-204",
			Remediation: "Return the same HTTP status code for all authentication failures regardless of the reason.",
		})
	}

	// Significantly different body lengths with the same status code suggest enumeration
	if resp.StatusCode == baseline.StatusCode && isClientError(resp.StatusCode) {
		baseLen := len(baseline.Body)
		respLen := len(resp.Body)
		if baseLen > 0 && respLen > 0 && resp.Body != baseline.Body {
			diff := respLen - baseLen
			if diff < 0 {
				diff = -diff
			}
			// Threshold: at least 10 bytes and 20% size difference
			minLen := baseLen
			if respLen < minLen {
				minLen = respLen
			}
			if diff > 10 && float64(diff)/float64(minLen) > 0.2 {
				findings = append(findings, types.Finding{
					ID:          generateID(),
					Type:        types.AttackEnumeration,
					Severity:    types.SeverityMedium,
					Confidence:  types.ConfidenceLow,
					Title:       "User Enumeration via Response Size Difference",
					Description: "Authentication endpoint returns different response body sizes for different inputs, which may allow attackers to distinguish valid from invalid usernames",
					CWE:         "CWE-204",
					Remediation: "Ensure authentication error responses are identical in size and content regardless of the failure reason.",
				})
			}
		}
	}

	return findings
}

// isClientError checks if a status code is a 4xx client error
func isClientError(code int) bool {
	return code >= 400 && code < 500
}

// isRegistrationEndpoint checks if the endpoint path indicates a user registration
// endpoint. Registration endpoints inherently reveal username availability and
// should not be flagged as user enumeration at medium severity.
func isRegistrationEndpoint(path string) bool {
	pathLower := strings.ToLower(path)
	return strings.Contains(pathLower, "register") ||
		strings.Contains(pathLower, "signup") ||
		strings.Contains(pathLower, "sign-up") ||
		strings.Contains(pathLower, "sign_up")
}
