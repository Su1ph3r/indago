package detector

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

// DataLeakDetector detects sensitive data leaks in responses
type DataLeakDetector struct {
	rules []*LeakRule
}

// LeakRule represents a data leak detection rule
type LeakRule struct {
	Name        string
	Description string
	Pattern     *regexp.Regexp
	Keywords    []string
	Severity    string
	Confidence  string
	CWE         string
	Remediation string
}

// NewDataLeakDetector creates a new data leak detector
func NewDataLeakDetector() *DataLeakDetector {
	d := &DataLeakDetector{
		rules: make([]*LeakRule, 0),
	}
	d.initRules()
	return d
}

// initRules initializes leak detection rules
func (d *DataLeakDetector) initRules() {
	// API Keys
	d.rules = append(d.rules, &LeakRule{
		Name:        "API Key Exposed",
		Description: "Potential API key found in response",
		Pattern:     regexp.MustCompile(`(?i)(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})["']?`),
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceMedium,
		CWE:         "CWE-200",
		Remediation: "Remove API keys from responses. Use server-side key management.",
	})

	// AWS credentials
	d.rules = append(d.rules, &LeakRule{
		Name:        "AWS Credentials Exposed",
		Description: "AWS access key or secret found in response",
		Pattern:     regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16}|aws[_-]?(access|secret)[_-]?key\s*[:=]\s*["']?[a-zA-Z0-9/+=]{20,})`),
		Severity:    types.SeverityCritical,
		Confidence:  types.ConfidenceHigh,
		CWE:         "CWE-798",
		Remediation: "Rotate compromised AWS credentials immediately. Use IAM roles instead of hardcoded keys.",
	})

	// Private keys
	d.rules = append(d.rules, &LeakRule{
		Name:        "Private Key Exposed",
		Description: "Private key found in response",
		Pattern:     regexp.MustCompile(`(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`),
		Severity:    types.SeverityCritical,
		Confidence:  types.ConfidenceHigh,
		CWE:         "CWE-321",
		Remediation: "Never expose private keys. Rotate compromised keys immediately.",
	})

	// JWT tokens
	d.rules = append(d.rules, &LeakRule{
		Name:        "JWT Token Exposed",
		Description: "JWT token found in response body",
		Pattern:     regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`),
		Severity:    types.SeverityMedium,
		Confidence:  types.ConfidenceMedium,
		CWE:         "CWE-200",
		Remediation: "Review JWT exposure. Ensure tokens are only sent when needed.",
	})

	// Passwords in response
	d.rules = append(d.rules, &LeakRule{
		Name:        "Password in Response",
		Description: "Password field found in API response",
		Pattern:     regexp.MustCompile(`(?i)"(password|passwd|pwd|secret)"\s*:\s*"[^"]+"`),
		Keywords:    []string{"password", "passwd", "pwd"},
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceHigh,
		CWE:         "CWE-200",
		Remediation: "Never include passwords in API responses. Remove password fields from serialization.",
	})

	// Credit card numbers
	d.rules = append(d.rules, &LeakRule{
		Name:        "Credit Card Number Exposed",
		Description: "Potential credit card number found",
		Pattern:     regexp.MustCompile(`(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})`),
		Severity:    types.SeverityCritical,
		Confidence:  types.ConfidenceMedium,
		CWE:         "CWE-311",
		Remediation: "Mask credit card numbers. Only show last 4 digits. Ensure PCI DSS compliance.",
	})

	// Social Security Numbers
	d.rules = append(d.rules, &LeakRule{
		Name:        "SSN Exposed",
		Description: "Potential Social Security Number found",
		Pattern:     regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		Severity:    types.SeverityCritical,
		Confidence:  types.ConfidenceLow,
		CWE:         "CWE-359",
		Remediation: "Mask SSNs in API responses. Implement proper access controls for PII.",
	})

	// Email addresses (bulk)
	d.rules = append(d.rules, &LeakRule{
		Name:        "Bulk Email Exposure",
		Description: "Multiple email addresses found in response",
		Pattern:     regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
		Severity:    types.SeverityLow,
		Confidence:  types.ConfidenceLow,
		CWE:         "CWE-200",
		Remediation: "Review if bulk email exposure is necessary. Implement pagination and access controls.",
	})

	// Internal IPs
	d.rules = append(d.rules, &LeakRule{
		Name:        "Internal IP Exposed",
		Description: "Internal IP address found in response",
		Pattern:     regexp.MustCompile(`(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}`),
		Severity:    types.SeverityLow,
		Confidence:  types.ConfidenceMedium,
		CWE:         "CWE-200",
		Remediation: "Remove internal infrastructure details from API responses.",
	})

	// Database connection strings
	d.rules = append(d.rules, &LeakRule{
		Name:        "Database Connection String",
		Description: "Database connection string found in response",
		Pattern:     regexp.MustCompile(`(?i)(mongodb|mysql|postgresql|postgres|mssql|redis):\/\/[^:\s]+:[^@\s]+@[^\s]+`),
		Severity:    types.SeverityCritical,
		Confidence:  types.ConfidenceHigh,
		CWE:         "CWE-200",
		Remediation: "Never expose database credentials. Use environment variables and secrets management.",
	})

	// Slack tokens
	d.rules = append(d.rules, &LeakRule{
		Name:        "Slack Token Exposed",
		Description: "Slack token found in response",
		Pattern:     regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`),
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceHigh,
		CWE:         "CWE-798",
		Remediation: "Rotate compromised Slack tokens. Use proper secrets management.",
	})

	// GitHub tokens
	d.rules = append(d.rules, &LeakRule{
		Name:        "GitHub Token Exposed",
		Description: "GitHub token found in response",
		Pattern:     regexp.MustCompile(`(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}`),
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceHigh,
		CWE:         "CWE-798",
		Remediation: "Revoke compromised GitHub tokens immediately.",
	})

	// Google API keys
	d.rules = append(d.rules, &LeakRule{
		Name:        "Google API Key Exposed",
		Description: "Google API key found in response",
		Pattern:     regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`),
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceHigh,
		CWE:         "CWE-798",
		Remediation: "Rotate Google API keys. Restrict key usage to specific APIs and referrers.",
	})
}

// Detect detects data leaks in a response
func (d *DataLeakDetector) Detect(resp *types.HTTPResponse, req *payloads.FuzzRequest) []types.Finding {
	var findings []types.Finding

	for _, rule := range d.rules {
		if d.matchRule(rule, resp) {
			finding := types.Finding{
				ID:          generateID(),
				Type:        "data_leak",
				Severity:    rule.Severity,
				Confidence:  rule.Confidence,
				Title:       rule.Name,
				Description: rule.Description,
				CWE:         rule.CWE,
				Remediation: rule.Remediation,
			}

			// For email detection, check if there are multiple
			if rule.Name == "Bulk Email Exposure" {
				matches := rule.Pattern.FindAllString(resp.Body, -1)
				if len(matches) < 5 {
					continue // Skip if less than 5 emails
				}
				finding.Description = strings.ReplaceAll(finding.Description, "Multiple", strconv.Itoa(len(matches)))
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// matchRule checks if a response matches a leak rule
func (d *DataLeakDetector) matchRule(rule *LeakRule, resp *types.HTTPResponse) bool {
	// Check pattern
	if rule.Pattern != nil && rule.Pattern.MatchString(resp.Body) {
		return true
	}

	// Check keywords
	bodyLower := strings.ToLower(resp.Body)
	for _, keyword := range rule.Keywords {
		if strings.Contains(bodyLower, keyword) {
			return true
		}
	}

	return false
}

// AddRule adds a custom leak detection rule
func (d *DataLeakDetector) AddRule(rule *LeakRule) {
	d.rules = append(d.rules, rule)
}

// SensitiveFieldDetector detects sensitive fields in responses
type SensitiveFieldDetector struct {
	sensitiveFields []string
}

// NewSensitiveFieldDetector creates a detector for sensitive fields
func NewSensitiveFieldDetector() *SensitiveFieldDetector {
	return &SensitiveFieldDetector{
		sensitiveFields: []string{
			"password", "passwd", "pwd", "secret",
			"token", "api_key", "apikey", "api-key",
			"private_key", "privatekey", "private-key",
			"credit_card", "creditcard", "credit-card",
			"ssn", "social_security", "socialsecurity",
			"secret_key", "secretkey", "secret-key",
			"access_token", "accesstoken", "access-token",
			"refresh_token", "refreshtoken", "refresh-token",
			"auth_token", "authtoken", "auth-token",
		},
	}
}

// DetectInJSON checks for sensitive fields in JSON response
func (d *SensitiveFieldDetector) DetectInJSON(body string) []string {
	var found []string

	bodyLower := strings.ToLower(body)
	for _, field := range d.sensitiveFields {
		// Check for JSON key pattern
		patterns := []string{
			`"` + field + `"`,
			`'` + field + `'`,
			field + `:`,
			field + `=`,
		}

		for _, pattern := range patterns {
			if strings.Contains(bodyLower, pattern) {
				found = append(found, field)
				break
			}
		}
	}

	return found
}
