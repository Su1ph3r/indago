package detector

import (
	"fmt"
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
	Severity    string
	Confidence  string
	CWE         string
	Remediation string
	Validate    func(match string, body string) bool // Optional post-match validation
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
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceHigh,
		CWE:         "CWE-200",
		Remediation: "Never include passwords in API responses. Remove password fields from serialization.",
	})

	// Credit card numbers (with Luhn checksum + contextual validation)
	d.rules = append(d.rules, &LeakRule{
		Name:        "Credit Card Number Exposed",
		Description: "Potential credit card number found",
		Pattern:     regexp.MustCompile(`(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})`),
		Severity:    types.SeverityCritical,
		Confidence:  types.ConfidenceMedium,
		CWE:         "CWE-311",
		Remediation: "Mask credit card numbers. Only show last 4 digits. Ensure PCI DSS compliance.",
		Validate: func(match string, body string) bool {
			return luhnValid(match) && validateCreditCardContext(match, body)
		},
	})

	// Social Security Numbers (with contextual validation)
	d.rules = append(d.rules, &LeakRule{
		Name:        "SSN Exposed",
		Description: "Potential Social Security Number found",
		Pattern:     regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		Severity:    types.SeverityCritical,
		Confidence:  types.ConfidenceMedium,
		CWE:         "CWE-359",
		Remediation: "Mask SSNs in API responses. Implement proper access controls for PII.",
		Validate: func(match string, body string) bool {
			return validateSSN(match, body)
		},
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
func (d *DataLeakDetector) Detect(resp *types.HTTPResponse, req *payloads.FuzzRequest, baseline *types.HTTPResponse) []types.Finding {
	var findings []types.Finding

	for _, rule := range d.rules {
		if d.matchRule(rule, resp) {
			// For JWT Token detection, check if the matched token is the scanner's own
			// payload reflected back. If the JWT appears in the request payload, URL, or
			// body, it's self-reflection -- not a genuine leak.
			if rule.Name == "JWT Token Exposed" && req != nil {
				matched := rule.Pattern.FindString(resp.Body)
				if matched != "" && isReflectedPayload(matched, req) {
					continue
				}
			}

			// Extract matched data for evidence
			matchedText := rule.Pattern.FindString(resp.Body)
			var matchedData []string
			if matchedText != "" {
				matchedData = append(matchedData, fmt.Sprintf("%s: %s", rule.Name, redactSensitiveMatch(matchedText)))
			}

			finding := types.Finding{
				ID:          generateID(),
				Type:        "data_leak",
				Severity:    rule.Severity,
				Confidence:  rule.Confidence,
				Title:       rule.Name,
				Description: rule.Description,
				CWE:         rule.CWE,
				Remediation: rule.Remediation,
				Evidence:    &types.Evidence{MatchedData: matchedData},
			}

			// For email detection, compare counts between baseline and response
			if rule.Name == "Bulk Email Exposure" {
				matches := rule.Pattern.FindAllString(resp.Body, -1)
				if len(matches) < 5 {
					continue // Skip if less than 5 emails
				}
				// Suppress only if baseline has similar email count
				if baseline != nil {
					baselineMatches := rule.Pattern.FindAllString(baseline.Body, -1)
					if len(baselineMatches) >= len(matches) {
						continue
					}
				}
				finding.Description = strings.ReplaceAll(finding.Description, "Multiple", strconv.Itoa(len(matches)))
				// Include sample of matched emails (up to 3), redacted for PII safety
				sampleCount := 3
				if len(matches) < sampleCount {
					sampleCount = len(matches)
				}
				redactedSamples := make([]string, sampleCount)
				for i := 0; i < sampleCount; i++ {
					redactedSamples[i] = redactEmail(matches[i])
				}
				finding.Evidence = &types.Evidence{
					MatchedData: []string{fmt.Sprintf("%d email addresses found (sample: %s)", len(matches), strings.Join(redactedSamples, ", "))},
				}
			} else {
				// Don't suppress for debug endpoints - sensitive data in baseline IS the vulnerability
				isDebugEndpoint := false
				if req != nil {
					pathLower := strings.ToLower(req.Endpoint.Path)
					if strings.Contains(pathLower, "debug") || strings.Contains(pathLower, "/internal") {
						isDebugEndpoint = true
					}
				}

				// Suppress if the same pattern exists in the baseline response (skip for debug endpoints)
				if !isDebugEndpoint && baseline != nil && d.matchRule(rule, baseline) {
					continue
				}
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// redactSensitiveMatch partially redacts sensitive matched data to avoid exposing
// full secrets in reports while still showing enough to identify the pattern.
func redactSensitiveMatch(match string) string {
	if len(match) <= 4 {
		return "***"
	}
	if len(match) <= 12 {
		return match[:2] + "..." + match[len(match)-2:]
	}
	return match[:4] + "..." + match[len(match)-4:]
}

// redactEmail redacts an email address for PII safety, e.g. "user@example.com" -> "us***@example.com"
func redactEmail(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return redactSensitiveMatch(email)
	}
	local := parts[0]
	if len(local) <= 2 {
		return "***@" + parts[1]
	}
	return local[:2] + "***@" + parts[1]
}

// isReflectedPayload checks if a matched string was sent as part of the request.
// This prevents flagging the scanner's own payloads as leaked data when the server
// reflects them back in error messages.
func isReflectedPayload(matched string, req *payloads.FuzzRequest) bool {
	// Check if the matched value is a substring of the payload value
	if req.Payload.Value != "" && strings.Contains(req.Payload.Value, matched) {
		return true
	}
	// Check endpoint URL (payload may have been injected into the path/query)
	if req.Endpoint.Path != "" && strings.Contains(req.Endpoint.Path, matched) {
		return true
	}
	return false
}

// matchRule checks if a response matches a leak rule
func (d *DataLeakDetector) matchRule(rule *LeakRule, resp *types.HTTPResponse) bool {
	if rule.Pattern == nil {
		return false
	}
	match := rule.Pattern.FindString(resp.Body)
	if match == "" {
		return false
	}
	// Run optional post-match validation
	if rule.Validate != nil {
		return rule.Validate(match, resp.Body)
	}
	return true
}

// AddRule adds a custom leak detection rule
func (d *DataLeakDetector) AddRule(rule *LeakRule) {
	d.rules = append(d.rules, rule)
}

// luhnValid checks if a numeric string passes the Luhn checksum algorithm
func luhnValid(number string) bool {
	// Extract only digits
	var digits []int
	for _, r := range number {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := digits[i]
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// creditCardFieldKeywords are JSON field names that indicate a credit card context
var creditCardFieldKeywords = []string{
	"card", "credit", "payment", "pan", "account_number", "account-number",
	"cc_", "cc-", "billing", "cardnumber", "card_number", "card-number",
	"creditcard", "credit_card", "credit-card",
}

// nonCreditCardFields are JSON field names that look numeric but are not credit cards
var nonCreditCardFields = []string{
	"id", "user_id", "userid", "user-id",
	"phone", "telephone", "tel", "mobile", "fax",
	"timestamp", "time", "date", "created", "updated", "modified",
	"exp", "expires", "expiry", "expiration",
	"code", "status", "count", "total", "amount",
	"port", "pid", "uid", "gid",
	"version", "sequence", "seq", "index", "offset",
	"book_id", "bookid", "book-id",
	"order_id", "orderid", "order-id",
	"session_id", "sessionid", "session-id",
	"transaction_id", "transactionid", "transaction-id",
}

// validateCreditCardContext checks whether a matched credit card number appears
// in a context that suggests it is actually a credit card, not a random numeric
// value like a user ID or timestamp that incidentally passes Luhn validation.
func validateCreditCardContext(match string, body string) bool {
	idx := strings.Index(body, match)
	if idx < 0 {
		return false
	}

	// Look at the text before the match to find a JSON field name context.
	// We look back up to 80 chars to find a pattern like "field_name": or "field_name":
	lookback := 80
	start := idx - lookback
	if start < 0 {
		start = 0
	}
	preceding := body[start:idx]

	// Try to extract the nearest JSON key before this value.
	// Pattern: "some_key" followed by optional whitespace, colon, optional whitespace, optional quote
	fieldName := extractNearestJSONKey(preceding)

	if fieldName != "" {
		fieldLower := strings.ToLower(fieldName)

		// If the field name matches a known non-card field, reject
		for _, nc := range nonCreditCardFields {
			if fieldLower == nc || strings.HasSuffix(fieldLower, "_"+nc) || strings.HasPrefix(fieldLower, nc+"_") {
				return false
			}
		}

		// If the field name contains a credit card keyword, accept
		for _, kw := range creditCardFieldKeywords {
			if strings.Contains(fieldLower, kw) {
				return true
			}
		}

		// Field name is present but doesn't match card keywords — reject.
		// This avoids flagging numbers under generic fields like "data", "value", etc.
		return false
	}

	// No JSON field context found — check for credit card keywords nearby.
	// In unstructured text (error pages, HTML), random numeric sequences commonly
	// pass Luhn validation (timestamps, thread IDs, etc). Only flag if there are
	// credit card keywords within 200 chars of the match.
	searchStart := idx - 200
	if searchStart < 0 {
		searchStart = 0
	}
	searchEnd := idx + len(match) + 200
	if searchEnd > len(body) {
		searchEnd = len(body)
	}
	nearby := strings.ToLower(body[searchStart:searchEnd])
	for _, kw := range creditCardFieldKeywords {
		if strings.Contains(nearby, kw) {
			return true
		}
	}
	return false
}

// extractNearestJSONKey looks backward through text preceding a value to find
// the most recent JSON key. Returns empty string if none found.
func extractNearestJSONKey(preceding string) string {
	// We search for the pattern: "key" : (value starts here)
	// Working backward from the end of preceding text, find the last quoted string
	// before a colon.

	// Find the last colon in the preceding text
	colonIdx := strings.LastIndex(preceding, ":")
	if colonIdx < 0 {
		return ""
	}

	// Look for quoted key before the colon
	beforeColon := strings.TrimRight(preceding[:colonIdx], " \t\n\r")
	if len(beforeColon) == 0 {
		return ""
	}

	// The key should end with a quote
	if beforeColon[len(beforeColon)-1] != '"' {
		return ""
	}

	// Find the opening quote of the key
	keyEnd := len(beforeColon) - 1
	keyStart := strings.LastIndex(beforeColon[:keyEnd], "\"")
	if keyStart < 0 {
		return ""
	}

	return beforeColon[keyStart+1 : keyEnd]
}

// validateSSN checks if a SSN match is contextually valid
func validateSSN(match string, body string) bool {
	// Require SSN-related keywords within 50 chars of the match
	idx := strings.Index(body, match)
	if idx < 0 {
		return false
	}
	start := idx - 50
	if start < 0 {
		start = 0
	}
	end := idx + len(match) + 50
	if end > len(body) {
		end = len(body)
	}
	context := strings.ToLower(body[start:end])
	hasKeyword := strings.Contains(context, "ssn") ||
		strings.Contains(context, "social_security") ||
		strings.Contains(context, "social-security")
	if !hasKeyword {
		return false
	}

	// Validate SSN format — reject known invalid prefixes
	parts := strings.Split(match, "-")
	if len(parts) != 3 {
		return false
	}
	area, _ := strconv.Atoi(parts[0])
	group, _ := strconv.Atoi(parts[1])
	serial, _ := strconv.Atoi(parts[2])

	if area == 0 || area == 666 || area >= 900 {
		return false
	}
	if group == 0 || serial == 0 {
		return false
	}
	return true
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
