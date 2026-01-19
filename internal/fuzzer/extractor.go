// Package fuzzer provides the core fuzzing engine
package fuzzer

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// Extractor extracts data from HTTP responses
type Extractor struct {
	rules         []ExtractionRule
	autoExtract   bool
	state         *StateTracker
}

// ExtractionRule defines how to extract data from a response
type ExtractionRule struct {
	Name       string `yaml:"name" json:"name"`
	Type       string `yaml:"type" json:"type"`             // json, regex, header, cookie
	Path       string `yaml:"path" json:"path"`             // JSONPath for json type
	Pattern    string `yaml:"pattern" json:"pattern"`       // Regex pattern for regex type
	HeaderName string `yaml:"header_name" json:"header_name"` // Header name for header type
	CookieName string `yaml:"cookie_name" json:"cookie_name"` // Cookie name for cookie type
	SaveAs     string `yaml:"save_as" json:"save_as"`       // Variable name to save as
	Group      int    `yaml:"group" json:"group"`           // Regex capture group (default 0)
}

// AutoExtractionPatterns contains patterns for auto-extraction
var AutoExtractionPatterns = []struct {
	Name       string
	Pattern    *regexp.Regexp
	ResourceType string
}{
	{
		Name:       "uuid",
		Pattern:    regexp.MustCompile(`"(?:id|uuid|_id)":\s*"([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"`),
		ResourceType: "id",
	},
	{
		Name:       "numeric_id",
		Pattern:    regexp.MustCompile(`"(?:id|user_id|order_id|product_id|account_id)":\s*(\d+)`),
		ResourceType: "id",
	},
	{
		Name:       "jwt_token",
		Pattern:    regexp.MustCompile(`"(?:token|access_token|jwt|auth_token)":\s*"(eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)"`),
		ResourceType: "token",
	},
	{
		Name:       "bearer_token",
		Pattern:    regexp.MustCompile(`"(?:bearer|access_token)":\s*"([a-zA-Z0-9_-]{20,})"`),
		ResourceType: "token",
	},
	{
		Name:       "api_key",
		Pattern:    regexp.MustCompile(`"(?:api_key|apiKey|api-key)":\s*"([a-zA-Z0-9_-]{16,})"`),
		ResourceType: "api_key",
	},
	{
		Name:       "session_id",
		Pattern:    regexp.MustCompile(`"(?:session|session_id|sessionId)":\s*"([a-zA-Z0-9_-]{16,})"`),
		ResourceType: "session",
	},
	{
		Name:       "csrf_token",
		Pattern:    regexp.MustCompile(`"(?:csrf|csrf_token|_csrf)":\s*"([a-zA-Z0-9_-]{16,})"`),
		ResourceType: "csrf",
	},
	{
		Name:       "refresh_token",
		Pattern:    regexp.MustCompile(`"(?:refresh_token|refreshToken)":\s*"([a-zA-Z0-9_-]{20,})"`),
		ResourceType: "refresh_token",
	},
}

// NewExtractor creates a new extractor
func NewExtractor(state *StateTracker, autoExtract bool) *Extractor {
	return &Extractor{
		rules:       make([]ExtractionRule, 0),
		autoExtract: autoExtract,
		state:       state,
	}
}

// AddRule adds an extraction rule
func (e *Extractor) AddRule(rule ExtractionRule) {
	e.rules = append(e.rules, rule)
}

// AddRules adds multiple extraction rules
func (e *Extractor) AddRules(rules []ExtractionRule) {
	e.rules = append(e.rules, rules...)
}

// LoadRulesFromYAML loads extraction rules from YAML content
func (e *Extractor) LoadRulesFromYAML(data []byte) error {
	var rules struct {
		Rules []ExtractionRule `yaml:"rules" json:"rules"`
	}

	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}

	e.rules = append(e.rules, rules.Rules...)
	return nil
}

// ExtractFromResponse extracts data from an HTTP response
func (e *Extractor) ExtractFromResponse(resp *types.HTTPResponse, endpoint string) map[string]string {
	extracted := make(map[string]string)

	if resp == nil {
		return extracted
	}

	// Apply custom rules
	for _, rule := range e.rules {
		value := e.applyRule(rule, resp)
		if value != "" {
			saveAs := rule.SaveAs
			if saveAs == "" {
				saveAs = rule.Name
			}
			extracted[saveAs] = value

			// Update state tracker
			if e.state != nil {
				e.state.SetVariable(saveAs, value)
			}
		}
	}

	// Auto-extract common patterns if enabled
	if e.autoExtract {
		autoExtracted := e.autoExtractPatterns(resp, endpoint)
		for k, v := range autoExtracted {
			if _, exists := extracted[k]; !exists {
				extracted[k] = v
			}
		}
	}

	// Extract cookies
	e.extractCookies(resp)

	return extracted
}

// applyRule applies a single extraction rule
func (e *Extractor) applyRule(rule ExtractionRule, resp *types.HTTPResponse) string {
	switch rule.Type {
	case "json":
		return e.extractJSON(resp.Body, rule.Path)
	case "regex":
		return e.extractRegex(resp.Body, rule.Pattern, rule.Group)
	case "header":
		return e.extractHeader(resp.Headers, rule.HeaderName)
	case "cookie":
		return e.extractCookie(resp.Headers, rule.CookieName)
	default:
		return ""
	}
}

// extractJSON extracts a value from JSON using a simple path
func (e *Extractor) extractJSON(body, path string) string {
	if path == "" || body == "" {
		return ""
	}

	var data interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return ""
	}

	// Simple JSONPath implementation
	parts := strings.Split(path, ".")
	current := data

	for _, part := range parts {
		// Skip empty parts
		if part == "" || part == "$" {
			continue
		}

		// Handle array index
		if strings.HasSuffix(part, "]") {
			bracketIdx := strings.Index(part, "[")
			if bracketIdx > 0 {
				fieldName := part[:bracketIdx]
				indexStr := part[bracketIdx+1 : len(part)-1]

				// Navigate to field first
				if m, ok := current.(map[string]interface{}); ok {
					current = m[fieldName]
				} else {
					return ""
				}

				// Then get array element
				if arr, ok := current.([]interface{}); ok {
					var idx int
					if err := json.Unmarshal([]byte(indexStr), &idx); err == nil && idx < len(arr) {
						current = arr[idx]
					} else {
						return ""
					}
				} else {
					return ""
				}
				continue
			}
		}

		// Regular field access
		if m, ok := current.(map[string]interface{}); ok {
			current = m[part]
		} else if arr, ok := current.([]interface{}); ok {
			// Try to get first element
			if len(arr) > 0 {
				if m, ok := arr[0].(map[string]interface{}); ok {
					current = m[part]
				} else {
					return ""
				}
			} else {
				return ""
			}
		} else {
			return ""
		}
	}

	// Convert to string
	switch v := current.(type) {
	case string:
		return v
	case float64:
		if v == float64(int(v)) {
			return strings.TrimSuffix(strings.TrimSuffix(
				strings.TrimSuffix(json.Number(string(rune(int(v)))).String(), ".0"), ""), "")
		}
		return ""
	case bool:
		if v {
			return "true"
		}
		return "false"
	case nil:
		return ""
	default:
		// For complex types, marshal back to JSON
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// extractRegex extracts a value using regex
func (e *Extractor) extractRegex(body, pattern string, group int) string {
	if pattern == "" || body == "" {
		return ""
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}

	matches := re.FindStringSubmatch(body)
	if matches == nil {
		return ""
	}

	if group >= 0 && group < len(matches) {
		return matches[group]
	}

	if len(matches) > 1 {
		return matches[1] // Return first capture group by default
	}

	return matches[0]
}

// extractHeader extracts a value from response headers
func (e *Extractor) extractHeader(headers map[string]string, headerName string) string {
	if headerName == "" {
		return ""
	}

	// Case-insensitive header lookup
	for k, v := range headers {
		if strings.EqualFold(k, headerName) {
			return v
		}
	}

	return ""
}

// extractCookie extracts a cookie value from Set-Cookie header
func (e *Extractor) extractCookie(headers map[string]string, cookieName string) string {
	if cookieName == "" {
		return ""
	}

	for k, v := range headers {
		if strings.EqualFold(k, "Set-Cookie") {
			// Parse cookie
			parts := strings.Split(v, ";")
			if len(parts) > 0 {
				cookieParts := strings.SplitN(parts[0], "=", 2)
				if len(cookieParts) == 2 && strings.TrimSpace(cookieParts[0]) == cookieName {
					return strings.TrimSpace(cookieParts[1])
				}
			}
		}
	}

	return ""
}

// extractCookies extracts all cookies and stores them in state
func (e *Extractor) extractCookies(resp *types.HTTPResponse) {
	if e.state == nil || resp == nil {
		return
	}

	for k, v := range resp.Headers {
		if strings.EqualFold(k, "Set-Cookie") {
			parts := strings.Split(v, ";")
			if len(parts) > 0 {
				cookieParts := strings.SplitN(parts[0], "=", 2)
				if len(cookieParts) == 2 {
					name := strings.TrimSpace(cookieParts[0])
					value := strings.TrimSpace(cookieParts[1])
					e.state.SetCookie(name, value)
				}
			}
		}
	}
}

// autoExtractPatterns automatically extracts common patterns
func (e *Extractor) autoExtractPatterns(resp *types.HTTPResponse, endpoint string) map[string]string {
	extracted := make(map[string]string)

	for _, pattern := range AutoExtractionPatterns {
		matches := pattern.Pattern.FindStringSubmatch(resp.Body)
		if len(matches) > 1 {
			key := pattern.Name
			value := matches[1]

			extracted[key] = value

			// Update state tracker
			if e.state != nil {
				e.state.SetVariable(key, value)

				// Also add as resource for discovery
				if pattern.ResourceType != "" {
					e.state.AddResource(pattern.ResourceType, value)
				}
			}
		}
	}

	// Extract from common response structures
	e.extractCommonStructures(resp.Body, extracted)

	return extracted
}

// extractCommonStructures extracts from common API response structures
func (e *Extractor) extractCommonStructures(body string, extracted map[string]string) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return
	}

	// Common wrapper patterns: data, result, response, payload
	wrappers := []string{"data", "result", "response", "payload", "body"}
	var targetData interface{} = data

	for _, wrapper := range wrappers {
		if wrapped, ok := data[wrapper]; ok {
			targetData = wrapped
			break
		}
	}

	// Extract from the target data
	switch v := targetData.(type) {
	case map[string]interface{}:
		e.extractFromMap(v, extracted, "")
	case []interface{}:
		if len(v) > 0 {
			if m, ok := v[0].(map[string]interface{}); ok {
				e.extractFromMap(m, extracted, "")
			}
		}
	}
}

// extractFromMap extracts values from a map
func (e *Extractor) extractFromMap(m map[string]interface{}, extracted map[string]string, prefix string) {
	// Fields that commonly contain IDs or tokens
	idFields := []string{"id", "_id", "uuid", "user_id", "userId", "account_id", "accountId",
		"order_id", "orderId", "product_id", "productId", "session_id", "sessionId"}
	tokenFields := []string{"token", "access_token", "accessToken", "refresh_token", "refreshToken",
		"jwt", "api_key", "apiKey", "auth_token", "authToken", "csrf", "csrf_token"}

	for _, field := range idFields {
		if val, ok := m[field]; ok {
			key := field
			if prefix != "" {
				key = prefix + "_" + field
			}

			var strVal string
			switch v := val.(type) {
			case string:
				strVal = v
			case float64:
				strVal = strings.TrimSuffix(strings.TrimSuffix(
					regexp.MustCompile(`\.0*$`).ReplaceAllString(
						fmt.Sprintf("%v", v), ""), ""), "")
			}

			if strVal != "" {
				extracted[key] = strVal
				if e.state != nil {
					e.state.SetVariable(key, strVal)
					e.state.AddResource("id", strVal)
				}
			}
		}
	}

	for _, field := range tokenFields {
		if val, ok := m[field]; ok {
			if strVal, ok := val.(string); ok && strVal != "" {
				key := field
				if prefix != "" {
					key = prefix + "_" + field
				}
				extracted[key] = strVal
				if e.state != nil {
					e.state.SetToken(field, strVal)
				}
			}
		}
	}
}

// GetRules returns the configured extraction rules
func (e *Extractor) GetRules() []ExtractionRule {
	rules := make([]ExtractionRule, len(e.rules))
	copy(rules, e.rules)
	return rules
}
