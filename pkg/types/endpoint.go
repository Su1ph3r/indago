// Package types provides core data structures for Indago
package types

import "encoding/json"

// Endpoint represents a unified API endpoint model
type Endpoint struct {
	Method      string            `json:"method" yaml:"method"`
	Path        string            `json:"path" yaml:"path"`
	BaseURL     string            `json:"base_url" yaml:"base_url"`
	Parameters  []Parameter       `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	Headers     map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Body        *RequestBody      `json:"body,omitempty" yaml:"body,omitempty"`
	Auth        *AuthConfig       `json:"auth,omitempty" yaml:"auth,omitempty"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Tags        []string          `json:"tags,omitempty" yaml:"tags,omitempty"`
	OperationID string            `json:"operation_id,omitempty" yaml:"operation_id,omitempty"`

	// AI-enriched fields
	BusinessContext  string         `json:"business_context,omitempty" yaml:"business_context,omitempty"`
	SensitivityLevel string         `json:"sensitivity_level,omitempty" yaml:"sensitivity_level,omitempty"`
	RelatedEndpoints []string       `json:"related_endpoints,omitempty" yaml:"related_endpoints,omitempty"`
	SuggestedAttacks []AttackVector `json:"suggested_attacks,omitempty" yaml:"suggested_attacks,omitempty"`
}

// FullPath returns the complete URL for the endpoint
func (e *Endpoint) FullPath() string {
	return e.BaseURL + e.Path
}

// Parameter represents an API parameter
type Parameter struct {
	Name        string      `json:"name" yaml:"name"`
	In          string      `json:"in" yaml:"in"` // query, path, header, cookie
	Type        string      `json:"type" yaml:"type"`
	Required    bool        `json:"required" yaml:"required"`
	Description string      `json:"description,omitempty" yaml:"description,omitempty"`
	Example     interface{} `json:"example,omitempty" yaml:"example,omitempty"`
	Default     interface{} `json:"default,omitempty" yaml:"default,omitempty"`
	Enum        []string    `json:"enum,omitempty" yaml:"enum,omitempty"`
	Format      string      `json:"format,omitempty" yaml:"format,omitempty"`
	Pattern     string      `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	Minimum     *float64    `json:"minimum,omitempty" yaml:"minimum,omitempty"`
	Maximum     *float64    `json:"maximum,omitempty" yaml:"maximum,omitempty"`
}

// RequestBody represents the request body configuration
type RequestBody struct {
	ContentType string                 `json:"content_type" yaml:"content_type"`
	Required    bool                   `json:"required" yaml:"required"`
	Schema      map[string]interface{} `json:"schema,omitempty" yaml:"schema,omitempty"`
	Example     interface{}            `json:"example,omitempty" yaml:"example,omitempty"`
	Fields      []BodyField            `json:"fields,omitempty" yaml:"fields,omitempty"`
}

// BodyField represents a field in the request body
type BodyField struct {
	Name        string      `json:"name" yaml:"name"`
	Type        string      `json:"type" yaml:"type"`
	Required    bool        `json:"required" yaml:"required"`
	Description string      `json:"description,omitempty" yaml:"description,omitempty"`
	Example     interface{} `json:"example,omitempty" yaml:"example,omitempty"`
	Nested      []BodyField `json:"nested,omitempty" yaml:"nested,omitempty"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Type         string            `json:"type" yaml:"type"` // bearer, basic, api_key, oauth2
	Location     string            `json:"location,omitempty" yaml:"location,omitempty"`
	Name         string            `json:"name,omitempty" yaml:"name,omitempty"`
	Value        string            `json:"value,omitempty" yaml:"value,omitempty"`
	HeaderName   string            `json:"header_name,omitempty" yaml:"header_name,omitempty"`
	HeaderPrefix string            `json:"header_prefix,omitempty" yaml:"header_prefix,omitempty"`
	Extra        map[string]string `json:"extra,omitempty" yaml:"extra,omitempty"`
}

// FlexibleString can unmarshal from either a string or an array of strings
type FlexibleString string

// UnmarshalJSON handles both string and array inputs
func (f *FlexibleString) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as a string first
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*f = FlexibleString(s)
		return nil
	}

	// Try to unmarshal as an array
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		if len(arr) > 0 {
			*f = FlexibleString(arr[0])
		}
		return nil
	}

	// If neither works, just set empty
	*f = ""
	return nil
}

// String returns the string value
func (f FlexibleString) String() string {
	return string(f)
}

// FlexibleStringSlice can unmarshal from a string array, object, or string
type FlexibleStringSlice []string

// UnmarshalJSON handles various input formats
func (f *FlexibleStringSlice) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as an array first
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*f = arr
		return nil
	}

	// Try to unmarshal as a single string
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*f = []string{s}
		return nil
	}

	// Try to unmarshal as an object with string values
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err == nil {
		var result []string
		for _, v := range obj {
			if str, ok := v.(string); ok {
				result = append(result, str)
			}
		}
		*f = result
		return nil
	}

	// If nothing works, set empty
	*f = []string{}
	return nil
}

// AttackVector represents a suggested attack type
type AttackVector struct {
	Type        string              `json:"type" yaml:"type"`
	Category    string              `json:"category" yaml:"category"`
	Priority    string              `json:"priority" yaml:"priority"` // high, medium, low
	Rationale   string              `json:"rationale,omitempty" yaml:"rationale,omitempty"`
	TargetParam FlexibleString      `json:"target_param,omitempty" yaml:"target_param,omitempty"`
	Payloads    FlexibleStringSlice `json:"payloads,omitempty" yaml:"payloads,omitempty"`
}

// AttackCategory constants
const (
	AttackIDOR           = "idor"
	AttackSQLi           = "sqli"
	AttackNoSQLi         = "nosqli"
	AttackCommandInject  = "command_injection"
	AttackXSS            = "xss"
	AttackAuthBypass     = "auth_bypass"
	AttackMassAssignment = "mass_assignment"
	AttackBOLA           = "bola"
	AttackBFLA           = "bfla"
	AttackRateLimit      = "rate_limit"
	AttackDataExposure   = "data_exposure"
	AttackSSRF           = "ssrf"
	AttackPathTraversal  = "path_traversal"
	AttackLDAP           = "ldap_injection"
	AttackXPath          = "xpath_injection"
	AttackSSTI           = "ssti"
	AttackJWT            = "jwt_manipulation"
)

// SensitivityLevel constants
const (
	SensitivityCritical = "critical"
	SensitivityHigh     = "high"
	SensitivityMedium   = "medium"
	SensitivityLow      = "low"
)
