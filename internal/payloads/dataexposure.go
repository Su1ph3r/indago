package payloads

import (
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// DataExposureGenerator generates payloads for detecting excessive data exposure
type DataExposureGenerator struct{}

// NewDataExposureGenerator creates a new data exposure payload generator
func NewDataExposureGenerator() *DataExposureGenerator {
	return &DataExposureGenerator{}
}

// Type returns the attack type
func (g *DataExposureGenerator) Type() string {
	return types.AttackDataExposure
}

// Generate generates data exposure test payloads for a parameter
func (g *DataExposureGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	// Target parameters that might control data filtering or selection
	if !g.isDataControlParameter(param, endpoint) {
		return payloads
	}

	// Field expansion payloads
	payloads = append(payloads, g.fieldExpansionPayloads()...)

	// Verbose/debug payloads
	payloads = append(payloads, g.verbosePayloads()...)

	// Filter bypass payloads
	payloads = append(payloads, g.filterBypassPayloads()...)

	return payloads
}

// isDataControlParameter checks if parameter controls data output
func (g *DataExposureGenerator) isDataControlParameter(param *types.Parameter, endpoint types.Endpoint) bool {
	nameLower := strings.ToLower(param.Name)
	pathLower := strings.ToLower(endpoint.Path)

	// Parameters that control data output
	dataPatterns := []string{
		"fields", "field", "select", "columns", "include", "expand",
		"filter", "query", "search", "limit", "offset", "page",
		"sort", "order", "verbose", "debug", "full", "all",
		"embed", "populate", "relations", "associations",
	}

	for _, pattern := range dataPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}

	// Endpoints that return data
	dataEndpoints := []string{
		"/users", "/accounts", "/profiles", "/customers",
		"/orders", "/transactions", "/payments",
		"/admin", "/internal", "/debug",
		"/export", "/download", "/report",
	}

	for _, ep := range dataEndpoints {
		if strings.Contains(pathLower, ep) {
			return true
		}
	}

	return false
}

// fieldExpansionPayloads generates payloads to request additional fields
func (g *DataExposureGenerator) fieldExpansionPayloads() []Payload {
	return []Payload{
		{
			Value:       "*",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Request all fields (wildcard)",
		},
		{
			Value:       "all",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Request all fields (keyword)",
		},
		{
			Value:       "password,secret,token,key,hash,salt",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Request sensitive credential fields",
		},
		{
			Value:       "ssn,social_security,tax_id,national_id",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Request PII identification fields",
		},
		{
			Value:       "credit_card,card_number,cvv,expiry",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Request payment card fields",
		},
		{
			Value:       "email,phone,address,dob,date_of_birth",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Request personal contact fields",
		},
		{
			Value:       "internal_id,admin_notes,private_data",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Request internal/admin fields",
		},
		{
			Value:       "created_at,updated_at,deleted_at,ip_address",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Request metadata fields",
		},
		{
			Value:       "password_hash,api_key,secret_key,access_token",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Request authentication secrets",
		},
		{
			Value:       "bank_account,routing_number,iban,swift",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Request banking fields",
		},
	}
}

// verbosePayloads generates payloads to enable verbose/debug output
func (g *DataExposureGenerator) verbosePayloads() []Payload {
	return []Payload{
		{
			Value:       "true",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Enable verbose mode",
			Metadata:    map[string]string{"param": "verbose"},
		},
		{
			Value:       "true",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Enable debug mode",
			Metadata:    map[string]string{"param": "debug"},
		},
		{
			Value:       "full",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Request full response",
			Metadata:    map[string]string{"param": "response"},
		},
		{
			Value:       "detailed",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Request detailed response",
			Metadata:    map[string]string{"param": "detail"},
		},
		{
			Value:       "1000000",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "High limit to retrieve all records",
			Metadata:    map[string]string{"param": "limit"},
		},
		{
			Value:       "-1",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Negative limit to bypass pagination",
			Metadata:    map[string]string{"param": "limit"},
		},
	}
}

// filterBypassPayloads generates payloads to bypass data filtering
func (g *DataExposureGenerator) filterBypassPayloads() []Payload {
	return []Payload{
		{
			Value:       "",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Empty filter to retrieve all",
		},
		{
			Value:       "{}",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Empty JSON filter",
		},
		{
			Value:       "[]",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Empty array filter",
		},
		{
			Value:       "null",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Null filter value",
		},
		{
			Value:       "!deleted",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Include deleted records",
		},
		{
			Value:       "include_deleted=true",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Include deleted flag",
		},
		{
			Value:       "with_trashed",
			Type:        types.AttackDataExposure,
			Category:    "information",
			Description: "Include soft-deleted (Laravel style)",
		},
	}
}
