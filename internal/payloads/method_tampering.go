// Package payloads provides attack payload generation
package payloads

import (
	"github.com/su1ph3r/indago/pkg/types"
)

// MethodTamperingGenerator generates payloads that attempt to use unauthorized
// HTTP methods on an endpoint. It also generates method-override header payloads.
type MethodTamperingGenerator struct{}

// NewMethodTamperingGenerator creates a new method tampering generator.
func NewMethodTamperingGenerator() *MethodTamperingGenerator {
	return &MethodTamperingGenerator{}
}

// Type returns the attack type.
func (g *MethodTamperingGenerator) Type() string {
	return types.AttackMethodTampering
}

// Generate produces method tampering payloads. Only runs for the first
// parameter to avoid N*M explosion.
func (g *MethodTamperingGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	// Sentinel: only generate for the first parameter
	if len(endpoint.Parameters) > 0 && param.Name != endpoint.Parameters[0].Name {
		return nil
	}
	if endpoint.Body != nil && len(endpoint.Parameters) == 0 &&
		len(endpoint.Body.Fields) > 0 && param.Name != endpoint.Body.Fields[0].Name {
		return nil
	}

	var payloads []Payload

	// Determine which methods to try based on endpoint's declared method
	var methods []string
	switch endpoint.Method {
	case "GET":
		methods = []string{"DELETE", "PUT", "PATCH"}
	case "POST":
		methods = []string{"DELETE", "PUT"}
	case "PUT", "PATCH":
		methods = []string{"DELETE"}
	}

	// Always try TRACE
	methods = append(methods, "TRACE")

	for _, method := range methods {
		payloads = append(payloads, Payload{
			Value:       param.Name, // keep original value; the method change is the attack
			Type:        types.AttackMethodTampering,
			Category:    "authorization",
			Description: "HTTP method override to " + method,
			Metadata: map[string]string{
				"override_method": method,
			},
		})
	}

	// Method override headers (tunneled through POST)
	overrideHeaders := []struct{ header, value string }{
		{"X-HTTP-Method-Override", "DELETE"},
		{"X-Method-Override", "DELETE"},
		{"X-HTTP-Method", "DELETE"},
	}

	for _, oh := range overrideHeaders {
		payloads = append(payloads, Payload{
			Value:       param.Name,
			Type:        types.AttackMethodTampering,
			Category:    "authorization",
			Description: "Method override via " + oh.header + ": " + oh.value,
			Metadata: map[string]string{
				"inject_header":       oh.header,
				"inject_header_value": oh.value,
			},
		})
	}

	return payloads
}
