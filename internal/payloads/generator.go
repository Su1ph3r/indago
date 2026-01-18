// Package payloads provides attack payload generation
package payloads

import (
	"context"

	"github.com/su1ph3r/indago/internal/llm"
	"github.com/su1ph3r/indago/pkg/types"
)

// Generator orchestrates payload generation for attacks
type Generator struct {
	provider   llm.Provider
	config     types.AttackSettings
	generators map[string]AttackGenerator
}

// AttackGenerator interface for specific attack type generators
type AttackGenerator interface {
	// Generate generates payloads for the given endpoint and parameter
	Generate(endpoint types.Endpoint, param *types.Parameter) []Payload

	// Type returns the attack type
	Type() string
}

// Payload represents a single attack payload
type Payload struct {
	Value       string            `json:"value"`
	Type        string            `json:"type"`
	Category    string            `json:"category"`
	Description string            `json:"description"`
	Encoding    string            `json:"encoding,omitempty"` // none, url, base64, etc.
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// FuzzRequest represents a request to be fuzzed
type FuzzRequest struct {
	Endpoint    types.Endpoint
	Param       *types.Parameter
	Payload     Payload
	Original    string
	Position    string // query, path, header, body
}

// NewGenerator creates a new payload generator
func NewGenerator(provider llm.Provider, config types.AttackSettings) *Generator {
	g := &Generator{
		provider:   provider,
		config:     config,
		generators: make(map[string]AttackGenerator),
	}

	// Register attack generators
	g.generators[types.AttackIDOR] = NewIDORGenerator(config.IDOR)
	g.generators[types.AttackSQLi] = NewInjectionGenerator(config.Injection).ForSQLi()
	g.generators[types.AttackNoSQLi] = NewInjectionGenerator(config.Injection).ForNoSQLi()
	g.generators[types.AttackCommandInject] = NewInjectionGenerator(config.Injection).ForCommand()
	g.generators[types.AttackXSS] = NewXSSGenerator()
	g.generators[types.AttackAuthBypass] = NewAuthBypassGenerator()
	g.generators[types.AttackMassAssignment] = NewMassAssignmentGenerator()
	g.generators[types.AttackSSRF] = NewSSRFGenerator()
	g.generators[types.AttackPathTraversal] = NewPathTraversalGenerator()
	g.generators[types.AttackBOLA] = NewBOLAGenerator()
	g.generators[types.AttackBFLA] = NewBFLAGenerator()
	g.generators[types.AttackRateLimit] = NewRateLimitGenerator()
	g.generators[types.AttackDataExposure] = NewDataExposureGenerator()
	g.generators[types.AttackLDAP] = NewLDAPGenerator()
	g.generators[types.AttackXPath] = NewXPathGenerator()
	g.generators[types.AttackSSTI] = NewSSTIGenerator()
	g.generators[types.AttackJWT] = NewJWTGenerator()

	return g
}

// GenerateForEndpoint generates all applicable payloads for an endpoint
func (g *Generator) GenerateForEndpoint(endpoint types.Endpoint) []FuzzRequest {
	var requests []FuzzRequest

	// Determine which attack types to use
	attackTypes := g.getAttackTypes(endpoint)

	// Generate payloads for each parameter
	for i := range endpoint.Parameters {
		param := &endpoint.Parameters[i]
		for _, attackType := range attackTypes {
			if gen, ok := g.generators[attackType]; ok {
				payloads := gen.Generate(endpoint, param)
				for _, payload := range payloads {
					requests = append(requests, FuzzRequest{
						Endpoint: endpoint,
						Param:    param,
						Payload:  payload,
						Original: g.getOriginalValue(param),
						Position: param.In,
					})
				}
			}
		}
	}

	// Generate payloads for body fields
	if endpoint.Body != nil {
		for i := range endpoint.Body.Fields {
			field := &endpoint.Body.Fields[i]
			param := fieldToParam(field)
			for _, attackType := range attackTypes {
				if gen, ok := g.generators[attackType]; ok {
					payloads := gen.Generate(endpoint, param)
					for _, payload := range payloads {
						requests = append(requests, FuzzRequest{
							Endpoint: endpoint,
							Param:    param,
							Payload:  payload,
							Original: g.getOriginalValue(param),
							Position: "body",
						})
					}
				}
			}
		}
	}

	// Limit payloads if configured
	if g.config.MaxPayloadsPerType > 0 {
		requests = g.limitPayloads(requests)
	}

	return requests
}

// GenerateWithLLM uses the LLM to generate contextual payloads
func (g *Generator) GenerateWithLLM(ctx context.Context, endpoint types.Endpoint) ([]Payload, error) {
	if g.provider == nil {
		return nil, nil
	}

	// Use LLM to generate targeted payloads based on business context
	prompt := g.buildPayloadPrompt(endpoint)

	var payloads []Payload
	err := g.provider.AnalyzeStructured(ctx, prompt, &payloads)
	if err != nil {
		return nil, err
	}

	return payloads, nil
}

// getAttackTypes determines which attacks to try based on endpoint
func (g *Generator) getAttackTypes(endpoint types.Endpoint) []string {
	var attacks []string

	// Check if specific attacks are enabled/disabled
	enabled := make(map[string]bool)
	for _, a := range g.config.Enabled {
		enabled[a] = true
	}
	disabled := make(map[string]bool)
	for _, a := range g.config.Disabled {
		disabled[a] = true
	}

	// Default attacks based on endpoint characteristics
	allAttacks := []string{
		types.AttackIDOR,
		types.AttackSQLi,
		types.AttackXSS,
		types.AttackAuthBypass,
	}

	// Add based on method
	if endpoint.Method == "POST" || endpoint.Method == "PUT" || endpoint.Method == "PATCH" {
		allAttacks = append(allAttacks, types.AttackMassAssignment)
	}

	// Add from suggested attacks
	for _, suggested := range endpoint.SuggestedAttacks {
		allAttacks = append(allAttacks, suggested.Type)
	}

	// Filter based on config
	for _, attack := range allAttacks {
		if disabled[attack] {
			continue
		}
		if len(enabled) > 0 && !enabled[attack] {
			continue
		}
		attacks = append(attacks, attack)
	}

	return uniqueStrings(attacks)
}

// getOriginalValue gets the original/example value for a parameter
func (g *Generator) getOriginalValue(param *types.Parameter) string {
	if param.Example != nil {
		switch v := param.Example.(type) {
		case string:
			return v
		}
	}
	if param.Default != nil {
		switch v := param.Default.(type) {
		case string:
			return v
		}
	}
	return ""
}

// limitPayloads limits the number of payloads per attack type
func (g *Generator) limitPayloads(requests []FuzzRequest) []FuzzRequest {
	counts := make(map[string]int)
	var limited []FuzzRequest

	for _, req := range requests {
		key := req.Payload.Type + ":" + req.Param.Name
		if counts[key] < g.config.MaxPayloadsPerType {
			limited = append(limited, req)
			counts[key]++
		}
	}

	return limited
}

// buildPayloadPrompt builds a prompt for LLM payload generation
func (g *Generator) buildPayloadPrompt(endpoint types.Endpoint) string {
	return `Generate targeted security testing payloads for this endpoint:

Endpoint: ` + endpoint.Method + ` ` + endpoint.Path + `
Business Context: ` + endpoint.BusinessContext + `

Generate payloads as JSON array:
[
  {
    "value": "the payload string",
    "type": "attack type",
    "category": "category",
    "description": "what this tests"
  }
]

Focus on business-logic specific attacks based on the context.
Respond with JSON only.`
}

// fieldToParam converts a body field to a parameter for consistent handling
func fieldToParam(field *types.BodyField) *types.Parameter {
	return &types.Parameter{
		Name:        field.Name,
		In:          "body",
		Type:        field.Type,
		Required:    field.Required,
		Description: field.Description,
		Example:     field.Example,
	}
}

// uniqueStrings returns unique strings from a slice
func uniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
