// Package payloads provides attack payload generation
package payloads

import (
	"context"
	"fmt"
	"strings"

	"github.com/su1ph3r/indago/internal/llm"
	"github.com/su1ph3r/indago/pkg/types"
)

// Generator orchestrates payload generation for attacks
type Generator struct {
	provider    llm.Provider
	config      types.AttackSettings
	generators  map[string]AttackGenerator
	userContext string
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
func NewGenerator(provider llm.Provider, config types.AttackSettings, userContext string) *Generator {
	g := &Generator{
		provider:    provider,
		config:      config,
		generators:  make(map[string]AttackGenerator),
		userContext: userContext,
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

	// New active generators
	g.generators[types.AttackMethodTampering] = NewMethodTamperingGenerator()
	g.generators[types.AttackOpenRedirect] = NewOpenRedirectGenerator()
	g.generators[types.AttackContentTypeConfusion] = NewContentTypeConfusionGenerator()

	// Register existing generators that were previously unwired
	g.generators["graphql"] = NewGraphQLGenerator(GraphQLSettings{})
	g.generators["blind"] = NewBlindGenerator(BlindSettings{})

	return g
}

// GenerateForEndpoint generates all applicable payloads for an endpoint
func (g *Generator) GenerateForEndpoint(ctx context.Context, endpoint types.Endpoint) []FuzzRequest {
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

	// Add LLM-suggested payloads from endpoint analysis
	for _, payload := range g.getLLMPayloads(endpoint) {
		if targetParam := g.findTargetParam(endpoint, payload); targetParam != nil {
			requests = append(requests, FuzzRequest{
				Endpoint: endpoint,
				Param:    targetParam,
				Payload:  payload,
				Original: g.getOriginalValue(targetParam),
				Position: targetParam.In,
			})
		}
	}

	// Generate dynamic LLM payloads if enabled
	if g.config.UseLLMPayloads && g.provider != nil {
		llmPayloads, err := g.GenerateWithLLM(ctx, endpoint)
		if err == nil && len(llmPayloads) > 0 {
			for _, payload := range llmPayloads {
				// Add source metadata
				if payload.Metadata == nil {
					payload.Metadata = make(map[string]string)
				}
				payload.Metadata["source"] = "llm-dynamic"

				if targetParam := g.findTargetParam(endpoint, payload); targetParam != nil {
					requests = append(requests, FuzzRequest{
						Endpoint: endpoint,
						Param:    targetParam,
						Payload:  payload,
						Original: g.getOriginalValue(targetParam),
						Position: targetParam.In,
					})
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
		types.AttackMethodTampering,
	}

	// Add based on method
	if endpoint.Method == "POST" || endpoint.Method == "PUT" || endpoint.Method == "PATCH" {
		allAttacks = append(allAttacks, types.AttackMassAssignment)
		allAttacks = append(allAttacks, types.AttackContentTypeConfusion)
	}

	// Add open redirect if redirect-like params exist
	for _, p := range endpoint.Parameters {
		if isRedirectParam(p.Name) {
			allAttacks = append(allAttacks, types.AttackOpenRedirect)
			break
		}
	}
	if endpoint.Body != nil {
		for _, f := range endpoint.Body.Fields {
			if isRedirectParam(f.Name) {
				allAttacks = append(allAttacks, types.AttackOpenRedirect)
				break
			}
		}
	}

	// Add GraphQL attacks for GraphQL endpoints
	if strings.Contains(strings.ToLower(endpoint.Path), "/graphql") {
		allAttacks = append(allAttacks, "graphql")
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
	var sb strings.Builder

	sb.WriteString("Generate targeted security testing payloads for this API endpoint:\n\n")

	if g.userContext != "" {
		sb.WriteString(fmt.Sprintf("API Context: %s\n\n", g.userContext))
	}

	sb.WriteString(fmt.Sprintf("Endpoint: %s %s\n", endpoint.Method, endpoint.Path))

	if endpoint.BusinessContext != "" {
		sb.WriteString(fmt.Sprintf("Business Context: %s\n", endpoint.BusinessContext))
	}

	if endpoint.Description != "" {
		sb.WriteString(fmt.Sprintf("Description: %s\n", endpoint.Description))
	}

	if endpoint.SensitivityLevel != "" {
		sb.WriteString(fmt.Sprintf("Sensitivity: %s\n", endpoint.SensitivityLevel))
	}

	// Include parameter details
	if len(endpoint.Parameters) > 0 {
		sb.WriteString("\nParameters:\n")
		for _, p := range endpoint.Parameters {
			sb.WriteString(fmt.Sprintf("  - %s (%s, in: %s)", p.Name, p.Type, p.In))
			if p.Description != "" {
				sb.WriteString(fmt.Sprintf(" - %s", p.Description))
			}
			sb.WriteString("\n")
		}
	}

	// Include body fields
	if endpoint.Body != nil && len(endpoint.Body.Fields) > 0 {
		sb.WriteString("\nBody Fields:\n")
		for _, f := range endpoint.Body.Fields {
			sb.WriteString(fmt.Sprintf("  - %s (%s)", f.Name, f.Type))
			if f.Description != "" {
				sb.WriteString(fmt.Sprintf(" - %s", f.Description))
			}
			if f.Required {
				sb.WriteString(" [required]")
			}
			sb.WriteString("\n")
		}
	}

	sb.WriteString(`
Generate payloads as JSON array. Include a "metadata" object with "target_param" set to the parameter name:
[
  {
    "value": "the payload string",
    "type": "attack type (e.g., sqli, xss, idor, auth_bypass)",
    "category": "category",
    "description": "what this tests",
    "metadata": {"target_param": "parameter_name"}
  }
]

Focus on business-logic specific attacks based on the context and parameter semantics.
Generate 3-5 highly targeted payloads.
Respond with JSON only.`)

	return sb.String()
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

// getLLMPayloads extracts payloads from LLM-suggested attacks on the endpoint
func (g *Generator) getLLMPayloads(endpoint types.Endpoint) []Payload {
	var payloads []Payload
	for _, attack := range endpoint.SuggestedAttacks {
		for _, p := range attack.Payloads {
			payloads = append(payloads, Payload{
				Value:       p,
				Type:        attack.Type,
				Category:    attack.Category,
				Description: fmt.Sprintf("LLM-suggested: %s", attack.Rationale),
				Metadata: map[string]string{
					"source":       "llm",
					"target_param": attack.TargetParam.String(),
					"priority":     attack.Priority,
				},
			})
		}
	}
	return payloads
}

// findTargetParam finds the parameter that matches the payload's target
func (g *Generator) findTargetParam(endpoint types.Endpoint, payload Payload) *types.Parameter {
	targetName := ""
	if payload.Metadata != nil {
		targetName = payload.Metadata["target_param"]
	}

	// Check endpoint parameters
	for i := range endpoint.Parameters {
		if strings.EqualFold(endpoint.Parameters[i].Name, targetName) {
			return &endpoint.Parameters[i]
		}
	}

	// Check body fields
	if endpoint.Body != nil {
		for i := range endpoint.Body.Fields {
			if strings.EqualFold(endpoint.Body.Fields[i].Name, targetName) {
				return fieldToParam(&endpoint.Body.Fields[i])
			}
		}
	}

	// Fallback: first string parameter
	for i := range endpoint.Parameters {
		if endpoint.Parameters[i].Type == "string" || endpoint.Parameters[i].Type == "" {
			return &endpoint.Parameters[i]
		}
	}

	// Fallback: first body field if no params
	if endpoint.Body != nil && len(endpoint.Body.Fields) > 0 {
		return fieldToParam(&endpoint.Body.Fields[0])
	}

	return nil
}
