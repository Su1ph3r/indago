// Package analyzer provides business logic analysis using LLMs
package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/su1ph3r/indago/internal/llm"
	"github.com/su1ph3r/indago/pkg/types"
)

// BusinessAnalyzer uses LLM to understand API business context
type BusinessAnalyzer struct {
	provider llm.Provider
}

// NewBusinessAnalyzer creates a new business logic analyzer
func NewBusinessAnalyzer(provider llm.Provider) *BusinessAnalyzer {
	return &BusinessAnalyzer{
		provider: provider,
	}
}

// AnalysisResult contains the LLM's analysis of endpoints
type AnalysisResult struct {
	Domain           string              `json:"domain"`
	BusinessContext  string              `json:"business_context"`
	EndpointAnalysis []EndpointAnalysis  `json:"endpoint_analysis"`
	Relationships    []EndpointRelation  `json:"relationships"`
	SecurityConcerns []string            `json:"security_concerns"`
}

// EndpointAnalysis contains analysis for a single endpoint
type EndpointAnalysis struct {
	Endpoint         string              `json:"endpoint"`
	Method           string              `json:"method"`
	Purpose          string              `json:"purpose"`
	SensitivityLevel string              `json:"sensitivity_level"`
	IDORCandidate    bool                `json:"idor_candidate"`
	AuthRequired     bool                `json:"auth_required"`
	DataExposureRisk bool                `json:"data_exposure_risk"`
	SuggestedAttacks []types.AttackVector `json:"suggested_attacks"`
	TargetParams     []string            `json:"target_params"`
}

// EndpointRelation describes a relationship between endpoints
type EndpointRelation struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Relation    string `json:"relation"` // creates, reads, updates, deletes, references
	Description string `json:"description"`
}

// Analyze analyzes endpoints to understand business context
func (a *BusinessAnalyzer) Analyze(ctx context.Context, endpoints []types.Endpoint) (*AnalysisResult, error) {
	// Build the analysis prompt
	prompt := a.buildAnalysisPrompt(endpoints)

	// Get analysis from LLM
	system := `You are a security researcher analyzing an API for vulnerabilities.
Your task is to understand the business context and identify potential security issues.
Always respond with valid JSON matching the requested schema.
Be thorough but concise in your analysis.`

	response, err := a.provider.AnalyzeWithSystem(ctx, system, prompt)
	if err != nil {
		return nil, fmt.Errorf("LLM analysis failed: %w", err)
	}

	// Parse the response
	var result AnalysisResult
	if err := llm.ParseJSONResponse(response, &result); err != nil {
		return nil, fmt.Errorf("failed to parse analysis: %w", err)
	}

	return &result, nil
}

// EnrichEndpoints enriches endpoints with LLM analysis
func (a *BusinessAnalyzer) EnrichEndpoints(ctx context.Context, endpoints []types.Endpoint) ([]types.Endpoint, error) {
	// Analyze the endpoints
	analysis, err := a.Analyze(ctx, endpoints)
	if err != nil {
		return nil, err
	}

	// Create a map of analysis by endpoint key
	analysisMap := make(map[string]*EndpointAnalysis)
	for i := range analysis.EndpointAnalysis {
		ea := &analysis.EndpointAnalysis[i]
		key := ea.Method + ":" + ea.Endpoint
		analysisMap[key] = ea
	}

	// Enrich each endpoint
	enriched := make([]types.Endpoint, len(endpoints))
	for i, ep := range endpoints {
		enriched[i] = ep
		key := ep.Method + ":" + ep.Path

		if ea, ok := analysisMap[key]; ok {
			enriched[i].BusinessContext = ea.Purpose
			enriched[i].SensitivityLevel = ea.SensitivityLevel
			enriched[i].SuggestedAttacks = ea.SuggestedAttacks

			// Find related endpoints
			for _, rel := range analysis.Relationships {
				if rel.From == ep.Path {
					enriched[i].RelatedEndpoints = append(enriched[i].RelatedEndpoints, rel.To)
				}
			}
		}
	}

	return enriched, nil
}

// buildAnalysisPrompt creates the prompt for API analysis
func (a *BusinessAnalyzer) buildAnalysisPrompt(endpoints []types.Endpoint) string {
	var sb strings.Builder

	sb.WriteString("Analyze the following API endpoints and provide security insights.\n\n")
	sb.WriteString("## Endpoints\n\n")

	for _, ep := range endpoints {
		sb.WriteString(fmt.Sprintf("### %s %s\n", ep.Method, ep.Path))

		if ep.Description != "" {
			sb.WriteString(fmt.Sprintf("Description: %s\n", ep.Description))
		}

		if len(ep.Tags) > 0 {
			sb.WriteString(fmt.Sprintf("Tags: %s\n", strings.Join(ep.Tags, ", ")))
		}

		if len(ep.Parameters) > 0 {
			sb.WriteString("Parameters:\n")
			for _, p := range ep.Parameters {
				required := ""
				if p.Required {
					required = " (required)"
				}
				sb.WriteString(fmt.Sprintf("  - %s (%s, %s)%s: %s\n", p.Name, p.In, p.Type, required, p.Description))
			}
		}

		if ep.Body != nil && len(ep.Body.Fields) > 0 {
			sb.WriteString("Body fields:\n")
			for _, f := range ep.Body.Fields {
				required := ""
				if f.Required {
					required = " (required)"
				}
				sb.WriteString(fmt.Sprintf("  - %s (%s)%s: %s\n", f.Name, f.Type, required, f.Description))
			}
		}

		sb.WriteString("\n")
	}

	sb.WriteString(`
## Analysis Required

Provide a JSON response with the following structure:
{
  "domain": "Brief description of the API's business domain",
  "business_context": "Overall understanding of what this API does",
  "endpoint_analysis": [
    {
      "endpoint": "/path",
      "method": "GET|POST|etc",
      "purpose": "What this endpoint does",
      "sensitivity_level": "critical|high|medium|low",
      "idor_candidate": true/false,
      "auth_required": true/false,
      "data_exposure_risk": true/false,
      "suggested_attacks": [
        {
          "type": "sqli",
          "category": "injection",
          "priority": "high",
          "rationale": "Why this attack is relevant",
          "target_param": "id",
          "payloads": ["' OR '1'='1", "1; DROP TABLE users--"]
        }
      ],
      "target_params": ["param1", "param2"]
    }
  ],
  "relationships": [
    {
      "from": "/endpoint1",
      "to": "/endpoint2",
      "relation": "creates|reads|updates|deletes|references",
      "description": "How they relate"
    }
  ],
  "security_concerns": ["Concern 1", "Concern 2"]
}

Focus on:
1. IDOR vulnerabilities - endpoints with ID parameters that could access other users' data
2. Authentication bypass opportunities
3. Mass assignment vulnerabilities in POST/PUT endpoints
4. Sensitive data exposure risks
5. Business logic flaws based on endpoint relationships
6. Injection points in parameters

Respond with valid JSON only.`)

	return sb.String()
}

// AnalyzeForAttacks generates targeted attack recommendations
func (a *BusinessAnalyzer) AnalyzeForAttacks(ctx context.Context, endpoint types.Endpoint) ([]types.AttackVector, error) {
	prompt := a.buildAttackPrompt(endpoint)

	system := `You are a penetration tester analyzing an API endpoint for vulnerabilities.
Generate specific attack vectors based on the endpoint's parameters and purpose.
Respond with valid JSON only.`

	response, err := a.provider.AnalyzeWithSystem(ctx, system, prompt)
	if err != nil {
		return nil, fmt.Errorf("attack analysis failed: %w", err)
	}

	var attacks []types.AttackVector
	if err := llm.ParseJSONResponse(response, &attacks); err != nil {
		return nil, fmt.Errorf("failed to parse attacks: %w", err)
	}

	return attacks, nil
}

// buildAttackPrompt creates a prompt for attack generation
func (a *BusinessAnalyzer) buildAttackPrompt(ep types.Endpoint) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Analyze this endpoint for attack vectors:\n\n"))
	sb.WriteString(fmt.Sprintf("Endpoint: %s %s\n", ep.Method, ep.Path))

	if ep.Description != "" {
		sb.WriteString(fmt.Sprintf("Description: %s\n", ep.Description))
	}

	if ep.BusinessContext != "" {
		sb.WriteString(fmt.Sprintf("Business Context: %s\n", ep.BusinessContext))
	}

	if len(ep.Parameters) > 0 {
		sb.WriteString("\nParameters:\n")
		for _, p := range ep.Parameters {
			paramInfo := fmt.Sprintf("- %s (in: %s, type: %s)", p.Name, p.In, p.Type)
			if p.Example != nil {
				paramInfo += fmt.Sprintf(", example: %v", p.Example)
			}
			sb.WriteString(paramInfo + "\n")
		}
	}

	if ep.Body != nil {
		bodyJSON, _ := json.Marshal(ep.Body)
		sb.WriteString(fmt.Sprintf("\nRequest Body: %s\n", string(bodyJSON)))
	}

	sb.WriteString(`
Generate attack vectors as JSON array:
[
  {
    "type": "idor|sqli|nosqli|command_injection|xss|auth_bypass|mass_assignment|bola|bfla|rate_limit|data_exposure|ssrf|path_traversal",
    "category": "authorization|injection|information_disclosure|authentication",
    "priority": "high|medium|low",
    "rationale": "Why this attack is relevant for this specific endpoint",
    "target_param": "specific parameter to target",
    "payloads": ["example payload 1", "example payload 2"]
  }
]

Consider:
- Parameter types and names (id, user_id, etc. suggest IDOR)
- String parameters for injection attacks
- File/path parameters for traversal
- The HTTP method and its typical vulnerabilities
- Business logic based on the endpoint purpose

Respond with JSON array only.`)

	return sb.String()
}
