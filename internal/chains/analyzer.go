// Package chains provides multi-step attack chain functionality
package chains

import (
	"context"
	"fmt"
	"strings"

	"github.com/su1ph3r/indago/internal/llm"
	"github.com/su1ph3r/indago/pkg/types"
)

// ChainAnalyzer uses LLM to discover attack chain opportunities
type ChainAnalyzer struct {
	provider llm.Provider
	graph    *EndpointGraph
}

// NewChainAnalyzer creates a new chain analyzer
func NewChainAnalyzer(provider llm.Provider) *ChainAnalyzer {
	return &ChainAnalyzer{
		provider: provider,
		graph:    NewEndpointGraph(),
	}
}

// AnalyzeEndpoints analyzes endpoints and discovers potential attack chains
func (ca *ChainAnalyzer) AnalyzeEndpoints(ctx context.Context, endpoints []types.Endpoint) ([]*AttackChain, error) {
	// Build endpoint graph
	for _, ep := range endpoints {
		ca.graph.AddEndpoint(ep)
	}
	ca.graph.BuildRelationships()

	var chains []*AttackChain

	// First, use graph analysis to find chain candidates
	graphChains := ca.discoverFromGraph(endpoints)
	chains = append(chains, graphChains...)

	// Then, use LLM for deeper analysis if available
	if ca.provider != nil {
		llmChains, err := ca.discoverWithLLM(ctx, endpoints)
		if err == nil && len(llmChains) > 0 {
			chains = append(chains, llmChains...)
		}
	}

	// Deduplicate chains
	chains = ca.deduplicateChains(chains)

	return chains, nil
}

// discoverFromGraph uses graph analysis to find chains
func (ca *ChainAnalyzer) discoverFromGraph(endpoints []types.Endpoint) []*AttackChain {
	var chains []*AttackChain

	// Find auth-related chains
	authChains := ca.findAuthChains(endpoints)
	chains = append(chains, authChains...)

	// Find IDOR chains
	idorChains := ca.findIDORChains(endpoints)
	chains = append(chains, idorChains...)

	// Find privilege escalation chains
	privEscChains := ca.findPrivilegeEscalationChains(endpoints)
	chains = append(chains, privEscChains...)

	// Find data leakage chains
	dataLeakChains := ca.findDataLeakageChains(endpoints)
	chains = append(chains, dataLeakChains...)

	return chains
}

// findAuthChains finds authentication-related attack chains
func (ca *ChainAnalyzer) findAuthChains(endpoints []types.Endpoint) []*AttackChain {
	var chains []*AttackChain

	var loginEndpoints, protectedEndpoints []types.Endpoint

	for _, ep := range endpoints {
		pathLower := strings.ToLower(ep.Path)
		if (strings.Contains(pathLower, "login") || strings.Contains(pathLower, "auth")) && ep.Method == "POST" {
			loginEndpoints = append(loginEndpoints, ep)
		}
		if strings.Contains(pathLower, "/admin") || strings.Contains(pathLower, "/user") {
			protectedEndpoints = append(protectedEndpoints, ep)
		}
	}

	// Create auth bypass chains
	for _, login := range loginEndpoints {
		for _, protected := range protectedEndpoints {
			chain := &AttackChain{
				ID:          fmt.Sprintf("auth-bypass-%s", protected.Path),
				Name:        "Authentication Bypass to " + protected.Path,
				Description: "Attempt to access protected endpoint without proper authentication",
				Purpose:     PurposeAuthBypass,
				Category:    "authentication",
				Priority:    "high",
				Steps: []ChainStep{
					{
						ID:       "login",
						Name:     "Authenticate",
						Endpoint: login,
						Role:     RoleSetup,
						Required: true,
						ExtractVars: []Extraction{
							{Name: "token", Type: "json", Path: "$.token", SaveAs: "auth_token"},
							{Name: "alt_token", Type: "json", Path: "$.access_token", SaveAs: "auth_token"},
						},
					},
					{
						ID:       "access_protected",
						Name:     "Access Protected Resource",
						Endpoint: protected,
						Role:     RoleAttack,
						Required: true,
						InjectVars: []string{"auth_token"},
					},
				},
			}
			chains = append(chains, chain)
		}
	}

	return chains
}

// findIDORChains finds IDOR vulnerability chains
func (ca *ChainAnalyzer) findIDORChains(endpoints []types.Endpoint) []*AttackChain {
	var chains []*AttackChain

	// Group endpoints by resource type
	resourceEndpoints := make(map[string][]types.Endpoint)
	for _, ep := range endpoints {
		resourceType := inferResourceType(ep)
		if resourceType != "" {
			resourceEndpoints[resourceType] = append(resourceEndpoints[resourceType], ep)
		}
	}

	// Create IDOR chains for each resource type
	for resourceType, eps := range resourceEndpoints {
		// Find create and read endpoints
		var createEP, readEP *types.Endpoint
		for i := range eps {
			if eps[i].Method == "POST" {
				createEP = &eps[i]
			}
			if eps[i].Method == "GET" {
				// Check if it has an ID parameter
				for _, p := range eps[i].Parameters {
					if strings.Contains(strings.ToLower(p.Name), "id") {
						readEP = &eps[i]
						break
					}
				}
			}
		}

		if readEP != nil {
			chain := &AttackChain{
				ID:          fmt.Sprintf("idor-%s", resourceType),
				Name:        fmt.Sprintf("IDOR on %s Resource", resourceType),
				Description: fmt.Sprintf("Access unauthorized %s resources by manipulating IDs", resourceType),
				Purpose:     PurposeIDOR,
				Category:    "authorization",
				Priority:    "high",
				Steps: []ChainStep{
					{
						ID:       "get_own",
						Name:     "Get Own " + resourceType,
						Endpoint: *readEP,
						Role:     RoleSetup,
						Required: true,
						ExtractVars: []Extraction{
							{Name: "id", Type: "json", Path: "$.id", SaveAs: "own_id"},
						},
					},
					{
						ID:       "access_other",
						Name:     "Access Other User's " + resourceType,
						Endpoint: *readEP,
						Role:     RoleAttack,
						Required: true,
						Payloads: []StepPayload{
							{Target: "id", Value: "1", Type: "idor", Position: "path"},
							{Target: "id", Value: "{{own_id}}+1", Type: "idor", Position: "path"},
							{Target: "id", Value: "{{own_id}}-1", Type: "idor", Position: "path"},
						},
					},
				},
			}

			if createEP != nil {
				// Add create step at the beginning
				createStep := ChainStep{
					ID:       "create",
					Name:     "Create " + resourceType,
					Endpoint: *createEP,
					Role:     RoleSetup,
					Required: false,
					ExtractVars: []Extraction{
						{Name: "created_id", Type: "json", Path: "$.id", SaveAs: "created_id"},
					},
				}
				chain.Steps = append([]ChainStep{createStep}, chain.Steps...)
			}

			chains = append(chains, chain)
		}
	}

	return chains
}

// findPrivilegeEscalationChains finds privilege escalation chains
func (ca *ChainAnalyzer) findPrivilegeEscalationChains(endpoints []types.Endpoint) []*AttackChain {
	var chains []*AttackChain

	// Find user and admin endpoints
	var userEndpoints, adminEndpoints []types.Endpoint

	for _, ep := range endpoints {
		pathLower := strings.ToLower(ep.Path)
		if strings.Contains(pathLower, "/admin") {
			adminEndpoints = append(adminEndpoints, ep)
		}
		if strings.Contains(pathLower, "/user") || strings.Contains(pathLower, "/profile") {
			userEndpoints = append(userEndpoints, ep)
		}
	}

	// Create priv esc chains
	for _, adminEP := range adminEndpoints {
		chain := &AttackChain{
			ID:          fmt.Sprintf("priv-esc-%s", strings.ReplaceAll(adminEP.Path, "/", "-")),
			Name:        "Privilege Escalation to " + adminEP.Path,
			Description: "Attempt to access admin functionality as regular user",
			Purpose:     PurposePrivilegeEscalation,
			Category:    "authorization",
			Priority:    "critical",
			Steps: []ChainStep{
				{
					ID:       "auth_user",
					Name:     "Authenticate as Regular User",
					Role:     RoleSetup,
					Required: true,
					ExtractVars: []Extraction{
						{Name: "token", Type: "json", Path: "$.token", SaveAs: "user_token"},
					},
				},
				{
					ID:       "access_admin",
					Name:     "Access Admin Endpoint",
					Endpoint: adminEP,
					Role:     RoleAttack,
					Required: true,
					InjectVars: []string{"user_token"},
					Conditions: []Condition{
						{Type: ConditionStatusCode, Operator: OperatorEq, Value: "200"},
					},
				},
			},
		}

		chains = append(chains, chain)
	}

	return chains
}

// findDataLeakageChains finds data leakage chains
func (ca *ChainAnalyzer) findDataLeakageChains(endpoints []types.Endpoint) []*AttackChain {
	var chains []*AttackChain

	// Look for endpoints that might leak sensitive data
	sensitivePatterns := []string{
		"/users", "/accounts", "/profiles",
		"/payment", "/billing", "/card",
		"/admin", "/internal", "/debug",
	}

	for _, ep := range endpoints {
		if ep.Method != "GET" {
			continue
		}

		pathLower := strings.ToLower(ep.Path)
		for _, pattern := range sensitivePatterns {
			if strings.Contains(pathLower, pattern) {
				chain := &AttackChain{
					ID:          fmt.Sprintf("data-leak-%s", strings.ReplaceAll(ep.Path, "/", "-")),
					Name:        "Data Leakage via " + ep.Path,
					Description: "Check for sensitive data exposure",
					Purpose:     PurposeDataLeakage,
					Category:    "information_disclosure",
					Priority:    "medium",
					Steps: []ChainStep{
						{
							ID:       "fetch_data",
							Name:     "Fetch Data",
							Endpoint: ep,
							Role:     RoleAttack,
							Required: true,
							Conditions: []Condition{
								{Type: ConditionContains, Value: "password", Negate: false},
								{Type: ConditionContains, Value: "token", Negate: false},
								{Type: ConditionContains, Value: "secret", Negate: false},
							},
						},
					},
				}
				chains = append(chains, chain)
				break
			}
		}
	}

	return chains
}

// discoverWithLLM uses LLM to discover attack chains
func (ca *ChainAnalyzer) discoverWithLLM(ctx context.Context, endpoints []types.Endpoint) ([]*AttackChain, error) {
	prompt := buildChainDiscoveryPrompt(endpoints)

	var discoveredChains []*AttackChain
	err := ca.provider.AnalyzeStructured(ctx, prompt, &discoveredChains)
	if err != nil {
		return nil, err
	}

	// Post-process LLM chains
	for i := range discoveredChains {
		if discoveredChains[i].ID == "" {
			discoveredChains[i].ID = fmt.Sprintf("llm-chain-%d", i)
		}
		if discoveredChains[i].Priority == "" {
			discoveredChains[i].Priority = "medium"
		}
	}

	return discoveredChains, nil
}

// buildChainDiscoveryPrompt builds the LLM prompt for chain discovery
func buildChainDiscoveryPrompt(endpoints []types.Endpoint) string {
	var sb strings.Builder

	sb.WriteString("Analyze these API endpoints and identify potential multi-step attack chains:\n\n")

	for _, ep := range endpoints {
		sb.WriteString(fmt.Sprintf("- %s %s", ep.Method, ep.Path))
		if ep.Description != "" {
			sb.WriteString(fmt.Sprintf(" (%s)", ep.Description))
		}
		sb.WriteString("\n")

		if len(ep.Parameters) > 0 {
			sb.WriteString("  Parameters: ")
			for i, p := range ep.Parameters {
				if i > 0 {
					sb.WriteString(", ")
				}
				sb.WriteString(p.Name)
			}
			sb.WriteString("\n")
		}
	}

	sb.WriteString(`
Identify attack chains for:
1. Privilege escalation (user -> admin)
2. IDOR/BOLA (accessing other users' data)
3. Account takeover flows
4. Data leakage paths
5. Mass assignment vulnerabilities

Respond with JSON array of attack chains:
[
  {
    "id": "chain-id",
    "name": "Chain Name",
    "description": "What this chain tests",
    "purpose": "privilege_escalation|idor|account_takeover|data_leakage|mass_assignment",
    "priority": "critical|high|medium|low",
    "steps": [
      {
        "id": "step-id",
        "name": "Step description",
        "role": "setup|attack|verify",
        "endpoint": {"method": "POST", "path": "/api/login"},
        "required": true
      }
    ]
  }
]`)

	return sb.String()
}

// deduplicateChains removes duplicate chains
func (ca *ChainAnalyzer) deduplicateChains(chains []*AttackChain) []*AttackChain {
	seen := make(map[string]bool)
	var unique []*AttackChain

	for _, chain := range chains {
		key := chain.Purpose + ":" + chain.Name
		if !seen[key] {
			seen[key] = true
			unique = append(unique, chain)
		}
	}

	return unique
}

// GetGraph returns the endpoint graph
func (ca *ChainAnalyzer) GetGraph() *EndpointGraph {
	return ca.graph
}
