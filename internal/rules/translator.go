// Package rules provides natural language business rule processing
package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/su1ph3r/indago/internal/llm"
	"github.com/su1ph3r/indago/pkg/types"
)

// RuleTranslator translates business rules to test cases
type RuleTranslator struct {
	provider llm.Provider
}

// NewRuleTranslator creates a new rule translator
func NewRuleTranslator(provider llm.Provider) *RuleTranslator {
	return &RuleTranslator{
		provider: provider,
	}
}

// TranslateRules translates business rules to test cases
func (rt *RuleTranslator) TranslateRules(ctx context.Context, rules []BusinessRule, endpoints []types.Endpoint) ([]RuleTestCase, error) {
	var testCases []RuleTestCase

	for _, rule := range rules {
		// Get matching endpoints
		matchingEndpoints := rt.getMatchingEndpoints(rule, endpoints)

		if rt.provider != nil {
			// Use LLM to generate sophisticated test cases
			cases, err := rt.translateWithLLM(ctx, rule, matchingEndpoints)
			if err == nil && len(cases) > 0 {
				testCases = append(testCases, cases...)
				continue
			}
		}

		// Fallback to heuristic-based translation
		cases := rt.translateHeuristic(rule, matchingEndpoints)
		testCases = append(testCases, cases...)
	}

	return testCases, nil
}

// getMatchingEndpoints returns endpoints that match a rule's scope
func (rt *RuleTranslator) getMatchingEndpoints(rule BusinessRule, endpoints []types.Endpoint) []types.Endpoint {
	var matching []types.Endpoint

	for _, ep := range endpoints {
		if rule.MatchesEndpoint(ep.Method, ep.Path) {
			matching = append(matching, ep)
		}
	}

	// If no explicit scope, match based on keywords in rule description
	if len(matching) == 0 && len(rule.Scope) == 0 {
		matching = rt.inferEndpoints(rule, endpoints)
	}

	return matching
}

// inferEndpoints infers matching endpoints from rule description
func (rt *RuleTranslator) inferEndpoints(rule BusinessRule, endpoints []types.Endpoint) []types.Endpoint {
	var matching []types.Endpoint

	descLower := strings.ToLower(rule.Description)

	// Extract resource keywords
	keywords := extractKeywords(descLower)

	for _, ep := range endpoints {
		pathLower := strings.ToLower(ep.Path)
		for _, kw := range keywords {
			if strings.Contains(pathLower, kw) {
				matching = append(matching, ep)
				break
			}
		}
	}

	return matching
}

// extractKeywords extracts potential resource keywords from text
func extractKeywords(text string) []string {
	// Common resource words
	resources := []string{
		"user", "users", "account", "accounts",
		"order", "orders", "cart", "checkout",
		"product", "products", "item", "items",
		"payment", "payments", "transaction",
		"profile", "profiles", "setting", "settings",
		"admin", "config", "report", "reports",
	}

	var found []string
	for _, r := range resources {
		if strings.Contains(text, r) {
			found = append(found, r)
		}
	}

	return found
}

// translateWithLLM uses LLM to translate rules
func (rt *RuleTranslator) translateWithLLM(ctx context.Context, rule BusinessRule, endpoints []types.Endpoint) ([]RuleTestCase, error) {
	prompt := buildTranslationPrompt(rule, endpoints)

	var testCases []RuleTestCase
	err := rt.provider.AnalyzeStructured(ctx, prompt, &testCases)
	if err != nil {
		return nil, err
	}

	// Post-process and validate
	for i := range testCases {
		testCases[i].RuleID = rule.ID
		testCases[i].Tags = append(testCases[i].Tags, rule.Tags...)
	}

	return testCases, nil
}

// buildTranslationPrompt builds the LLM prompt for rule translation
func buildTranslationPrompt(rule BusinessRule, endpoints []types.Endpoint) string {
	var sb strings.Builder

	sb.WriteString("Translate this business rule into API security test cases:\n\n")
	sb.WriteString("Rule:\n")
	sb.WriteString(fmt.Sprintf("  Description: %s\n", rule.Description))
	sb.WriteString(fmt.Sprintf("  Category: %s\n", rule.Category))
	sb.WriteString(fmt.Sprintf("  Priority: %s\n", rule.Priority))

	if rule.Actor != "" {
		sb.WriteString(fmt.Sprintf("  Actor: %s\n", rule.Actor))
	}
	if rule.Action != "" {
		sb.WriteString(fmt.Sprintf("  Action: %s\n", rule.Action))
	}
	if rule.Resource != "" {
		sb.WriteString(fmt.Sprintf("  Resource: %s\n", rule.Resource))
	}
	if rule.Constraint != "" {
		sb.WriteString(fmt.Sprintf("  Constraint: %s\n", rule.Constraint))
	}

	if len(endpoints) > 0 {
		sb.WriteString("\nRelevant endpoints:\n")
		for _, ep := range endpoints {
			sb.WriteString(fmt.Sprintf("  - %s %s", ep.Method, ep.Path))
			if ep.Description != "" {
				sb.WriteString(fmt.Sprintf(" (%s)", ep.Description))
			}
			sb.WriteString("\n")
		}
	}

	sb.WriteString(`
Generate test cases as JSON array:
[
  {
    "rule_id": "rule-id",
    "description": "test case description",
    "setup_steps": [
      {
        "name": "step name",
        "method": "POST",
        "endpoint": "/api/login",
        "actor": "attacker",
        "body": {"field": "value"}
      }
    ],
    "action_step": {
      "name": "main action",
      "method": "GET",
      "endpoint": "/api/users/123",
      "actor": "attacker"
    },
    "expected_result": {
      "success": false,
      "status_codes": [401, 403],
      "error_message": "Access denied"
    },
    "actors": [
      {"name": "attacker", "role": "regular_user"},
      {"name": "victim", "role": "other_user"}
    ]
  }
]`)

	return sb.String()
}

// translateHeuristic translates rules using heuristics
func (rt *RuleTranslator) translateHeuristic(rule BusinessRule, endpoints []types.Endpoint) []RuleTestCase {
	var testCases []RuleTestCase

	switch rule.Category {
	case "authorization":
		testCases = append(testCases, rt.translateAuthorizationRule(rule, endpoints)...)
	case "data_access":
		testCases = append(testCases, rt.translateDataAccessRule(rule, endpoints)...)
	case "workflow":
		testCases = append(testCases, rt.translateWorkflowRule(rule, endpoints)...)
	default:
		testCases = append(testCases, rt.translateGenericRule(rule, endpoints)...)
	}

	return testCases
}

// translateAuthorizationRule translates authorization rules
func (rt *RuleTranslator) translateAuthorizationRule(rule BusinessRule, endpoints []types.Endpoint) []RuleTestCase {
	var testCases []RuleTestCase

	descLower := strings.ToLower(rule.Description)

	// Check for common authorization patterns
	if strings.Contains(descLower, "other user") || strings.Contains(descLower, "another user") {
		// Horizontal access control test
		for _, ep := range endpoints {
			if hasIDParam(ep) {
				tc := RuleTestCase{
					RuleID:      rule.ID,
					Description: "Verify " + rule.Description,
					ActionStep: TestStep{
						Name:     "Access other user's resource",
						Method:   ep.Method,
						Endpoint: ep.Path,
						Actor:    "attacker",
					},
					ExpectedResult: ExpectedResult{
						Success:     false,
						StatusCodes: []int{401, 403, 404},
					},
					Actors: []TestActor{
						{Name: "attacker", Role: "regular_user"},
						{Name: "victim", Role: "other_user"},
					},
					Tags: []string{"authorization", "horizontal-access"},
				}
				testCases = append(testCases, tc)
			}
		}
	}

	if strings.Contains(descLower, "admin") {
		// Vertical access control test
		for _, ep := range endpoints {
			if strings.Contains(strings.ToLower(ep.Path), "admin") {
				tc := RuleTestCase{
					RuleID:      rule.ID,
					Description: "Verify admin-only access: " + rule.Description,
					ActionStep: TestStep{
						Name:     "Access admin endpoint as regular user",
						Method:   ep.Method,
						Endpoint: ep.Path,
						Actor:    "regular_user",
					},
					ExpectedResult: ExpectedResult{
						Success:     false,
						StatusCodes: []int{401, 403},
					},
					Actors: []TestActor{
						{Name: "regular_user", Role: "user"},
					},
					Tags: []string{"authorization", "vertical-access", "admin"},
				}
				testCases = append(testCases, tc)
			}
		}
	}

	return testCases
}

// translateDataAccessRule translates data access rules
func (rt *RuleTranslator) translateDataAccessRule(rule BusinessRule, endpoints []types.Endpoint) []RuleTestCase {
	var testCases []RuleTestCase

	descLower := strings.ToLower(rule.Description)

	// Check for data exposure patterns
	if strings.Contains(descLower, "should not") || strings.Contains(descLower, "never") {
		sensitiveFields := extractSensitiveFields(descLower)

		for _, ep := range endpoints {
			if ep.Method == "GET" {
				tc := RuleTestCase{
					RuleID:      rule.ID,
					Description: "Verify data access restriction: " + rule.Description,
					ActionStep: TestStep{
						Name:     "Fetch data",
						Method:   ep.Method,
						Endpoint: ep.Path,
						Actor:    "regular_user",
					},
					ExpectedResult: ExpectedResult{
						Success:        true,
						StatusCodes:    []int{200},
						MustNotContain: sensitiveFields,
					},
					Tags: []string{"data_access", "sensitive_data"},
				}
				testCases = append(testCases, tc)
			}
		}
	}

	return testCases
}

// translateWorkflowRule translates workflow rules
func (rt *RuleTranslator) translateWorkflowRule(rule BusinessRule, endpoints []types.Endpoint) []RuleTestCase {
	var testCases []RuleTestCase

	descLower := strings.ToLower(rule.Description)

	// Check for sequence patterns
	if strings.Contains(descLower, "before") || strings.Contains(descLower, "after") {
		// Try to identify the workflow steps
		// This is simplified - real implementation would parse more carefully

		tc := RuleTestCase{
			RuleID:      rule.ID,
			Description: "Verify workflow: " + rule.Description,
			SetupSteps:  []TestStep{},
			ActionStep: TestStep{
				Name:  "Execute action out of sequence",
				Actor: "regular_user",
			},
			ExpectedResult: ExpectedResult{
				Success:     false,
				StatusCodes: []int{400, 403},
			},
			Tags: []string{"workflow", "sequence"},
		}
		testCases = append(testCases, tc)
	}

	return testCases
}

// translateGenericRule translates rules without specific category handling
func (rt *RuleTranslator) translateGenericRule(rule BusinessRule, endpoints []types.Endpoint) []RuleTestCase {
	var testCases []RuleTestCase

	for _, ep := range endpoints {
		tc := RuleTestCase{
			RuleID:      rule.ID,
			Description: "Verify rule: " + rule.Description,
			ActionStep: TestStep{
				Name:     "Test rule compliance",
				Method:   ep.Method,
				Endpoint: ep.Path,
				Actor:    "test_user",
			},
			ExpectedResult: ExpectedResult{
				Success: true,
			},
			Tags: []string{"general"},
		}
		testCases = append(testCases, tc)
	}

	return testCases
}

// Helper functions

func hasIDParam(ep types.Endpoint) bool {
	for _, p := range ep.Parameters {
		nameLower := strings.ToLower(p.Name)
		if strings.Contains(nameLower, "id") || strings.Contains(nameLower, "uuid") {
			return true
		}
	}

	// Check path for ID patterns
	return strings.Contains(ep.Path, "{id}") ||
		strings.Contains(ep.Path, "{uuid}") ||
		strings.Contains(ep.Path, "/{")
}

func extractSensitiveFields(text string) []string {
	sensitive := []string{
		"password", "hash", "secret", "token",
		"ssn", "social_security", "credit_card",
		"private_key", "api_key",
	}

	var found []string
	for _, s := range sensitive {
		if strings.Contains(text, s) || strings.Contains(text, strings.ReplaceAll(s, "_", " ")) {
			found = append(found, s)
		}
	}

	// If none found explicitly, return common sensitive fields
	if len(found) == 0 {
		return []string{"password", "token", "secret"}
	}

	return found
}
