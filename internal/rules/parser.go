// Package rules provides natural language business rule processing
package rules

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// BusinessRule represents a natural language business rule
type BusinessRule struct {
	ID          string   `yaml:"id" json:"id"`
	Description string   `yaml:"description" json:"description"`
	Category    string   `yaml:"category" json:"category"` // authorization, data_access, workflow, validation
	Priority    string   `yaml:"priority" json:"priority"` // critical, high, medium, low
	Scope       []string `yaml:"scope" json:"scope"`       // Endpoint patterns this rule applies to
	Actor       string   `yaml:"actor" json:"actor"`       // Who is performing the action
	Action      string   `yaml:"action" json:"action"`     // What action is being performed
	Resource    string   `yaml:"resource" json:"resource"` // What resource is being accessed
	Constraint  string   `yaml:"constraint" json:"constraint"` // Natural language constraint
	Tags        []string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// RuleSet represents a collection of business rules
type RuleSet struct {
	Name        string         `yaml:"name" json:"name"`
	Description string         `yaml:"description" json:"description"`
	Version     string         `yaml:"version" json:"version"`
	Rules       []BusinessRule `yaml:"rules" json:"rules"`
}

// RuleTestCase represents a test case generated from a rule
type RuleTestCase struct {
	RuleID         string          `json:"rule_id"`
	Description    string          `json:"description"`
	SetupSteps     []TestStep      `json:"setup_steps"`
	ActionStep     TestStep        `json:"action_step"`
	ExpectedResult ExpectedResult  `json:"expected_result"`
	Actors         []TestActor     `json:"actors"`
	Tags           []string        `json:"tags"`
}

// TestStep represents a step in a test case
type TestStep struct {
	Name        string            `json:"name"`
	Method      string            `json:"method"`
	Endpoint    string            `json:"endpoint"`
	Actor       string            `json:"actor"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        map[string]interface{} `json:"body,omitempty"`
	QueryParams map[string]string `json:"query_params,omitempty"`
	Extract     []Extraction      `json:"extract,omitempty"`
}

// Extraction defines what to extract from a response
type Extraction struct {
	Name     string `json:"name"`
	From     string `json:"from"` // body, header, cookie
	Path     string `json:"path"`
	SaveAs   string `json:"save_as"`
}

// ExpectedResult defines expected test outcomes
type ExpectedResult struct {
	Success        bool     `json:"success"`
	StatusCode     int      `json:"status_code,omitempty"`
	StatusCodes    []int    `json:"status_codes,omitempty"` // Multiple acceptable codes
	ContainsData   bool     `json:"contains_data,omitempty"`
	ErrorMessage   string   `json:"error_message,omitempty"`
	MustNotContain []string `json:"must_not_contain,omitempty"`
	MustContain    []string `json:"must_contain,omitempty"`
}

// TestActor represents an actor in the test
type TestActor struct {
	Name     string `json:"name"`
	Role     string `json:"role"`
	AuthType string `json:"auth_type"`
	Token    string `json:"token,omitempty"`
}

// RuleParser parses business rules from YAML
type RuleParser struct{}

// NewRuleParser creates a new rule parser
func NewRuleParser() *RuleParser {
	return &RuleParser{}
}

// ParseFile parses rules from a YAML file
func (p *RuleParser) ParseFile(filePath string) (*RuleSet, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}

	return p.Parse(data)
}

// Parse parses rules from YAML data
func (p *RuleParser) Parse(data []byte) (*RuleSet, error) {
	var ruleSet RuleSet
	if err := yaml.Unmarshal(data, &ruleSet); err != nil {
		return nil, fmt.Errorf("failed to parse rules YAML: %w", err)
	}

	// Validate and set defaults
	for i := range ruleSet.Rules {
		if err := p.validateRule(&ruleSet.Rules[i]); err != nil {
			return nil, fmt.Errorf("invalid rule %s: %w", ruleSet.Rules[i].ID, err)
		}
		p.setDefaults(&ruleSet.Rules[i])
	}

	return &ruleSet, nil
}

// validateRule validates a business rule
func (p *RuleParser) validateRule(rule *BusinessRule) error {
	if rule.Description == "" {
		return fmt.Errorf("rule description is required")
	}
	return nil
}

// setDefaults sets default values for a rule
func (p *RuleParser) setDefaults(rule *BusinessRule) {
	if rule.ID == "" {
		rule.ID = generateRuleID(rule.Description)
	}
	if rule.Category == "" {
		rule.Category = inferCategory(rule.Description)
	}
	if rule.Priority == "" {
		rule.Priority = "medium"
	}
}

// generateRuleID generates an ID from the description
func generateRuleID(description string) string {
	// Lowercase, replace spaces with hyphens, remove special chars
	id := strings.ToLower(description)
	id = strings.ReplaceAll(id, " ", "-")
	id = regexp.MustCompile(`[^a-z0-9-]`).ReplaceAllString(id, "")

	if len(id) > 50 {
		id = id[:50]
	}

	return id
}

// inferCategory infers the rule category from description
func inferCategory(description string) string {
	descLower := strings.ToLower(description)

	authKeywords := []string{"access", "permission", "role", "admin", "user", "authorize", "authenticate"}
	dataKeywords := []string{"data", "view", "read", "see", "expose", "leak", "sensitive"}
	workflowKeywords := []string{"before", "after", "must", "should", "cannot", "only"}
	validationKeywords := []string{"valid", "format", "required", "must be", "cannot be"}

	for _, kw := range authKeywords {
		if strings.Contains(descLower, kw) {
			return "authorization"
		}
	}

	for _, kw := range dataKeywords {
		if strings.Contains(descLower, kw) {
			return "data_access"
		}
	}

	for _, kw := range workflowKeywords {
		if strings.Contains(descLower, kw) {
			return "workflow"
		}
	}

	for _, kw := range validationKeywords {
		if strings.Contains(descLower, kw) {
			return "validation"
		}
	}

	return "general"
}

// MatchesEndpoint checks if a rule applies to an endpoint
func (rule *BusinessRule) MatchesEndpoint(method, path string) bool {
	if len(rule.Scope) == 0 {
		return true // No scope means applies to all
	}

	for _, pattern := range rule.Scope {
		// Simple pattern matching
		// Supports: /users/*, /orders/**, /api/v1/*
		if matchPattern(pattern, path) {
			return true
		}

		// Also match method:path format
		if strings.Contains(pattern, ":") {
			parts := strings.SplitN(pattern, ":", 2)
			if len(parts) == 2 {
				if parts[0] == method && matchPattern(parts[1], path) {
					return true
				}
			}
		}
	}

	return false
}

// matchPattern performs simple glob-like pattern matching
func matchPattern(pattern, path string) bool {
	// Normalize paths
	pattern = strings.TrimSuffix(pattern, "/")
	path = strings.TrimSuffix(path, "/")

	// Direct match
	if pattern == path {
		return true
	}

	// ** matches anything
	if pattern == "**" {
		return true
	}

	// Convert glob pattern to regex
	regexPattern := "^"
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				regexPattern += ".*"
				i++ // Skip next *
			} else {
				regexPattern += "[^/]*"
			}
		case '?':
			regexPattern += "."
		case '.', '\\', '+', '^', '$', '|', '(', ')', '[', ']', '{', '}':
			regexPattern += "\\" + string(pattern[i])
		default:
			regexPattern += string(pattern[i])
		}
	}
	regexPattern += "$"

	matched, _ := regexp.MatchString(regexPattern, path)
	return matched
}

// GetRulesByCategory returns rules filtered by category
func (rs *RuleSet) GetRulesByCategory(category string) []BusinessRule {
	var rules []BusinessRule
	for _, rule := range rs.Rules {
		if rule.Category == category {
			rules = append(rules, rule)
		}
	}
	return rules
}

// GetRulesByPriority returns rules filtered by priority
func (rs *RuleSet) GetRulesByPriority(priority string) []BusinessRule {
	var rules []BusinessRule
	for _, rule := range rs.Rules {
		if rule.Priority == priority {
			rules = append(rules, rule)
		}
	}
	return rules
}

// GetRulesForEndpoint returns rules that apply to an endpoint
func (rs *RuleSet) GetRulesForEndpoint(method, path string) []BusinessRule {
	var rules []BusinessRule
	for _, rule := range rs.Rules {
		if rule.MatchesEndpoint(method, path) {
			rules = append(rules, rule)
		}
	}
	return rules
}
