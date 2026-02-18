package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

// --- Sample YAML for tests ---

const validRuleSetYAML = `
name: "Test API Rules"
description: "Business rules for testing"
version: "1.0"
rules:
  - id: "rule-user-access"
    description: "Users should not access other user profiles"
    category: "authorization"
    priority: "high"
    scope:
      - "/users/*"
      - "GET:/users/*/profile"
    actor: "regular_user"
    action: "read"
    resource: "user profile"
    constraint: "Users can only access their own profile"
    tags:
      - "idor"
      - "horizontal-access"
  - id: "rule-admin-only"
    description: "Admin endpoints require admin role"
    category: "authorization"
    priority: "critical"
    scope:
      - "/admin/**"
    actor: "admin"
    action: "manage"
    resource: "admin panel"
    constraint: "Only admin users can access admin endpoints"
  - id: "rule-no-password-leak"
    description: "API should never expose password hashes in responses"
    category: "data_access"
    priority: "high"
    scope:
      - "/users/*"
      - "/accounts/*"
    actor: "any"
    action: "read"
    resource: "user data"
    constraint: "Password fields must be omitted from API responses"
  - id: "rule-checkout-workflow"
    description: "Users must add items to cart before checkout"
    category: "workflow"
    priority: "medium"
    scope:
      - "/orders/*"
      - "/checkout"
    actor: "customer"
    action: "checkout"
    resource: "order"
    constraint: "Cannot checkout without items in cart"
  - id: "rule-low-priority"
    description: "Rate limiting on public endpoints"
    category: "validation"
    priority: "low"
    scope:
      - "/public/**"
`

const minimalRuleSetYAML = `
name: "Minimal"
description: "Minimal ruleset"
version: "0.1"
rules:
  - description: "Only admin can delete users"
`

// --- NewRuleParser ---

func TestNewRuleParser(t *testing.T) {
	p := NewRuleParser()
	if p == nil {
		t.Fatal("NewRuleParser returned nil")
	}
}

// --- Parse ---

func TestParseValidRuleSet(t *testing.T) {
	p := NewRuleParser()
	rs, err := p.Parse([]byte(validRuleSetYAML))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if rs.Name != "Test API Rules" {
		t.Errorf("expected name 'Test API Rules', got %q", rs.Name)
	}
	if rs.Description != "Business rules for testing" {
		t.Errorf("expected description 'Business rules for testing', got %q", rs.Description)
	}
	if rs.Version != "1.0" {
		t.Errorf("expected version '1.0', got %q", rs.Version)
	}
	if len(rs.Rules) != 5 {
		t.Fatalf("expected 5 rules, got %d", len(rs.Rules))
	}

	// Verify first rule fields
	r := rs.Rules[0]
	if r.ID != "rule-user-access" {
		t.Errorf("rule[0].ID = %q, want 'rule-user-access'", r.ID)
	}
	if r.Description != "Users should not access other user profiles" {
		t.Errorf("rule[0].Description = %q", r.Description)
	}
	if r.Category != "authorization" {
		t.Errorf("rule[0].Category = %q, want 'authorization'", r.Category)
	}
	if r.Priority != "high" {
		t.Errorf("rule[0].Priority = %q, want 'high'", r.Priority)
	}
	if len(r.Scope) != 2 {
		t.Errorf("rule[0].Scope len = %d, want 2", len(r.Scope))
	}
	if r.Actor != "regular_user" {
		t.Errorf("rule[0].Actor = %q, want 'regular_user'", r.Actor)
	}
	if r.Action != "read" {
		t.Errorf("rule[0].Action = %q, want 'read'", r.Action)
	}
	if r.Resource != "user profile" {
		t.Errorf("rule[0].Resource = %q, want 'user profile'", r.Resource)
	}
	if r.Constraint != "Users can only access their own profile" {
		t.Errorf("rule[0].Constraint = %q", r.Constraint)
	}
	if len(r.Tags) != 2 || r.Tags[0] != "idor" {
		t.Errorf("rule[0].Tags = %v, want [idor horizontal-access]", r.Tags)
	}
}

func TestParseInvalidYAML(t *testing.T) {
	p := NewRuleParser()
	_, err := p.Parse([]byte("{{{{not valid yaml"))
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestParseEmptyRules(t *testing.T) {
	p := NewRuleParser()
	rs, err := p.Parse([]byte(`name: "empty"
description: "no rules"
version: "0"
rules: []
`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rs.Rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rs.Rules))
	}
}

func TestParseMissingDescription(t *testing.T) {
	p := NewRuleParser()
	_, err := p.Parse([]byte(`
name: "bad"
rules:
  - id: "no-desc"
    category: "authorization"
`))
	if err == nil {
		t.Fatal("expected error for rule without description")
	}
}

// --- ParseFile ---

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(fp, []byte(validRuleSetYAML), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	p := NewRuleParser()
	rs, err := p.ParseFile(fp)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	if rs.Name != "Test API Rules" {
		t.Errorf("expected name 'Test API Rules', got %q", rs.Name)
	}
	if len(rs.Rules) != 5 {
		t.Errorf("expected 5 rules, got %d", len(rs.Rules))
	}
}

func TestParseFileNotFound(t *testing.T) {
	p := NewRuleParser()
	_, err := p.ParseFile("/nonexistent/path/rules.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

// --- validateRule ---

func TestValidateRuleWithDescription(t *testing.T) {
	p := NewRuleParser()
	rule := &BusinessRule{Description: "a valid rule"}
	if err := p.validateRule(rule); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestValidateRuleWithoutDescription(t *testing.T) {
	p := NewRuleParser()
	rule := &BusinessRule{ID: "no-desc"}
	if err := p.validateRule(rule); err == nil {
		t.Fatal("expected error for missing description")
	}
}

// --- setDefaults ---

func TestSetDefaultsGeneratesID(t *testing.T) {
	p := NewRuleParser()
	rule := &BusinessRule{Description: "Admin access only"}
	p.setDefaults(rule)

	if rule.ID == "" {
		t.Fatal("expected ID to be generated")
	}
	if rule.ID != "admin-access-only" {
		t.Errorf("generated ID = %q, want 'admin-access-only'", rule.ID)
	}
}

func TestSetDefaultsPreservesExistingID(t *testing.T) {
	p := NewRuleParser()
	rule := &BusinessRule{ID: "my-custom-id", Description: "Something"}
	p.setDefaults(rule)

	if rule.ID != "my-custom-id" {
		t.Errorf("ID should be preserved, got %q", rule.ID)
	}
}

func TestSetDefaultsInfersCategory(t *testing.T) {
	tests := []struct {
		desc     string
		expected string
	}{
		{"Only admin users can access this", "authorization"},
		{"Sensitive data should not leak", "data_access"},
		{"Payment happens before shipping", "workflow"},
		{"Email format is valid and required", "validation"},
		{"Some random rule about foobar", "general"},
	}

	p := NewRuleParser()
	for _, tt := range tests {
		rule := &BusinessRule{Description: tt.desc}
		p.setDefaults(rule)
		if rule.Category != tt.expected {
			t.Errorf("description %q: category = %q, want %q", tt.desc, rule.Category, tt.expected)
		}
	}
}

func TestSetDefaultsPreservesExistingCategory(t *testing.T) {
	p := NewRuleParser()
	rule := &BusinessRule{Description: "Something with admin keyword", Category: "custom_cat"}
	p.setDefaults(rule)

	if rule.Category != "custom_cat" {
		t.Errorf("category should be preserved, got %q", rule.Category)
	}
}

func TestSetDefaultsPriorityMedium(t *testing.T) {
	p := NewRuleParser()
	rule := &BusinessRule{Description: "test"}
	p.setDefaults(rule)

	if rule.Priority != "medium" {
		t.Errorf("expected default priority 'medium', got %q", rule.Priority)
	}
}

func TestSetDefaultsPreservesExistingPriority(t *testing.T) {
	p := NewRuleParser()
	rule := &BusinessRule{Description: "test", Priority: "critical"}
	p.setDefaults(rule)

	if rule.Priority != "critical" {
		t.Errorf("priority should be preserved, got %q", rule.Priority)
	}
}

func TestParseMinimalRuleSetsDefaults(t *testing.T) {
	p := NewRuleParser()
	rs, err := p.Parse([]byte(minimalRuleSetYAML))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rs.Rules))
	}

	r := rs.Rules[0]
	if r.ID == "" {
		t.Error("expected ID to be generated")
	}
	// "Only admin can delete users" contains "admin" -> authorization
	if r.Category != "authorization" {
		t.Errorf("expected inferred category 'authorization', got %q", r.Category)
	}
	if r.Priority != "medium" {
		t.Errorf("expected default priority 'medium', got %q", r.Priority)
	}
}

// --- BusinessRule.MatchesEndpoint ---

func TestMatchesEndpointNoScope(t *testing.T) {
	rule := BusinessRule{Description: "test"}
	// Empty scope matches everything
	if !rule.MatchesEndpoint("GET", "/anything") {
		t.Error("empty scope should match any endpoint")
	}
}

func TestMatchesEndpointExactPath(t *testing.T) {
	rule := BusinessRule{
		Description: "test",
		Scope:       []string{"/users/list"},
	}
	if !rule.MatchesEndpoint("GET", "/users/list") {
		t.Error("expected exact path match")
	}
	if rule.MatchesEndpoint("GET", "/users/other") {
		t.Error("should not match different path")
	}
}

func TestMatchesEndpointWildcard(t *testing.T) {
	rule := BusinessRule{
		Description: "test",
		Scope:       []string{"/users/*"},
	}
	if !rule.MatchesEndpoint("GET", "/users/123") {
		t.Error("wildcard * should match single segment")
	}
	if rule.MatchesEndpoint("GET", "/users/123/profile") {
		t.Error("single * should not match multiple segments")
	}
}

func TestMatchesEndpointDoubleWildcard(t *testing.T) {
	rule := BusinessRule{
		Description: "test",
		Scope:       []string{"/admin/**"},
	}
	if !rule.MatchesEndpoint("GET", "/admin/users/list") {
		t.Error("** should match multiple segments")
	}
	if !rule.MatchesEndpoint("POST", "/admin/settings") {
		t.Error("** should match any sub-path")
	}
}

func TestMatchesEndpointMethodPath(t *testing.T) {
	rule := BusinessRule{
		Description: "test",
		Scope:       []string{"GET:/users/*/profile"},
	}
	if !rule.MatchesEndpoint("GET", "/users/123/profile") {
		t.Error("expected method:path match")
	}
	if rule.MatchesEndpoint("POST", "/users/123/profile") {
		t.Error("should not match wrong method")
	}
}

func TestMatchesEndpointMultipleScopes(t *testing.T) {
	rule := BusinessRule{
		Description: "test",
		Scope:       []string{"/users/*", "/accounts/*"},
	}
	if !rule.MatchesEndpoint("GET", "/users/123") {
		t.Error("should match first scope")
	}
	if !rule.MatchesEndpoint("GET", "/accounts/456") {
		t.Error("should match second scope")
	}
	if rule.MatchesEndpoint("GET", "/orders/789") {
		t.Error("should not match unrelated path")
	}
}

func TestMatchesEndpointTrailingSlash(t *testing.T) {
	rule := BusinessRule{
		Description: "test",
		Scope:       []string{"/users/list"},
	}
	// Trailing slash normalization
	if !rule.MatchesEndpoint("GET", "/users/list/") {
		t.Error("trailing slash should be normalized for match")
	}
}

// --- matchPattern ---

func TestMatchPatternExact(t *testing.T) {
	if !matchPattern("/users", "/users") {
		t.Error("exact match should succeed")
	}
	if matchPattern("/users", "/orders") {
		t.Error("different paths should not match")
	}
}

func TestMatchPatternSingleWildcard(t *testing.T) {
	if !matchPattern("/users/*", "/users/123") {
		t.Error("* should match single segment")
	}
	if matchPattern("/users/*", "/users/123/profile") {
		t.Error("* should not match across /")
	}
}

func TestMatchPatternDoubleWildcard(t *testing.T) {
	if !matchPattern("/api/**", "/api/v1/users/list") {
		t.Error("** should match multiple segments")
	}
	if !matchPattern("**", "/anything/at/all") {
		t.Error("standalone ** should match everything")
	}
}

func TestMatchPatternPathParam(t *testing.T) {
	// {id} is treated as literal with braces escaped to regex
	// In the regex, { becomes \{ which matches literal {
	// So /users/{id} matches /users/{id} literally
	if !matchPattern("/users/{id}", "/users/{id}") {
		t.Error("literal path param pattern should match itself")
	}
}

func TestMatchPatternQuestionMark(t *testing.T) {
	if !matchPattern("/api/v?/users", "/api/v1/users") {
		t.Error("? should match single character")
	}
	if !matchPattern("/api/v?/users", "/api/v2/users") {
		t.Error("? should match any single character")
	}
}

// --- RuleSet.GetRulesByCategory ---

func TestGetRulesByCategory(t *testing.T) {
	p := NewRuleParser()
	rs, err := p.Parse([]byte(validRuleSetYAML))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	authRules := rs.GetRulesByCategory("authorization")
	if len(authRules) != 2 {
		t.Errorf("expected 2 authorization rules, got %d", len(authRules))
	}

	dataRules := rs.GetRulesByCategory("data_access")
	if len(dataRules) != 1 {
		t.Errorf("expected 1 data_access rule, got %d", len(dataRules))
	}

	workflowRules := rs.GetRulesByCategory("workflow")
	if len(workflowRules) != 1 {
		t.Errorf("expected 1 workflow rule, got %d", len(workflowRules))
	}

	noneRules := rs.GetRulesByCategory("nonexistent")
	if len(noneRules) != 0 {
		t.Errorf("expected 0 rules for nonexistent category, got %d", len(noneRules))
	}
}

// --- RuleSet.GetRulesByPriority ---

func TestGetRulesByPriority(t *testing.T) {
	p := NewRuleParser()
	rs, err := p.Parse([]byte(validRuleSetYAML))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	highRules := rs.GetRulesByPriority("high")
	if len(highRules) != 2 {
		t.Errorf("expected 2 high-priority rules, got %d", len(highRules))
	}

	criticalRules := rs.GetRulesByPriority("critical")
	if len(criticalRules) != 1 {
		t.Errorf("expected 1 critical rule, got %d", len(criticalRules))
	}

	mediumRules := rs.GetRulesByPriority("medium")
	if len(mediumRules) != 1 {
		t.Errorf("expected 1 medium rule, got %d", len(mediumRules))
	}

	lowRules := rs.GetRulesByPriority("low")
	if len(lowRules) != 1 {
		t.Errorf("expected 1 low rule, got %d", len(lowRules))
	}

	noneRules := rs.GetRulesByPriority("nonexistent")
	if len(noneRules) != 0 {
		t.Errorf("expected 0 rules for nonexistent priority, got %d", len(noneRules))
	}
}

// --- RuleSet.GetRulesForEndpoint ---

func TestGetRulesForEndpoint(t *testing.T) {
	p := NewRuleParser()
	rs, err := p.Parse([]byte(validRuleSetYAML))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// /users/123 matches rules scoped to /users/*
	rules := rs.GetRulesForEndpoint("GET", "/users/123")
	if len(rules) < 2 {
		t.Errorf("expected at least 2 rules for /users/123, got %d", len(rules))
	}

	// /admin/settings matches rule scoped to /admin/**
	adminRules := rs.GetRulesForEndpoint("GET", "/admin/settings")
	found := false
	for _, r := range adminRules {
		if r.ID == "rule-admin-only" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected rule-admin-only to match /admin/settings")
	}

	// /public/docs should match the low-priority rule scoped to /public/**
	publicRules := rs.GetRulesForEndpoint("GET", "/public/docs")
	found = false
	for _, r := range publicRules {
		if r.ID == "rule-low-priority" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected rule-low-priority to match /public/docs")
	}
}

// --- NewRuleTranslator ---

func TestNewRuleTranslator(t *testing.T) {
	rt := NewRuleTranslator(nil)
	if rt == nil {
		t.Fatal("NewRuleTranslator returned nil")
	}
	if rt.provider != nil {
		t.Error("expected nil provider")
	}
}

// --- translateHeuristic ---

func TestTranslateHeuristicAuthorization(t *testing.T) {
	rt := NewRuleTranslator(nil)

	rule := BusinessRule{
		ID:          "test-auth",
		Description: "Users should not access other user profiles",
		Category:    "authorization",
		Priority:    "high",
	}

	endpoints := []types.Endpoint{
		{
			Method: "GET",
			Path:   "/users/{id}/profile",
			Parameters: []types.Parameter{
				{Name: "id", In: "path", Type: "string"},
			},
		},
	}

	cases := rt.translateHeuristic(rule, endpoints)
	if len(cases) == 0 {
		t.Fatal("expected at least one test case for authorization rule with ID param")
	}

	tc := cases[0]
	if tc.RuleID != "test-auth" {
		t.Errorf("RuleID = %q, want 'test-auth'", tc.RuleID)
	}
	if tc.ExpectedResult.Success != false {
		t.Error("expected Success = false for authorization violation test")
	}
	if len(tc.ExpectedResult.StatusCodes) == 0 {
		t.Error("expected status codes to be set")
	}
	if len(tc.Actors) == 0 {
		t.Error("expected actors to be defined")
	}
}

func TestTranslateHeuristicAuthorizationAdmin(t *testing.T) {
	rt := NewRuleTranslator(nil)

	rule := BusinessRule{
		ID:          "test-admin",
		Description: "Only admin can access admin panel",
		Category:    "authorization",
		Priority:    "critical",
	}

	endpoints := []types.Endpoint{
		{Method: "GET", Path: "/admin/dashboard"},
		{Method: "GET", Path: "/users/list"},
	}

	cases := rt.translateHeuristic(rule, endpoints)
	if len(cases) == 0 {
		t.Fatal("expected test cases for admin authorization rule")
	}

	// Should only generate for the admin endpoint
	for _, tc := range cases {
		if tc.ActionStep.Endpoint != "/admin/dashboard" {
			t.Errorf("expected admin endpoint, got %q", tc.ActionStep.Endpoint)
		}
	}
}

func TestTranslateHeuristicDataAccess(t *testing.T) {
	rt := NewRuleTranslator(nil)

	rule := BusinessRule{
		ID:          "test-data",
		Description: "API should never expose password hashes",
		Category:    "data_access",
		Priority:    "high",
	}

	endpoints := []types.Endpoint{
		{Method: "GET", Path: "/users/me"},
		{Method: "POST", Path: "/users"},
	}

	cases := rt.translateHeuristic(rule, endpoints)
	if len(cases) == 0 {
		t.Fatal("expected test cases for data_access rule")
	}

	// Should generate test for GET endpoint only
	for _, tc := range cases {
		if tc.ActionStep.Method != "GET" {
			t.Errorf("data access checks should target GET, got %q", tc.ActionStep.Method)
		}
	}

	// Should include password in MustNotContain
	tc := cases[0]
	if len(tc.ExpectedResult.MustNotContain) == 0 {
		t.Error("expected MustNotContain to be populated")
	}
	foundPassword := false
	for _, f := range tc.ExpectedResult.MustNotContain {
		if f == "password" {
			foundPassword = true
		}
	}
	if !foundPassword {
		t.Error("expected 'password' in MustNotContain")
	}
}

func TestTranslateHeuristicWorkflow(t *testing.T) {
	rt := NewRuleTranslator(nil)

	rule := BusinessRule{
		ID:          "test-workflow",
		Description: "Users must add items before checkout",
		Category:    "workflow",
		Priority:    "medium",
	}

	endpoints := []types.Endpoint{
		{Method: "POST", Path: "/checkout"},
	}

	cases := rt.translateHeuristic(rule, endpoints)
	if len(cases) == 0 {
		t.Fatal("expected test cases for workflow rule")
	}

	tc := cases[0]
	if tc.ExpectedResult.Success != false {
		t.Error("expected Success = false for out-of-sequence workflow test")
	}
}

func TestTranslateHeuristicGeneric(t *testing.T) {
	rt := NewRuleTranslator(nil)

	rule := BusinessRule{
		ID:          "test-generic",
		Description: "Some generic foobar rule",
		Category:    "general",
		Priority:    "low",
	}

	endpoints := []types.Endpoint{
		{Method: "GET", Path: "/foo"},
		{Method: "POST", Path: "/bar"},
	}

	cases := rt.translateHeuristic(rule, endpoints)
	if len(cases) != 2 {
		t.Errorf("expected 2 generic test cases (one per endpoint), got %d", len(cases))
	}

	for _, tc := range cases {
		if tc.RuleID != "test-generic" {
			t.Errorf("RuleID = %q, want 'test-generic'", tc.RuleID)
		}
	}
}

func TestTranslateHeuristicNoEndpoints(t *testing.T) {
	rt := NewRuleTranslator(nil)

	rule := BusinessRule{
		ID:          "test-empty",
		Description: "Rule with no matching endpoints",
		Category:    "authorization",
		Priority:    "low",
	}

	cases := rt.translateHeuristic(rule, nil)
	// With no endpoints, no test cases should be generated
	if len(cases) != 0 {
		t.Errorf("expected 0 test cases with no endpoints, got %d", len(cases))
	}
}

// --- generateRuleID ---

func TestGenerateRuleID(t *testing.T) {
	tests := []struct {
		desc string
		want string
	}{
		{"Admin Access Only", "admin-access-only"},
		{"No special chars!@#$", "no-special-chars"},
		{"lowercase already", "lowercase-already"},
	}

	for _, tt := range tests {
		got := generateRuleID(tt.desc)
		if got != tt.want {
			t.Errorf("generateRuleID(%q) = %q, want %q", tt.desc, got, tt.want)
		}
	}
}

func TestGenerateRuleIDTruncation(t *testing.T) {
	longDesc := "This is a very long rule description that should be truncated to fifty characters maximum for the ID"
	id := generateRuleID(longDesc)
	if len(id) > 50 {
		t.Errorf("expected ID length <= 50, got %d", len(id))
	}
}

// --- inferCategory ---

func TestInferCategory(t *testing.T) {
	tests := []struct {
		desc     string
		expected string
	}{
		{"Only authorized users can access", "authorization"},
		{"Permission to edit", "authorization"},
		{"Users with admin role", "authorization"},
		{"Sensitive data should not leak", "data_access"},
		{"Expose private records", "data_access"},
		{"Complete step before next", "workflow"},
		{"Only after payment", "workflow"},
		{"Input is valid and required", "validation"},
		{"Format required for dates", "validation"},
		{"Random unrelated rule", "general"},
	}

	for _, tt := range tests {
		got := inferCategory(tt.desc)
		if got != tt.expected {
			t.Errorf("inferCategory(%q) = %q, want %q", tt.desc, got, tt.expected)
		}
	}
}

// --- extractSensitiveFields ---

func TestExtractSensitiveFields(t *testing.T) {
	found := extractSensitiveFields("should not expose password or api key")
	has := func(s string) bool {
		for _, f := range found {
			if f == s {
				return true
			}
		}
		return false
	}
	if !has("password") {
		t.Error("expected 'password' in sensitive fields")
	}
	if !has("api_key") {
		t.Error("expected 'api_key' in sensitive fields")
	}
}

func TestExtractSensitiveFieldsDefault(t *testing.T) {
	// When no specific fields are mentioned, returns defaults
	found := extractSensitiveFields("should not expose anything")
	if len(found) != 3 {
		t.Errorf("expected 3 default sensitive fields, got %d: %v", len(found), found)
	}
}

// --- hasIDParam ---

func TestHasIDParam(t *testing.T) {
	tests := []struct {
		name   string
		ep     types.Endpoint
		expect bool
	}{
		{
			name: "param named id",
			ep: types.Endpoint{
				Path:       "/users/123",
				Parameters: []types.Parameter{{Name: "user_id"}},
			},
			expect: true,
		},
		{
			name: "param named uuid",
			ep: types.Endpoint{
				Path:       "/items/abc",
				Parameters: []types.Parameter{{Name: "uuid"}},
			},
			expect: true,
		},
		{
			name: "path contains {id}",
			ep: types.Endpoint{
				Path: "/users/{id}",
			},
			expect: true,
		},
		{
			name: "path contains {uuid}",
			ep: types.Endpoint{
				Path: "/users/{uuid}",
			},
			expect: true,
		},
		{
			name: "path contains generic param",
			ep: types.Endpoint{
				Path: "/users/{user_id}/profile",
			},
			expect: true,
		},
		{
			name: "no id param",
			ep: types.Endpoint{
				Path:       "/status",
				Parameters: []types.Parameter{{Name: "format"}},
			},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasIDParam(tt.ep)
			if got != tt.expect {
				t.Errorf("hasIDParam() = %v, want %v", got, tt.expect)
			}
		})
	}
}
