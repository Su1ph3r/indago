package payloads

import (
	"context"
	"testing"

	"github.com/su1ph3r/indago/internal/llm"
	"github.com/su1ph3r/indago/pkg/types"
)

func TestNewGenerator(t *testing.T) {
	config := types.AttackSettings{
		IDOR:      types.IDORSettings{IDRange: 5},
		Injection: types.InjectionSettings{SQLi: true},
	}

	g := NewGenerator(nil, config, "")

	if g == nil {
		t.Fatal("NewGenerator returned nil")
	}

	// Check that generators are registered
	expectedTypes := []string{
		types.AttackIDOR,
		types.AttackSQLi,
		types.AttackNoSQLi,
		types.AttackCommandInject,
		types.AttackXSS,
	}

	for _, attackType := range expectedTypes {
		if _, ok := g.generators[attackType]; !ok {
			t.Errorf("generator for %s not registered", attackType)
		}
	}
}

func TestGenerator_GenerateForEndpoint(t *testing.T) {
	config := types.AttackSettings{
		IDOR:               types.IDORSettings{IDRange: 3},
		Injection:          types.InjectionSettings{SQLi: true},
		MaxPayloadsPerType: 100,
	}

	g := NewGenerator(nil, config, "")

	endpoint := types.Endpoint{
		Method:  "GET",
		Path:    "/users/{userId}",
		BaseURL: "https://api.example.com",
		Parameters: []types.Parameter{
			{
				Name:    "userId",
				In:      "path",
				Type:    "integer",
				Example: 123,
			},
			{
				Name:    "search",
				In:      "query",
				Type:    "string",
				Example: "test",
			},
		},
	}

	ctx := context.Background()
	requests := g.GenerateForEndpoint(ctx, endpoint)

	if len(requests) == 0 {
		t.Error("expected fuzz requests, got none")
	}

	// Verify request structure
	payloadsWithValues := 0
	for _, req := range requests {
		if req.Endpoint.Path != endpoint.Path {
			t.Errorf("request endpoint path = %s, expected %s", req.Endpoint.Path, endpoint.Path)
		}
		if req.Payload.Value != "" {
			payloadsWithValues++
		}
		if req.Payload.Type == "" {
			t.Error("request payload type is empty")
		}
	}

	// Most payloads should have values
	if payloadsWithValues == 0 {
		t.Error("expected at least some payloads with values")
	}
}

func TestGenerator_GenerateForEndpointWithBody(t *testing.T) {
	config := types.AttackSettings{
		IDOR:               types.IDORSettings{IDRange: 3},
		MaxPayloadsPerType: 100,
	}

	g := NewGenerator(nil, config, "")

	endpoint := types.Endpoint{
		Method:  "POST",
		Path:    "/users",
		BaseURL: "https://api.example.com",
		Body: &types.RequestBody{
			ContentType: "application/json",
			Fields: []types.BodyField{
				{Name: "user_id", Type: "integer", Required: true},
				{Name: "name", Type: "string", Required: true},
			},
		},
	}

	ctx := context.Background()
	requests := g.GenerateForEndpoint(ctx, endpoint)

	if len(requests) == 0 {
		t.Error("expected fuzz requests for body fields, got none")
	}

	// Check that body fields were targeted
	bodyFieldTargeted := false
	for _, req := range requests {
		if req.Position == "body" {
			bodyFieldTargeted = true
			break
		}
	}

	if !bodyFieldTargeted {
		t.Error("expected at least one body field to be targeted")
	}
}

func TestGenerator_GenerateWithLLM(t *testing.T) {
	mockProvider := llm.NewMockProvider(
		llm.WithDefaultResponse(`[
			{
				"value": "admin' OR '1'='1",
				"type": "sqli",
				"category": "injection",
				"description": "SQL injection to bypass auth",
				"metadata": {"target_param": "username"}
			}
		]`),
	)

	config := types.AttackSettings{
		UseLLMPayloads: true,
		LLMConcurrency: 1,
	}

	g := NewGenerator(mockProvider, config, "")

	endpoint := types.Endpoint{
		Method:          "POST",
		Path:            "/login",
		BusinessContext: "User authentication endpoint",
		Parameters: []types.Parameter{
			{Name: "username", In: "body", Type: "string"},
		},
	}

	ctx := context.Background()
	payloads, err := g.GenerateWithLLM(ctx, endpoint)

	if err != nil {
		t.Fatalf("GenerateWithLLM failed: %v", err)
	}

	if len(payloads) == 0 {
		t.Error("expected LLM-generated payloads, got none")
	}

	// Verify the provider was called
	if mockProvider.CallCount() == 0 {
		t.Error("expected LLM provider to be called")
	}
}

func TestGenerator_GetAttackTypes(t *testing.T) {
	tests := []struct {
		name           string
		config         types.AttackSettings
		endpoint       types.Endpoint
		expectContains []string
		expectMissing  []string
	}{
		{
			name:   "default attacks",
			config: types.AttackSettings{},
			endpoint: types.Endpoint{
				Method: "GET",
				Path:   "/users",
			},
			expectContains: []string{types.AttackIDOR, types.AttackSQLi, types.AttackXSS},
		},
		{
			name: "POST adds mass assignment",
			config: types.AttackSettings{},
			endpoint: types.Endpoint{
				Method: "POST",
				Path:   "/users",
			},
			expectContains: []string{types.AttackMassAssignment},
		},
		{
			name: "disabled attacks excluded",
			config: types.AttackSettings{
				Disabled: []string{types.AttackSQLi},
			},
			endpoint: types.Endpoint{
				Method: "GET",
				Path:   "/users",
			},
			expectMissing: []string{types.AttackSQLi},
		},
		{
			name: "only enabled attacks",
			config: types.AttackSettings{
				Enabled: []string{types.AttackIDOR},
			},
			endpoint: types.Endpoint{
				Method: "GET",
				Path:   "/users",
			},
			expectContains: []string{types.AttackIDOR},
			expectMissing:  []string{types.AttackSQLi, types.AttackXSS},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGenerator(nil, tt.config, "")
			attacks := g.getAttackTypes(tt.endpoint)

			attackSet := make(map[string]bool)
			for _, a := range attacks {
				attackSet[a] = true
			}

			for _, expected := range tt.expectContains {
				if !attackSet[expected] {
					t.Errorf("expected attack type %s not found", expected)
				}
			}

			for _, missing := range tt.expectMissing {
				if attackSet[missing] {
					t.Errorf("attack type %s should not be present", missing)
				}
			}
		})
	}
}

func TestGenerator_LimitPayloads(t *testing.T) {
	config := types.AttackSettings{
		MaxPayloadsPerType: 2,
	}

	g := NewGenerator(nil, config, "")

	requests := []FuzzRequest{
		{Param: &types.Parameter{Name: "id"}, Payload: Payload{Type: "idor", Value: "1"}},
		{Param: &types.Parameter{Name: "id"}, Payload: Payload{Type: "idor", Value: "2"}},
		{Param: &types.Parameter{Name: "id"}, Payload: Payload{Type: "idor", Value: "3"}},
		{Param: &types.Parameter{Name: "id"}, Payload: Payload{Type: "idor", Value: "4"}},
		{Param: &types.Parameter{Name: "q"}, Payload: Payload{Type: "sqli", Value: "a"}},
		{Param: &types.Parameter{Name: "q"}, Payload: Payload{Type: "sqli", Value: "b"}},
		{Param: &types.Parameter{Name: "q"}, Payload: Payload{Type: "sqli", Value: "c"}},
	}

	limited := g.limitPayloads(requests)

	// Should have max 2 per type:param combination
	idorCount := 0
	sqliCount := 0
	for _, req := range limited {
		if req.Payload.Type == "idor" {
			idorCount++
		}
		if req.Payload.Type == "sqli" {
			sqliCount++
		}
	}

	if idorCount > 2 {
		t.Errorf("expected max 2 IDOR payloads, got %d", idorCount)
	}
	if sqliCount > 2 {
		t.Errorf("expected max 2 SQLi payloads, got %d", sqliCount)
	}
}

func TestGenerator_FindTargetParam(t *testing.T) {
	g := NewGenerator(nil, types.AttackSettings{}, "")

	endpoint := types.Endpoint{
		Parameters: []types.Parameter{
			{Name: "id", In: "path", Type: "integer"},
			{Name: "search", In: "query", Type: "string"},
		},
		Body: &types.RequestBody{
			Fields: []types.BodyField{
				{Name: "username", Type: "string"},
			},
		},
	}

	tests := []struct {
		name         string
		payload      Payload
		expectedName string
	}{
		{
			name: "find by metadata",
			payload: Payload{
				Metadata: map[string]string{"target_param": "search"},
			},
			expectedName: "search",
		},
		{
			name: "find body field",
			payload: Payload{
				Metadata: map[string]string{"target_param": "username"},
			},
			expectedName: "username",
		},
		{
			name:         "fallback to first string param",
			payload:      Payload{},
			expectedName: "search",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			param := g.findTargetParam(endpoint, tt.payload)
			if param == nil {
				t.Fatal("findTargetParam returned nil")
			}
			if param.Name != tt.expectedName {
				t.Errorf("param name = %s, expected %s", param.Name, tt.expectedName)
			}
		})
	}
}
