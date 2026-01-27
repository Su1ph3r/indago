package payloads

import (
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestInjectionGenerator_SQLi(t *testing.T) {
	config := types.InjectionSettings{
		SQLi:       true,
		BlindDelay: 5,
	}
	g := NewInjectionGenerator(config).ForSQLi()

	if g.Type() != types.AttackSQLi {
		t.Errorf("expected type %s, got %s", types.AttackSQLi, g.Type())
	}

	endpoint := types.Endpoint{
		Method: "GET",
		Path:   "/search",
	}
	param := &types.Parameter{
		Name: "query",
		In:   "query",
		Type: "string",
	}

	payloads := g.Generate(endpoint, param)

	if len(payloads) < 5 {
		t.Errorf("expected at least 5 SQLi payloads, got %d", len(payloads))
	}

	// Check for common SQLi patterns
	foundQuote := false
	foundOr := false
	foundUnion := false

	for _, p := range payloads {
		if contains(p.Value, "'") {
			foundQuote = true
		}
		if containsIgnoreCase(p.Value, "or") {
			foundOr = true
		}
		if containsIgnoreCase(p.Value, "union") {
			foundUnion = true
		}
	}

	if !foundQuote {
		t.Error("expected SQLi payload with single quote")
	}
	if !foundOr {
		t.Error("expected SQLi payload with OR condition")
	}
	if !foundUnion {
		t.Error("expected SQLi payload with UNION")
	}
}

func TestInjectionGenerator_NoSQLi(t *testing.T) {
	config := types.InjectionSettings{
		NoSQLi: true,
	}
	g := NewInjectionGenerator(config).ForNoSQLi()

	if g.Type() != types.AttackNoSQLi {
		t.Errorf("expected type %s, got %s", types.AttackNoSQLi, g.Type())
	}

	endpoint := types.Endpoint{
		Method: "POST",
		Path:   "/login",
	}
	param := &types.Parameter{
		Name: "username",
		In:   "body",
		Type: "string",
	}

	payloads := g.Generate(endpoint, param)

	if len(payloads) < 3 {
		t.Errorf("expected at least 3 NoSQLi payloads, got %d", len(payloads))
	}

	// Check for MongoDB operators
	foundDollar := false
	foundGt := false

	for _, p := range payloads {
		if contains(p.Value, "$") {
			foundDollar = true
		}
		if contains(p.Value, "$gt") || contains(p.Value, "$ne") {
			foundGt = true
		}
	}

	if !foundDollar {
		t.Error("expected NoSQLi payload with $ operator")
	}
	if !foundGt {
		t.Error("expected NoSQLi payload with comparison operator")
	}
}

func TestInjectionGenerator_CommandInjection(t *testing.T) {
	config := types.InjectionSettings{
		Command: true,
	}
	g := NewInjectionGenerator(config).ForCommand()

	if g.Type() != types.AttackCommandInject {
		t.Errorf("expected type %s, got %s", types.AttackCommandInject, g.Type())
	}

	endpoint := types.Endpoint{
		Method: "POST",
		Path:   "/execute",
	}
	param := &types.Parameter{
		Name: "cmd",
		In:   "body",
		Type: "string",
	}

	payloads := g.Generate(endpoint, param)

	if len(payloads) < 5 {
		t.Errorf("expected at least 5 command injection payloads, got %d", len(payloads))
	}

	// Check for common command injection patterns
	foundPipe := false
	foundSemicolon := false
	foundBacktick := false

	for _, p := range payloads {
		if contains(p.Value, "|") {
			foundPipe = true
		}
		if contains(p.Value, ";") {
			foundSemicolon = true
		}
		if contains(p.Value, "`") || contains(p.Value, "$(") {
			foundBacktick = true
		}
	}

	if !foundPipe {
		t.Error("expected command injection payload with pipe")
	}
	if !foundSemicolon {
		t.Error("expected command injection payload with semicolon")
	}
	if !foundBacktick {
		t.Error("expected command injection payload with command substitution")
	}
}

func TestInjectionGenerator_AllPayloadsHaveCorrectType(t *testing.T) {
	tests := []struct {
		name         string
		generator    AttackGenerator
		expectedType string
	}{
		{
			name:         "SQLi",
			generator:    NewInjectionGenerator(types.InjectionSettings{SQLi: true}).ForSQLi(),
			expectedType: types.AttackSQLi,
		},
		{
			name:         "NoSQLi",
			generator:    NewInjectionGenerator(types.InjectionSettings{NoSQLi: true}).ForNoSQLi(),
			expectedType: types.AttackNoSQLi,
		},
		{
			name:         "Command",
			generator:    NewInjectionGenerator(types.InjectionSettings{Command: true}).ForCommand(),
			expectedType: types.AttackCommandInject,
		},
	}

	endpoint := types.Endpoint{Method: "GET", Path: "/test"}
	param := &types.Parameter{Name: "input", In: "query", Type: "string"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := tt.generator.Generate(endpoint, param)
			for i, p := range payloads {
				if p.Type != tt.expectedType {
					t.Errorf("payload[%d] type = %s, expected %s", i, p.Type, tt.expectedType)
				}
			}
		})
	}
}

// Helper functions
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func containsIgnoreCase(s, substr string) bool {
	sLower := toLower(s)
	substrLower := toLower(substr)
	return contains(sLower, substrLower)
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
