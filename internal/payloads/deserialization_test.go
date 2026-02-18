package payloads

import (
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestDeserializationGenerator_Type(t *testing.T) {
	g := NewDeserializationGenerator()
	if got := g.Type(); got != "deserialization" {
		t.Errorf("Type() = %q, want %q", got, "deserialization")
	}
}

func TestDeserializationGenerator_RelevantEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint types.Endpoint
		param    *types.Parameter
	}{
		{
			name: "POST endpoint with data param",
			endpoint: types.Endpoint{
				Method: "POST",
				Path:   "/api/process",
			},
			param: &types.Parameter{Name: "data", In: "body", Type: "string"},
		},
		{
			name: "PUT endpoint with generic param",
			endpoint: types.Endpoint{
				Method: "PUT",
				Path:   "/api/update",
			},
			param: &types.Parameter{Name: "value", In: "body", Type: "string"},
		},
		{
			name: "deserialization-related param name",
			endpoint: types.Endpoint{
				Method: "GET",
				Path:   "/api/items",
			},
			param: &types.Parameter{Name: "serialized_object", In: "query", Type: "string"},
		},
		{
			name: "deserialization-related path",
			endpoint: types.Endpoint{
				Method: "GET",
				Path:   "/api/deserialize",
			},
			param: &types.Parameter{Name: "value", In: "query", Type: "string"},
		},
		{
			name: "object type parameter",
			endpoint: types.Endpoint{
				Method: "GET",
				Path:   "/api/items",
			},
			param: &types.Parameter{Name: "value", In: "query", Type: "object"},
		},
	}

	g := NewDeserializationGenerator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := g.Generate(tt.endpoint, tt.param)
			if len(payloads) == 0 {
				t.Error("expected payloads for relevant endpoint, got 0")
			}
			for i, p := range payloads {
				if p.Type != types.AttackDeserialization {
					t.Errorf("payload[%d].Type = %q, want %q", i, p.Type, types.AttackDeserialization)
				}
			}
		})
	}
}

func TestDeserializationGenerator_IrrelevantEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint types.Endpoint
		param    *types.Parameter
	}{
		{
			name: "GET endpoint with irrelevant param",
			endpoint: types.Endpoint{
				Method: "GET",
				Path:   "/api/users",
			},
			param: &types.Parameter{Name: "page", In: "query", Type: "string"},
		},
		{
			name: "GET with integer param",
			endpoint: types.Endpoint{
				Method: "GET",
				Path:   "/api/health",
			},
			param: &types.Parameter{Name: "version", In: "query", Type: "integer"},
		},
	}

	g := NewDeserializationGenerator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := g.Generate(tt.endpoint, tt.param)
			if len(payloads) != 0 {
				t.Errorf("expected 0 payloads for irrelevant endpoint, got %d", len(payloads))
			}
		})
	}
}

func TestDeserializationGenerator_PayloadCategories(t *testing.T) {
	g := NewDeserializationGenerator()
	endpoint := types.Endpoint{
		Method: "POST",
		Path:   "/api/import",
	}
	param := &types.Parameter{Name: "payload", In: "body", Type: "string"}

	payloads := g.Generate(endpoint, param)
	if len(payloads) == 0 {
		t.Fatal("expected payloads, got 0")
	}

	// The deserialization generator produces payloads from five methods.
	// All use category "deserialization" but differ by metadata["language"]:
	// javaPayloads -> language "java"
	// pythonPayloads -> language "python"
	// phpPayloads -> language "php"
	// dotNetPayloads -> language "dotnet"
	// rubyPayloads -> language "ruby"
	wantLanguages := map[string]bool{
		"java":   false,
		"python": false,
		"php":    false,
		"dotnet": false,
		"ruby":   false,
	}

	for _, p := range payloads {
		if lang, ok := p.Metadata["language"]; ok {
			if _, want := wantLanguages[lang]; want {
				wantLanguages[lang] = true
			}
		}
	}

	for lang, found := range wantLanguages {
		if !found {
			t.Errorf("expected language %q not found in payloads", lang)
		}
	}
}
