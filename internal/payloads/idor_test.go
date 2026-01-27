package payloads

import (
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestIDORGenerator_Type(t *testing.T) {
	g := NewIDORGenerator(types.IDORSettings{})
	if g.Type() != types.AttackIDOR {
		t.Errorf("expected type %s, got %s", types.AttackIDOR, g.Type())
	}
}

func TestIDORGenerator_IsIDParameter(t *testing.T) {
	g := NewIDORGenerator(types.IDORSettings{})

	tests := []struct {
		name     string
		param    types.Parameter
		expected bool
	}{
		{
			name:     "user_id parameter",
			param:    types.Parameter{Name: "user_id", In: "path", Type: "integer"},
			expected: true,
		},
		{
			name:     "userId parameter",
			param:    types.Parameter{Name: "userId", In: "path", Type: "integer"},
			expected: true,
		},
		{
			name:     "account_id parameter",
			param:    types.Parameter{Name: "account_id", In: "query", Type: "string"},
			expected: true,
		},
		{
			name:     "orderId parameter",
			param:    types.Parameter{Name: "orderId", In: "path", Type: "integer"},
			expected: true,
		},
		{
			name:     "generic path integer",
			param:    types.Parameter{Name: "foo", In: "path", Type: "integer"},
			expected: true,
		},
		{
			name:     "search parameter",
			param:    types.Parameter{Name: "search", In: "query", Type: "string"},
			expected: false,
		},
		{
			name:     "limit parameter",
			param:    types.Parameter{Name: "limit", In: "query", Type: "integer"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := g.isIDParameter(&tt.param)
			if result != tt.expected {
				t.Errorf("isIDParameter(%s) = %v, expected %v", tt.param.Name, result, tt.expected)
			}
		})
	}
}

func TestIDORGenerator_GenerateNumericPayloads(t *testing.T) {
	g := NewIDORGenerator(types.IDORSettings{IDRange: 5})

	payloads := g.generateNumericPayloads("100")

	// Should have increments and decrements
	if len(payloads) < 10 {
		t.Errorf("expected at least 10 payloads, got %d", len(payloads))
	}

	// Check for expected values
	expectedValues := map[string]bool{
		"101": false, "102": false, "99": false, "98": false,
		"0": false, "1": false, "-1": false,
	}

	for _, p := range payloads {
		if _, ok := expectedValues[p.Value]; ok {
			expectedValues[p.Value] = true
		}
	}

	for val, found := range expectedValues {
		if !found {
			t.Errorf("expected payload value %s not found", val)
		}
	}
}

func TestIDORGenerator_GenerateUUIDPayloads(t *testing.T) {
	g := NewIDORGenerator(types.IDORSettings{TestUUIDs: true})

	original := "550e8400-e29b-41d4-a716-446655440000"
	payloads := g.generateUUIDPayloads(original)

	if len(payloads) < 3 {
		t.Errorf("expected at least 3 UUID payloads, got %d", len(payloads))
	}

	// Check for null UUID
	foundNull := false
	for _, p := range payloads {
		if p.Value == "00000000-0000-0000-0000-000000000000" {
			foundNull = true
			break
		}
	}
	if !foundNull {
		t.Error("expected null UUID payload not found")
	}
}

func TestIDORGenerator_Generate(t *testing.T) {
	g := NewIDORGenerator(types.IDORSettings{
		IDRange:   3,
		TestUUIDs: true,
	})

	endpoint := types.Endpoint{
		Method: "GET",
		Path:   "/users/{userId}",
	}

	tests := []struct {
		name          string
		param         types.Parameter
		minPayloads   int
		shouldGenerate bool
	}{
		{
			name: "numeric user_id",
			param: types.Parameter{
				Name:    "user_id",
				In:      "path",
				Type:    "integer",
				Example: 123,
			},
			minPayloads:   10,
			shouldGenerate: true,
		},
		{
			name: "UUID user_id",
			param: types.Parameter{
				Name:    "user_id",
				In:      "path",
				Type:    "string",
				Example: "550e8400-e29b-41d4-a716-446655440000",
			},
			minPayloads:   5,
			shouldGenerate: true,
		},
		{
			name: "non-ID parameter",
			param: types.Parameter{
				Name: "search",
				In:   "query",
				Type: "string",
			},
			minPayloads:   0,
			shouldGenerate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := g.Generate(endpoint, &tt.param)

			if tt.shouldGenerate && len(payloads) < tt.minPayloads {
				t.Errorf("expected at least %d payloads, got %d", tt.minPayloads, len(payloads))
			}

			if !tt.shouldGenerate && len(payloads) > 0 {
				t.Errorf("expected no payloads for non-ID parameter, got %d", len(payloads))
			}

			// Verify all payloads have the correct type
			for _, p := range payloads {
				if p.Type != types.AttackIDOR {
					t.Errorf("payload type = %s, expected %s", p.Type, types.AttackIDOR)
				}
			}
		})
	}
}

func TestIDORGenerator_GenerateGenericPayloads(t *testing.T) {
	g := NewIDORGenerator(types.IDORSettings{})

	payloads := g.generateGenericPayloads()

	if len(payloads) < 5 {
		t.Errorf("expected at least 5 generic payloads, got %d", len(payloads))
	}

	// Check for expected generic values
	expectedValues := map[string]bool{
		"admin": false, "root": false, "*": false,
	}

	for _, p := range payloads {
		if _, ok := expectedValues[p.Value]; ok {
			expectedValues[p.Value] = true
		}
	}

	for val, found := range expectedValues {
		if !found {
			t.Errorf("expected generic payload value %s not found", val)
		}
	}
}
