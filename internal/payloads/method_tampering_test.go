package payloads

import (
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestMethodTamperingGenerator_GET(t *testing.T) {
	gen := NewMethodTamperingGenerator()
	ep := types.Endpoint{
		Method: "GET",
		Path:   "/api/users",
		Parameters: []types.Parameter{
			{Name: "id", In: "query", Type: "string"},
		},
	}

	payloads := gen.Generate(ep, &ep.Parameters[0])

	if len(payloads) == 0 {
		t.Fatal("expected payloads for GET endpoint")
	}

	// Should include DELETE, PUT, PATCH, TRACE + method override headers
	methodOverrides := map[string]bool{}
	headerOverrides := 0
	for _, p := range payloads {
		if p.Type != types.AttackMethodTampering {
			t.Errorf("expected type %s, got %s", types.AttackMethodTampering, p.Type)
		}
		if m, ok := p.Metadata["override_method"]; ok {
			methodOverrides[m] = true
		}
		if _, ok := p.Metadata["inject_header"]; ok {
			headerOverrides++
		}
	}

	for _, method := range []string{"DELETE", "PUT", "PATCH", "TRACE"} {
		if !methodOverrides[method] {
			t.Errorf("expected method override %s in payloads", method)
		}
	}
	if headerOverrides == 0 {
		t.Error("expected at least one header override payload")
	}
}

func TestMethodTamperingGenerator_POST(t *testing.T) {
	gen := NewMethodTamperingGenerator()
	ep := types.Endpoint{
		Method: "POST",
		Path:   "/api/users",
		Parameters: []types.Parameter{
			{Name: "name", In: "body", Type: "string"},
		},
	}

	payloads := gen.Generate(ep, &ep.Parameters[0])

	methodOverrides := map[string]bool{}
	for _, p := range payloads {
		if m, ok := p.Metadata["override_method"]; ok {
			methodOverrides[m] = true
		}
	}

	// POST should try DELETE, PUT, TRACE (not PATCH — not in the list for POST)
	if !methodOverrides["DELETE"] {
		t.Error("expected DELETE override for POST endpoint")
	}
	if !methodOverrides["TRACE"] {
		t.Error("expected TRACE override for POST endpoint")
	}
}

func TestMethodTamperingGenerator_Sentinel(t *testing.T) {
	gen := NewMethodTamperingGenerator()
	ep := types.Endpoint{
		Method: "GET",
		Path:   "/api/users",
		Parameters: []types.Parameter{
			{Name: "id", In: "query", Type: "string"},
			{Name: "name", In: "query", Type: "string"},
		},
	}

	// First param should generate payloads
	p1 := gen.Generate(ep, &ep.Parameters[0])
	if len(p1) == 0 {
		t.Error("expected payloads for first parameter")
	}

	// Second param should be skipped (sentinel)
	p2 := gen.Generate(ep, &ep.Parameters[1])
	if len(p2) != 0 {
		t.Errorf("expected 0 payloads for second parameter (sentinel), got %d", len(p2))
	}
}
