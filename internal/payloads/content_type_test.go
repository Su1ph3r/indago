package payloads

import (
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestContentTypeConfusionGenerator_POST(t *testing.T) {
	gen := NewContentTypeConfusionGenerator()
	ep := types.Endpoint{
		Method: "POST",
		Path:   "/api/users",
		Parameters: []types.Parameter{
			{Name: "name", In: "body", Type: "string"},
		},
	}

	payloads := gen.Generate(ep, &ep.Parameters[0])

	if len(payloads) == 0 {
		t.Fatal("expected payloads for POST endpoint")
	}

	for _, p := range payloads {
		if p.Type != types.AttackContentTypeConfusion {
			t.Errorf("expected type %s, got %s", types.AttackContentTypeConfusion, p.Type)
		}
	}

	// Check metadata keys
	hasOverride := false
	hasRemove := false
	for _, p := range payloads {
		if _, ok := p.Metadata["override_content_type"]; ok {
			hasOverride = true
		}
		if _, ok := p.Metadata["remove_content_type"]; ok {
			hasRemove = true
		}
	}
	if !hasOverride {
		t.Error("expected at least one payload with override_content_type metadata")
	}
	if !hasRemove {
		t.Error("expected at least one payload with remove_content_type metadata")
	}
}

func TestContentTypeConfusionGenerator_GET(t *testing.T) {
	gen := NewContentTypeConfusionGenerator()
	ep := types.Endpoint{
		Method: "GET",
		Path:   "/api/users",
		Parameters: []types.Parameter{
			{Name: "id", In: "query", Type: "string"},
		},
	}

	payloads := gen.Generate(ep, &ep.Parameters[0])

	if len(payloads) != 0 {
		t.Errorf("expected 0 payloads for GET endpoint, got %d", len(payloads))
	}
}

func TestContentTypeConfusionGenerator_PUT(t *testing.T) {
	gen := NewContentTypeConfusionGenerator()
	ep := types.Endpoint{
		Method: "PUT",
		Path:   "/api/users/1",
		Parameters: []types.Parameter{
			{Name: "name", In: "body", Type: "string"},
		},
	}

	payloads := gen.Generate(ep, &ep.Parameters[0])

	if len(payloads) == 0 {
		t.Error("expected payloads for PUT endpoint")
	}
}

func TestContentTypeConfusionGenerator_Sentinel(t *testing.T) {
	gen := NewContentTypeConfusionGenerator()
	ep := types.Endpoint{
		Method: "POST",
		Path:   "/api/users",
		Parameters: []types.Parameter{
			{Name: "name", In: "body", Type: "string"},
			{Name: "email", In: "body", Type: "string"},
		},
	}

	// First param generates payloads
	p1 := gen.Generate(ep, &ep.Parameters[0])
	if len(p1) == 0 {
		t.Error("expected payloads for first parameter")
	}

	// Second param skipped by sentinel
	p2 := gen.Generate(ep, &ep.Parameters[1])
	if len(p2) != 0 {
		t.Errorf("expected 0 payloads for second parameter (sentinel), got %d", len(p2))
	}
}
