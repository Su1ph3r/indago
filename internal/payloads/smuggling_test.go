package payloads

import (
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestSmugglingGenerator_Type(t *testing.T) {
	g := NewSmugglingGenerator()
	if got := g.Type(); got != "request_smuggling" {
		t.Errorf("Type() = %q, want %q", got, "request_smuggling")
	}
}

func TestSmugglingGenerator_Generate(t *testing.T) {
	g := NewSmugglingGenerator()

	endpoint := types.Endpoint{
		Method: "POST",
		Path:   "/api/data",
		Parameters: []types.Parameter{
			{Name: "input", In: "body", Type: "string"},
			{Name: "extra", In: "body", Type: "string"},
		},
	}

	// First parameter (sentinel) should produce payloads
	firstParam := &endpoint.Parameters[0]
	payloads := g.Generate(endpoint, firstParam)
	if len(payloads) == 0 {
		t.Fatal("expected payloads for sentinel (first) parameter, got 0")
	}

	for i, p := range payloads {
		if p.Type != types.AttackSmuggling {
			t.Errorf("payload[%d].Type = %q, want %q", i, p.Type, types.AttackSmuggling)
		}
	}

	// Second parameter should NOT produce payloads (not sentinel)
	secondParam := &endpoint.Parameters[1]
	payloads2 := g.Generate(endpoint, secondParam)
	if len(payloads2) != 0 {
		t.Errorf("expected 0 payloads for non-sentinel parameter, got %d", len(payloads2))
	}
}

func TestSmugglingGenerator_NoParamsSkip(t *testing.T) {
	g := NewSmugglingGenerator()

	// Endpoint with no parameters at all
	endpoint := types.Endpoint{
		Method:     "POST",
		Path:       "/api/data",
		Parameters: []types.Parameter{},
	}
	param := &types.Parameter{Name: "orphan", In: "body", Type: "string"}

	payloads := g.Generate(endpoint, param)
	if len(payloads) != 0 {
		t.Errorf("expected 0 payloads when endpoint has no parameters, got %d", len(payloads))
	}
}

func TestSmugglingGenerator_PayloadCategories(t *testing.T) {
	g := NewSmugglingGenerator()

	endpoint := types.Endpoint{
		Method: "POST",
		Path:   "/api/data",
		Parameters: []types.Parameter{
			{Name: "input", In: "body", Type: "string"},
		},
	}
	param := &endpoint.Parameters[0]

	payloads := g.Generate(endpoint, param)
	if len(payloads) == 0 {
		t.Fatal("expected payloads, got 0")
	}

	// The smuggling generator produces payloads from four methods.
	// All use category "smuggling" but differ by metadata["technique"]:
	// clTEPayloads -> technique "CL.TE"
	// teCLPayloads -> technique "TE.CL"
	// teTEObfuscationPayloads -> technique "TE.TE"
	// headerInjectionPayloads -> technique "crlf_injection"
	wantTechniques := map[string]bool{
		"CL.TE":          false,
		"TE.CL":          false,
		"TE.TE":          false,
		"crlf_injection": false,
	}

	for _, p := range payloads {
		if tech, ok := p.Metadata["technique"]; ok {
			if _, want := wantTechniques[tech]; want {
				wantTechniques[tech] = true
			}
		}
	}

	for tech, found := range wantTechniques {
		if !found {
			t.Errorf("expected technique %q not found in payloads", tech)
		}
	}
}
