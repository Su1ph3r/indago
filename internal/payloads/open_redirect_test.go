package payloads

import (
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestOpenRedirectGenerator_RedirectParam(t *testing.T) {
	gen := NewOpenRedirectGenerator()
	ep := types.Endpoint{
		Method: "GET",
		Path:   "/auth/callback",
		Parameters: []types.Parameter{
			{Name: "redirect_uri", In: "query", Type: "string"},
		},
	}

	payloads := gen.Generate(ep, &ep.Parameters[0])

	if len(payloads) == 0 {
		t.Fatal("expected payloads for redirect_uri parameter")
	}

	for _, p := range payloads {
		if p.Type != types.AttackOpenRedirect {
			t.Errorf("expected type %s, got %s", types.AttackOpenRedirect, p.Type)
		}
	}

	// Check that evil.com is in at least one payload
	foundEvil := false
	for _, p := range payloads {
		if p.Value == "https://evil.com" {
			foundEvil = true
			break
		}
	}
	if !foundEvil {
		t.Error("expected https://evil.com in payloads")
	}
}

func TestOpenRedirectGenerator_NonRedirectParam(t *testing.T) {
	gen := NewOpenRedirectGenerator()
	ep := types.Endpoint{
		Method: "GET",
		Path:   "/api/users",
		Parameters: []types.Parameter{
			{Name: "id", In: "query", Type: "string"},
		},
	}

	payloads := gen.Generate(ep, &ep.Parameters[0])

	if len(payloads) != 0 {
		t.Errorf("expected 0 payloads for non-redirect parameter, got %d", len(payloads))
	}
}

func TestOpenRedirectGenerator_AllRedirectParams(t *testing.T) {
	gen := NewOpenRedirectGenerator()

	redirectParams := []string{
		"redirect", "redirect_uri", "return_to", "callback",
		"next", "url", "goto", "dest", "forward", "return",
		"continue", "target", "rurl",
	}

	for _, name := range redirectParams {
		ep := types.Endpoint{
			Method: "GET",
			Path:   "/test",
			Parameters: []types.Parameter{
				{Name: name, In: "query", Type: "string"},
			},
		}

		payloads := gen.Generate(ep, &ep.Parameters[0])
		if len(payloads) == 0 {
			t.Errorf("expected payloads for redirect param '%s'", name)
		}
	}
}

func TestOpenRedirectGenerator_CaseInsensitive(t *testing.T) {
	gen := NewOpenRedirectGenerator()
	ep := types.Endpoint{
		Method: "GET",
		Path:   "/test",
		Parameters: []types.Parameter{
			{Name: "Redirect_URI", In: "query", Type: "string"},
		},
	}

	payloads := gen.Generate(ep, &ep.Parameters[0])

	// isRedirectParam does strings.ToLower, so this should match
	if len(payloads) == 0 {
		t.Error("expected payloads for case-insensitive redirect param")
	}
}
