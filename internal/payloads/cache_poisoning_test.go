package payloads

import (
	"strings"
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestCachePoisoningGenerator_Type(t *testing.T) {
	g := NewCachePoisoningGenerator()
	if got := g.Type(); got != "cache_poisoning" {
		t.Errorf("Type() = %q, want %q", got, "cache_poisoning")
	}
}

func TestCachePoisoningGenerator_GETEndpoint(t *testing.T) {
	g := NewCachePoisoningGenerator()

	endpoint := types.Endpoint{
		Method: "GET",
		Path:   "/api/products",
		Parameters: []types.Parameter{
			{Name: "category", In: "query", Type: "string"},
			{Name: "page", In: "query", Type: "string"},
		},
	}

	// First parameter (sentinel) should produce payloads
	firstParam := &endpoint.Parameters[0]
	payloads := g.Generate(endpoint, firstParam)
	if len(payloads) == 0 {
		t.Fatal("expected payloads for GET endpoint sentinel parameter, got 0")
	}

	for i, p := range payloads {
		if p.Type != types.AttackCachePoisoning {
			t.Errorf("payload[%d].Type = %q, want %q", i, p.Type, types.AttackCachePoisoning)
		}
	}

	// Second parameter should NOT produce payloads (not sentinel)
	secondParam := &endpoint.Parameters[1]
	payloads2 := g.Generate(endpoint, secondParam)
	if len(payloads2) != 0 {
		t.Errorf("expected 0 payloads for non-sentinel parameter, got %d", len(payloads2))
	}
}

func TestCachePoisoningGenerator_NonGETSkip(t *testing.T) {
	tests := []struct {
		name   string
		method string
	}{
		{name: "POST", method: "POST"},
		{name: "PUT", method: "PUT"},
		{name: "DELETE", method: "DELETE"},
		{name: "PATCH", method: "PATCH"},
	}

	g := NewCachePoisoningGenerator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := types.Endpoint{
				Method: tt.method,
				Path:   "/api/data",
				Parameters: []types.Parameter{
					{Name: "input", In: "body", Type: "string"},
				},
			}
			param := &endpoint.Parameters[0]

			payloads := g.Generate(endpoint, param)
			if len(payloads) != 0 {
				t.Errorf("expected 0 payloads for %s endpoint, got %d", tt.method, len(payloads))
			}
		})
	}
}

func TestCachePoisoningGenerator_PayloadCategories(t *testing.T) {
	g := NewCachePoisoningGenerator()

	endpoint := types.Endpoint{
		Method: "GET",
		Path:   "/api/products",
		Parameters: []types.Parameter{
			{Name: "category", In: "query", Type: "string"},
		},
	}
	param := &endpoint.Parameters[0]

	payloads := g.Generate(endpoint, param)
	if len(payloads) == 0 {
		t.Fatal("expected payloads, got 0")
	}

	// The cache poisoning generator produces payloads from five methods:
	// unkeyedHeaderPayloads -> metadata has inject_header with X-Forwarded-Host/Scheme/etc.
	// parameterCloakingPayloads -> values with "&" or ";" separators
	// fatGETPayloads -> metadata has inject_body
	// hostHeaderPayloads -> metadata has inject_header with "Host:"
	// cacheKeyNormalizationPayloads -> URL-encoded or case-varied values

	foundUnkeyedHeader := false
	foundParameterCloaking := false
	foundFatGET := false
	foundHostHeader := false
	foundNormalization := false

	for _, p := range payloads {
		if hdr, ok := p.Metadata["inject_header"]; ok {
			if strings.Contains(hdr, "X-Forwarded") || strings.Contains(hdr, "X-Original") || strings.Contains(hdr, "X-Rewrite") {
				foundUnkeyedHeader = true
			}
			if strings.Contains(hdr, "Host:") {
				foundHostHeader = true
			}
		}
		if _, ok := p.Metadata["inject_body"]; ok {
			foundFatGET = true
		}
		if strings.Contains(p.Value, "&cachebuster") || strings.Contains(p.Value, ";cachebuster") {
			foundParameterCloaking = true
		}
		if strings.Contains(p.Value, "%") || p.Value == "NORMAL" || p.Value == "Normal" {
			foundNormalization = true
		}
	}

	if !foundUnkeyedHeader {
		t.Error("expected unkeyed_header payloads (X-Forwarded-Host etc.)")
	}
	if !foundParameterCloaking {
		t.Error("expected parameter_cloaking payloads (& or ; separator)")
	}
	if !foundFatGET {
		t.Error("expected fat_get payloads (inject_body metadata)")
	}
	if !foundHostHeader {
		t.Error("expected host_header payloads (Host: in inject_header)")
	}
	if !foundNormalization {
		t.Error("expected cache_key_normalization payloads (URL-encoded or case variants)")
	}
}
