package payloads

import (
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestXXEGenerator_Type(t *testing.T) {
	g := NewXXEGenerator()
	if got := g.Type(); got != "xxe" {
		t.Errorf("Type() = %q, want %q", got, "xxe")
	}
}

func TestXXEGenerator_RelevantEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint types.Endpoint
		param    *types.Parameter
	}{
		{
			name: "XML content-type body",
			endpoint: types.Endpoint{
				Method: "POST",
				Path:   "/api/data",
				Body:   &types.RequestBody{ContentType: "application/xml"},
			},
			param: &types.Parameter{Name: "data", In: "body", Type: "string"},
		},
		{
			name: "SOAP content-type body",
			endpoint: types.Endpoint{
				Method: "POST",
				Path:   "/api/service",
				Body:   &types.RequestBody{ContentType: "text/xml+soap"},
			},
			param: &types.Parameter{Name: "request", In: "body", Type: "string"},
		},
		{
			name: "XML-related param name",
			endpoint: types.Endpoint{
				Method: "POST",
				Path:   "/api/process",
			},
			param: &types.Parameter{Name: "xml_data", In: "body", Type: "string"},
		},
		{
			name: "XML-related endpoint path",
			endpoint: types.Endpoint{
				Method: "POST",
				Path:   "/xml/import",
			},
			param: &types.Parameter{Name: "value", In: "body", Type: "string"},
		},
	}

	g := NewXXEGenerator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := g.Generate(tt.endpoint, tt.param)
			if len(payloads) == 0 {
				t.Error("expected payloads for relevant endpoint, got 0")
			}
			for i, p := range payloads {
				if p.Type != types.AttackXXE {
					t.Errorf("payload[%d].Type = %q, want %q", i, p.Type, types.AttackXXE)
				}
			}
		})
	}
}

func TestXXEGenerator_IrrelevantEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint types.Endpoint
		param    *types.Parameter
	}{
		{
			name: "JSON endpoint with generic param",
			endpoint: types.Endpoint{
				Method: "GET",
				Path:   "/api/users",
				Body:   &types.RequestBody{ContentType: "application/json"},
			},
			param: &types.Parameter{Name: "page", In: "query", Type: "string"},
		},
		{
			name: "no body, irrelevant path and param",
			endpoint: types.Endpoint{
				Method: "GET",
				Path:   "/api/health",
			},
			param: &types.Parameter{Name: "version", In: "query", Type: "string"},
		},
		{
			name: "integer param type",
			endpoint: types.Endpoint{
				Method: "GET",
				Path:   "/api/items",
			},
			param: &types.Parameter{Name: "count", In: "query", Type: "integer"},
		},
	}

	g := NewXXEGenerator()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := g.Generate(tt.endpoint, tt.param)
			if len(payloads) != 0 {
				t.Errorf("expected 0 payloads for irrelevant endpoint, got %d", len(payloads))
			}
		})
	}
}

func TestXXEGenerator_PayloadCategories(t *testing.T) {
	g := NewXXEGenerator()
	endpoint := types.Endpoint{
		Method: "POST",
		Path:   "/xml/import",
		Body:   &types.RequestBody{ContentType: "application/xml"},
	}
	param := &types.Parameter{Name: "document", In: "body", Type: "string"}

	payloads := g.Generate(endpoint, param)
	if len(payloads) == 0 {
		t.Fatal("expected payloads, got 0")
	}

	// The XXE generator produces payloads from four methods:
	// standardXXEPayloads -> category "file_read"
	// entityExpansionPayloads -> category "dos"
	// externalDTDPayloads -> category "external_dtd"
	// xxeViaFileFormatPayloads -> category "file_format"
	wantCategories := map[string]bool{
		"file_read":    false,
		"dos":          false,
		"external_dtd": false,
		"file_format":  false,
	}

	for _, p := range payloads {
		if _, ok := wantCategories[p.Category]; ok {
			wantCategories[p.Category] = true
		}
	}

	for cat, found := range wantCategories {
		if !found {
			t.Errorf("expected payload category %q not found", cat)
		}
	}
}
