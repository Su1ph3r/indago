// Package payloads provides attack payload generation
package payloads

import (
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// redirectParamNames are parameter names commonly used for redirects.
var redirectParamNames = map[string]bool{
	"redirect":     true,
	"redirect_uri": true,
	"redirect_url": true,
	"return_to":    true,
	"return_url":   true,
	"callback":     true,
	"callback_url": true,
	"next":         true,
	"url":          true,
	"goto":         true,
	"dest":         true,
	"destination":  true,
	"forward":      true,
	"return":       true,
	"continue":     true,
	"target":       true,
	"rurl":         true,
	"redir":        true,
	"returl":       true,
}

// OpenRedirectGenerator generates payloads for open redirect testing.
type OpenRedirectGenerator struct{}

// NewOpenRedirectGenerator creates a new open redirect generator.
func NewOpenRedirectGenerator() *OpenRedirectGenerator {
	return &OpenRedirectGenerator{}
}

// Type returns the attack type.
func (g *OpenRedirectGenerator) Type() string {
	return types.AttackOpenRedirect
}

// Generate produces open redirect payloads only for redirect-like parameters.
func (g *OpenRedirectGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	if !isRedirectParam(param.Name) {
		return nil
	}

	redirectPayloads := []struct {
		value string
		desc  string
	}{
		{"https://evil.com", "Direct external redirect"},
		{"//evil.com", "Protocol-relative redirect"},
		{`\/\/evil.com`, "Escaped slash redirect"},
		{"https://example.com@evil.com", "URL authority confusion"},
		{"%2f%2fevil.com", "URL-encoded protocol-relative redirect"},
		{"///evil.com", "Triple-slash redirect"},
		{"https://evil.com/%2e%2e", "Path traversal redirect"},
	}

	var payloads []Payload
	for _, p := range redirectPayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Type:        types.AttackOpenRedirect,
			Category:    "redirect",
			Description: p.desc,
			Metadata: map[string]string{
				"target_param": param.Name,
			},
		})
	}

	return payloads
}

func isRedirectParam(name string) bool {
	return redirectParamNames[strings.ToLower(name)]
}
