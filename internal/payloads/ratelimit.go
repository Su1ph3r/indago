package payloads

import (
	"github.com/su1ph3r/indago/pkg/types"
)

// RateLimitGenerator generates payloads for rate limit testing
type RateLimitGenerator struct{}

// NewRateLimitGenerator creates a new rate limit payload generator
func NewRateLimitGenerator() *RateLimitGenerator {
	return &RateLimitGenerator{}
}

// Type returns the attack type
func (g *RateLimitGenerator) Type() string {
	return types.AttackRateLimit
}

// Generate generates rate limit test payloads for a parameter
func (g *RateLimitGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	// Rate limit testing is endpoint-focused, not parameter-focused
	// Generate payloads that help detect rate limiting weaknesses

	// Standard values to use for rapid requests
	payloads = append(payloads, g.rapidRequestPayloads()...)

	// Bypass technique payloads
	payloads = append(payloads, g.bypassPayloads()...)

	return payloads
}

// rapidRequestPayloads generates payloads for rapid request testing
func (g *RateLimitGenerator) rapidRequestPayloads() []Payload {
	return []Payload{
		{
			Value:       "test",
			Type:        types.AttackRateLimit,
			Category:    "availability",
			Description: "Rate limit test - standard value",
			Metadata:    map[string]string{"test_type": "rapid", "count": "100"},
		},
		{
			Value:       "ratelimit-test-1",
			Type:        types.AttackRateLimit,
			Category:    "availability",
			Description: "Rate limit test - unique marker 1",
			Metadata:    map[string]string{"test_type": "rapid", "count": "50"},
		},
		{
			Value:       "ratelimit-test-2",
			Type:        types.AttackRateLimit,
			Category:    "availability",
			Description: "Rate limit test - unique marker 2",
			Metadata:    map[string]string{"test_type": "rapid", "count": "50"},
		},
	}
}

// bypassPayloads generates payloads for rate limit bypass attempts
func (g *RateLimitGenerator) bypassPayloads() []Payload {
	return []Payload{
		{
			Value:       "X-Forwarded-For: 127.0.0.1",
			Type:        types.AttackRateLimit,
			Category:    "availability",
			Description: "Rate limit bypass via X-Forwarded-For",
			Metadata:    map[string]string{"bypass_type": "header", "header": "X-Forwarded-For"},
		},
		{
			Value:       "X-Real-IP: 10.0.0.1",
			Type:        types.AttackRateLimit,
			Category:    "availability",
			Description: "Rate limit bypass via X-Real-IP",
			Metadata:    map[string]string{"bypass_type": "header", "header": "X-Real-IP"},
		},
		{
			Value:       "X-Originating-IP: 192.168.1.1",
			Type:        types.AttackRateLimit,
			Category:    "availability",
			Description: "Rate limit bypass via X-Originating-IP",
			Metadata:    map[string]string{"bypass_type": "header", "header": "X-Originating-IP"},
		},
		{
			Value:       "X-Client-IP: 172.16.0.1",
			Type:        types.AttackRateLimit,
			Category:    "availability",
			Description: "Rate limit bypass via X-Client-IP",
			Metadata:    map[string]string{"bypass_type": "header", "header": "X-Client-IP"},
		},
		{
			Value:       "True-Client-IP: 8.8.8.8",
			Type:        types.AttackRateLimit,
			Category:    "availability",
			Description: "Rate limit bypass via True-Client-IP",
			Metadata:    map[string]string{"bypass_type": "header", "header": "True-Client-IP"},
		},
		{
			Value:       "X-Forwarded-Host: different-host.com",
			Type:        types.AttackRateLimit,
			Category:    "availability",
			Description: "Rate limit bypass via X-Forwarded-Host",
			Metadata:    map[string]string{"bypass_type": "header", "header": "X-Forwarded-Host"},
		},
		{
			Value:       "?cachebuster=1",
			Type:        types.AttackRateLimit,
			Category:    "availability",
			Description: "Rate limit bypass via cache buster parameter",
			Metadata:    map[string]string{"bypass_type": "parameter"},
		},
		{
			Value:       "/./",
			Type:        types.AttackRateLimit,
			Category:    "availability",
			Description: "Rate limit bypass via path normalization",
			Metadata:    map[string]string{"bypass_type": "path"},
		},
		{
			Value:       "/%2e/",
			Type:        types.AttackRateLimit,
			Category:    "availability",
			Description: "Rate limit bypass via URL encoded path",
			Metadata:    map[string]string{"bypass_type": "path"},
		},
		{
			Value:       "/;/",
			Type:        types.AttackRateLimit,
			Category:    "availability",
			Description: "Rate limit bypass via path parameter",
			Metadata:    map[string]string{"bypass_type": "path"},
		},
	}
}
