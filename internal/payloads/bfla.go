package payloads

import (
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// BFLAGenerator generates Broken Function Level Authorization attack payloads
type BFLAGenerator struct{}

// NewBFLAGenerator creates a new BFLA payload generator
func NewBFLAGenerator() *BFLAGenerator {
	return &BFLAGenerator{}
}

// Type returns the attack type
func (g *BFLAGenerator) Type() string {
	return types.AttackBFLA
}

// Generate generates BFLA payloads for a parameter
func (g *BFLAGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	// BFLA targets function/action-related parameters
	if !g.isFunctionParameter(param, endpoint) {
		return payloads
	}

	// Generate role escalation payloads
	payloads = append(payloads, g.roleEscalationPayloads()...)

	// Generate action manipulation payloads
	payloads = append(payloads, g.actionManipulationPayloads()...)

	// Generate privilege escalation payloads
	payloads = append(payloads, g.privilegePayloads()...)

	return payloads
}

// isFunctionParameter checks if parameter relates to function/action control
func (g *BFLAGenerator) isFunctionParameter(param *types.Parameter, endpoint types.Endpoint) bool {
	nameLower := strings.ToLower(param.Name)
	pathLower := strings.ToLower(endpoint.Path)

	// Function/action related parameter names
	functionPatterns := []string{
		"action", "operation", "method", "function", "cmd", "command",
		"role", "permission", "privilege", "access", "level",
		"admin", "manager", "moderator", "superuser",
		"scope", "grant", "capability",
		"approve", "delete", "create", "update", "modify",
		"type", "mode", "status",
	}

	for _, pattern := range functionPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}

	// Check if endpoint path suggests admin/privileged function
	adminPaths := []string{
		"/admin", "/manage", "/internal", "/system",
		"/config", "/settings", "/control", "/debug",
		"/users", "/roles", "/permissions",
	}

	for _, adminPath := range adminPaths {
		if strings.Contains(pathLower, adminPath) {
			return true
		}
	}

	return false
}

// roleEscalationPayloads generates payloads for role-based access bypass
func (g *BFLAGenerator) roleEscalationPayloads() []Payload {
	return []Payload{
		{
			Value:       "admin",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Admin role escalation",
			Metadata:    map[string]string{"target": "role"},
		},
		{
			Value:       "administrator",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Administrator role escalation",
			Metadata:    map[string]string{"target": "role"},
		},
		{
			Value:       "superuser",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Superuser role escalation",
			Metadata:    map[string]string{"target": "role"},
		},
		{
			Value:       "root",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Root role escalation",
			Metadata:    map[string]string{"target": "role"},
		},
		{
			Value:       "system",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: System role escalation",
			Metadata:    map[string]string{"target": "role"},
		},
		{
			Value:       "manager",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Manager role escalation",
			Metadata:    map[string]string{"target": "role"},
		},
		{
			Value:       "moderator",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Moderator role escalation",
			Metadata:    map[string]string{"target": "role"},
		},
		{
			Value:       "owner",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Owner role escalation",
			Metadata:    map[string]string{"target": "role"},
		},
	}
}

// actionManipulationPayloads generates payloads for action/function bypass
func (g *BFLAGenerator) actionManipulationPayloads() []Payload {
	return []Payload{
		{
			Value:       "delete",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Delete action access",
			Metadata:    map[string]string{"target": "action"},
		},
		{
			Value:       "destroy",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Destroy action access",
			Metadata:    map[string]string{"target": "action"},
		},
		{
			Value:       "create",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Create action access",
			Metadata:    map[string]string{"target": "action"},
		},
		{
			Value:       "update",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Update action access",
			Metadata:    map[string]string{"target": "action"},
		},
		{
			Value:       "modify",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Modify action access",
			Metadata:    map[string]string{"target": "action"},
		},
		{
			Value:       "approve",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Approve action access",
			Metadata:    map[string]string{"target": "action"},
		},
		{
			Value:       "reject",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Reject action access",
			Metadata:    map[string]string{"target": "action"},
		},
		{
			Value:       "export",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Export action access",
			Metadata:    map[string]string{"target": "action"},
		},
		{
			Value:       "import",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Import action access",
			Metadata:    map[string]string{"target": "action"},
		},
		{
			Value:       "execute",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Execute action access",
			Metadata:    map[string]string{"target": "action"},
		},
	}
}

// privilegePayloads generates payloads for privilege level bypass
func (g *BFLAGenerator) privilegePayloads() []Payload {
	return []Payload{
		{
			Value:       "true",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Boolean privilege flag",
			Metadata:    map[string]string{"target": "privilege"},
		},
		{
			Value:       "1",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Numeric privilege flag",
			Metadata:    map[string]string{"target": "privilege"},
		},
		{
			Value:       "9999",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: High privilege level",
			Metadata:    map[string]string{"target": "privilege"},
		},
		{
			Value:       "*",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Wildcard privilege",
			Metadata:    map[string]string{"target": "privilege"},
		},
		{
			Value:       "all",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: All privileges",
			Metadata:    map[string]string{"target": "privilege"},
		},
		{
			Value:       "read,write,delete,admin",
			Type:        types.AttackBFLA,
			Category:    "authorization",
			Description: "BFLA: Multiple privileges",
			Metadata:    map[string]string{"target": "privilege"},
		},
	}
}
