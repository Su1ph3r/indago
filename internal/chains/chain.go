// Package chains provides multi-step attack chain functionality
package chains

import (
	"github.com/su1ph3r/indago/pkg/types"
)

// AttackChain represents a multi-step attack sequence
type AttackChain struct {
	ID          string       `yaml:"id" json:"id"`
	Name        string       `yaml:"name" json:"name"`
	Description string       `yaml:"description" json:"description"`
	Steps       []ChainStep  `yaml:"steps" json:"steps"`
	Purpose     string       `yaml:"purpose" json:"purpose"` // privilege_escalation, data_leakage, etc.
	Category    string       `yaml:"category" json:"category"`
	Priority    string       `yaml:"priority" json:"priority"`
	Conditions  []Condition  `yaml:"conditions,omitempty" json:"conditions,omitempty"`
	Tags        []string     `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// ChainStep represents a single step in an attack chain
type ChainStep struct {
	ID          string          `yaml:"id" json:"id"`
	Name        string          `yaml:"name" json:"name"`
	Endpoint    types.Endpoint  `yaml:"endpoint" json:"endpoint"`
	Role        string          `yaml:"role" json:"role"` // setup, attack, verify
	ExtractVars []Extraction    `yaml:"extract_vars,omitempty" json:"extract_vars,omitempty"`
	InjectVars  []string        `yaml:"inject_vars,omitempty" json:"inject_vars,omitempty"`
	Conditions  []Condition     `yaml:"conditions,omitempty" json:"conditions,omitempty"`
	Payloads    []StepPayload   `yaml:"payloads,omitempty" json:"payloads,omitempty"`
	Timeout     int             `yaml:"timeout,omitempty" json:"timeout,omitempty"` // seconds
	Required    bool            `yaml:"required" json:"required"`
	Order       int             `yaml:"order" json:"order"`
}

// Extraction defines how to extract data from a response
type Extraction struct {
	Name       string `yaml:"name" json:"name"`
	Type       string `yaml:"type" json:"type"`       // json, regex, header, cookie
	Path       string `yaml:"path" json:"path"`       // JSONPath or header name
	Pattern    string `yaml:"pattern" json:"pattern"` // Regex pattern
	SaveAs     string `yaml:"save_as" json:"save_as"`
	Required   bool   `yaml:"required" json:"required"`
	Default    string `yaml:"default,omitempty" json:"default,omitempty"`
}

// Condition defines a condition for execution
type Condition struct {
	Type     string `yaml:"type" json:"type"` // status_code, contains, matches, exists
	Field    string `yaml:"field" json:"field"`
	Operator string `yaml:"operator" json:"operator"` // eq, ne, gt, lt, contains, matches
	Value    string `yaml:"value" json:"value"`
	Negate   bool   `yaml:"negate,omitempty" json:"negate,omitempty"`
}

// StepPayload defines a payload to use in a step
type StepPayload struct {
	Target    string `yaml:"target" json:"target"`       // Parameter to inject into
	Value     string `yaml:"value" json:"value"`         // Payload value (can include {{vars}})
	Type      string `yaml:"type" json:"type"`           // Attack type
	Position  string `yaml:"position" json:"position"`   // query, path, header, body
}

// ChainResult represents the result of executing a chain
type ChainResult struct {
	Chain        *AttackChain             `json:"chain"`
	Success      bool                     `json:"success"`
	StepResults  []ChainStepResult        `json:"step_results"`
	Findings     []types.Finding          `json:"findings"`
	Variables    map[string]string        `json:"variables"`
	FailedAtStep int                      `json:"failed_at_step,omitempty"`
	Error        string                   `json:"error,omitempty"`
}

// ChainStepResult represents the result of a single step
type ChainStepResult struct {
	Step           *ChainStep        `json:"step"`
	Success        bool              `json:"success"`
	Response       *types.HTTPResponse `json:"response,omitempty"`
	ExtractedVars  map[string]string `json:"extracted_vars"`
	ConditionsMet  bool              `json:"conditions_met"`
	Error          string            `json:"error,omitempty"`
}

// ChainPurpose constants
const (
	PurposePrivilegeEscalation = "privilege_escalation"
	PurposeDataLeakage         = "data_leakage"
	PurposeAuthBypass          = "auth_bypass"
	PurposeIDOR                = "idor"
	PurposeBOLA                = "bola"
	PurposeBFLA                = "bfla"
	PurposeAccountTakeover     = "account_takeover"
	PurposeMassAssignment      = "mass_assignment"
)

// ChainRole constants
const (
	RoleSetup    = "setup"    // Prepare state for attack
	RoleAttack   = "attack"   // Execute the attack
	RoleVerify   = "verify"   // Verify attack success
	RoleCleanup  = "cleanup"  // Clean up after attack
)

// ConditionType constants
const (
	ConditionStatusCode = "status_code"
	ConditionContains   = "contains"
	ConditionMatches    = "matches"
	ConditionExists     = "exists"
	ConditionHeader     = "header"
	ConditionJSON       = "json"
)

// OperatorType constants
const (
	OperatorEq       = "eq"
	OperatorNe       = "ne"
	OperatorGt       = "gt"
	OperatorLt       = "lt"
	OperatorGte      = "gte"
	OperatorLte      = "lte"
	OperatorContains = "contains"
	OperatorMatches  = "matches"
)

// NewAttackChain creates a new attack chain
func NewAttackChain(id, name, purpose string) *AttackChain {
	return &AttackChain{
		ID:       id,
		Name:     name,
		Purpose:  purpose,
		Steps:    make([]ChainStep, 0),
		Priority: "medium",
	}
}

// AddStep adds a step to the chain
func (c *AttackChain) AddStep(step ChainStep) {
	step.Order = len(c.Steps)
	c.Steps = append(c.Steps, step)
}

// Validate validates the chain configuration
func (c *AttackChain) Validate() error {
	if c.ID == "" {
		return &ChainError{Message: "chain ID is required"}
	}
	if c.Name == "" {
		return &ChainError{Message: "chain name is required"}
	}
	if len(c.Steps) == 0 {
		return &ChainError{Message: "chain must have at least one step"}
	}
	return nil
}

// ChainError represents a chain-related error
type ChainError struct {
	Message string
	Step    int
}

func (e *ChainError) Error() string {
	if e.Step > 0 {
		return e.Message + " at step " + string(rune(e.Step))
	}
	return e.Message
}

// PredefinedChains returns commonly used attack chains
func PredefinedChains() []*AttackChain {
	return []*AttackChain{
		createPrivilegeEscalationChain(),
		createIDORChain(),
		createAccountTakeoverChain(),
		createMassAssignmentChain(),
	}
}

func createPrivilegeEscalationChain() *AttackChain {
	return &AttackChain{
		ID:          "priv-esc-user-to-admin",
		Name:        "User to Admin Privilege Escalation",
		Description: "Attempts to escalate from regular user to admin privileges",
		Purpose:     PurposePrivilegeEscalation,
		Category:    "authorization",
		Priority:    "high",
		Steps: []ChainStep{
			{
				ID:       "login",
				Name:     "Authenticate as regular user",
				Role:     RoleSetup,
				Required: true,
				ExtractVars: []Extraction{
					{Name: "token", Type: "json", Path: "$.token", SaveAs: "user_token", Required: true},
					{Name: "user_id", Type: "json", Path: "$.user.id", SaveAs: "user_id", Required: false},
				},
			},
			{
				ID:       "access_admin",
				Name:     "Attempt to access admin endpoint",
				Role:     RoleAttack,
				Required: true,
				InjectVars: []string{"user_token"},
			},
			{
				ID:       "modify_role",
				Name:     "Attempt to modify user role",
				Role:     RoleAttack,
				Required: false,
				InjectVars: []string{"user_token", "user_id"},
				Payloads: []StepPayload{
					{Target: "role", Value: "admin", Type: "mass_assignment", Position: "body"},
					{Target: "is_admin", Value: "true", Type: "mass_assignment", Position: "body"},
				},
			},
			{
				ID:       "verify_escalation",
				Name:     "Verify privilege escalation",
				Role:     RoleVerify,
				Required: true,
				InjectVars: []string{"user_token"},
				Conditions: []Condition{
					{Type: ConditionStatusCode, Operator: OperatorEq, Value: "200"},
				},
			},
		},
	}
}

func createIDORChain() *AttackChain {
	return &AttackChain{
		ID:          "idor-horizontal",
		Name:        "Horizontal IDOR Attack",
		Description: "Access another user's resources by manipulating IDs",
		Purpose:     PurposeIDOR,
		Category:    "authorization",
		Priority:    "high",
		Steps: []ChainStep{
			{
				ID:       "get_own_resource",
				Name:     "Retrieve own resource",
				Role:     RoleSetup,
				Required: true,
				ExtractVars: []Extraction{
					{Name: "resource_id", Type: "json", Path: "$.id", SaveAs: "own_resource_id", Required: true},
				},
			},
			{
				ID:       "enumerate_ids",
				Name:     "Enumerate potential resource IDs",
				Role:     RoleSetup,
				Required: false,
			},
			{
				ID:       "access_other_resource",
				Name:     "Attempt to access other user's resource",
				Role:     RoleAttack,
				Required: true,
				Payloads: []StepPayload{
					{Target: "id", Value: "{{own_resource_id}}-1", Type: "idor", Position: "path"},
					{Target: "id", Value: "{{own_resource_id}}+1", Type: "idor", Position: "path"},
				},
			},
		},
	}
}

func createAccountTakeoverChain() *AttackChain {
	return &AttackChain{
		ID:          "account-takeover",
		Name:        "Account Takeover via Password Reset",
		Description: "Attempt to take over another account via password reset flow",
		Purpose:     PurposeAccountTakeover,
		Category:    "authentication",
		Priority:    "critical",
		Steps: []ChainStep{
			{
				ID:       "request_reset",
				Name:     "Request password reset for target",
				Role:     RoleSetup,
				Required: true,
				ExtractVars: []Extraction{
					{Name: "reset_token", Type: "json", Path: "$.token", SaveAs: "reset_token", Required: false},
				},
			},
			{
				ID:       "manipulate_token",
				Name:     "Attempt to manipulate reset token",
				Role:     RoleAttack,
				Required: true,
				Payloads: []StepPayload{
					{Target: "token", Value: "{{reset_token}}", Type: "auth_bypass", Position: "query"},
				},
			},
			{
				ID:       "reset_password",
				Name:     "Attempt to reset password with manipulated token",
				Role:     RoleAttack,
				Required: true,
			},
		},
	}
}

func createMassAssignmentChain() *AttackChain {
	return &AttackChain{
		ID:          "mass-assignment",
		Name:        "Mass Assignment Attack",
		Description: "Attempt to modify protected fields via mass assignment",
		Purpose:     PurposeMassAssignment,
		Category:    "authorization",
		Priority:    "high",
		Steps: []ChainStep{
			{
				ID:       "get_current_state",
				Name:     "Get current object state",
				Role:     RoleSetup,
				Required: true,
				ExtractVars: []Extraction{
					{Name: "object_id", Type: "json", Path: "$.id", SaveAs: "object_id", Required: true},
				},
			},
			{
				ID:       "inject_fields",
				Name:     "Inject protected fields",
				Role:     RoleAttack,
				Required: true,
				InjectVars: []string{"object_id"},
				Payloads: []StepPayload{
					{Target: "role", Value: "admin", Type: "mass_assignment", Position: "body"},
					{Target: "is_admin", Value: "true", Type: "mass_assignment", Position: "body"},
					{Target: "permissions", Value: "[\"all\"]", Type: "mass_assignment", Position: "body"},
					{Target: "balance", Value: "999999", Type: "mass_assignment", Position: "body"},
					{Target: "verified", Value: "true", Type: "mass_assignment", Position: "body"},
				},
			},
			{
				ID:       "verify_change",
				Name:     "Verify field was modified",
				Role:     RoleVerify,
				Required: true,
				InjectVars: []string{"object_id"},
			},
		},
	}
}
