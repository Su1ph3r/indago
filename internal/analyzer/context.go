package analyzer

import (
	"regexp"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// ContextExtractor extracts context from endpoints without LLM
type ContextExtractor struct{}

// NewContextExtractor creates a new context extractor
func NewContextExtractor() *ContextExtractor {
	return &ContextExtractor{}
}

// ExtractContext extracts context from endpoints using heuristics
func (e *ContextExtractor) ExtractContext(endpoints []types.Endpoint) *APIContext {
	ctx := &APIContext{
		Domain:            e.inferDomain(endpoints),
		AuthEndpoints:     e.findAuthEndpoints(endpoints),
		CRUDGroups:        e.identifyCRUDGroups(endpoints),
		IDORCandidates:    e.findIDORCandidates(endpoints),
		SensitiveEndpoints: e.findSensitiveEndpoints(endpoints),
	}
	return ctx
}

// APIContext contains extracted API context
type APIContext struct {
	Domain             string
	AuthEndpoints      []types.Endpoint
	CRUDGroups         map[string][]types.Endpoint
	IDORCandidates     []types.Endpoint
	SensitiveEndpoints []types.Endpoint
}

// inferDomain tries to infer the API domain from endpoints
func (e *ContextExtractor) inferDomain(endpoints []types.Endpoint) string {
	// Count path segments to identify domain
	segments := make(map[string]int)

	for _, ep := range endpoints {
		parts := strings.Split(strings.Trim(ep.Path, "/"), "/")
		if len(parts) > 0 {
			// Skip version prefixes
			seg := parts[0]
			if !strings.HasPrefix(seg, "v") || len(seg) > 3 {
				segments[seg]++
			} else if len(parts) > 1 {
				segments[parts[1]]++
			}
		}
	}

	// Find most common segment
	maxCount := 0
	domain := "api"
	for seg, count := range segments {
		if count > maxCount {
			maxCount = count
			domain = seg
		}
	}

	return domain
}

// findAuthEndpoints identifies authentication-related endpoints
func (e *ContextExtractor) findAuthEndpoints(endpoints []types.Endpoint) []types.Endpoint {
	var authEndpoints []types.Endpoint

	authPatterns := []string{
		"login", "logout", "auth", "signin", "signout", "signup",
		"register", "password", "token", "oauth", "session",
		"verify", "confirm", "reset", "forgot", "2fa", "mfa",
	}

	for _, ep := range endpoints {
		pathLower := strings.ToLower(ep.Path)
		for _, pattern := range authPatterns {
			if strings.Contains(pathLower, pattern) {
				authEndpoints = append(authEndpoints, ep)
				break
			}
		}
	}

	return authEndpoints
}

// identifyCRUDGroups groups endpoints by resource
func (e *ContextExtractor) identifyCRUDGroups(endpoints []types.Endpoint) map[string][]types.Endpoint {
	groups := make(map[string][]types.Endpoint)

	// Pattern to match resource paths like /users/{id} or /users/:id
	resourcePattern := regexp.MustCompile(`^/([^/]+)(?:/\{[^}]+\}|/:[^/]+)?$`)

	for _, ep := range endpoints {
		matches := resourcePattern.FindStringSubmatch(ep.Path)
		if len(matches) > 1 {
			resource := matches[1]
			groups[resource] = append(groups[resource], ep)
		} else {
			// Try to extract first path segment
			parts := strings.Split(strings.Trim(ep.Path, "/"), "/")
			if len(parts) > 0 {
				resource := parts[0]
				groups[resource] = append(groups[resource], ep)
			}
		}
	}

	return groups
}

// findIDORCandidates finds endpoints likely vulnerable to IDOR
func (e *ContextExtractor) findIDORCandidates(endpoints []types.Endpoint) []types.Endpoint {
	var candidates []types.Endpoint

	// Patterns that suggest IDOR vulnerability
	idPatterns := []string{
		"id", "user_id", "userid", "user-id",
		"account_id", "accountid", "account-id",
		"order_id", "orderid", "order-id",
		"document_id", "doc_id", "file_id",
		"profile_id", "customer_id", "member_id",
	}

	// Path patterns with IDs
	pathIDPattern := regexp.MustCompile(`/\{([^}]+)\}|/:([^/]+)`)

	for _, ep := range endpoints {
		isCandidate := false

		// Check path for ID parameters
		if pathIDPattern.MatchString(ep.Path) {
			matches := pathIDPattern.FindStringSubmatch(ep.Path)
			for _, m := range matches {
				mLower := strings.ToLower(m)
				for _, pattern := range idPatterns {
					if strings.Contains(mLower, pattern) {
						isCandidate = true
						break
					}
				}
			}
		}

		// Check query/body parameters
		for _, param := range ep.Parameters {
			nameLower := strings.ToLower(param.Name)
			for _, pattern := range idPatterns {
				if strings.Contains(nameLower, pattern) {
					isCandidate = true
					break
				}
			}
		}

		// Check for numeric ID in path
		if regexp.MustCompile(`/\d+`).MatchString(ep.Path) {
			isCandidate = true
		}

		if isCandidate {
			candidates = append(candidates, ep)
		}
	}

	return candidates
}

// findSensitiveEndpoints finds potentially sensitive endpoints
func (e *ContextExtractor) findSensitiveEndpoints(endpoints []types.Endpoint) []types.Endpoint {
	var sensitive []types.Endpoint

	sensitivePatterns := []string{
		"admin", "config", "setting", "secret",
		"payment", "billing", "invoice", "credit",
		"password", "credential", "key", "token",
		"export", "download", "backup", "dump",
		"delete", "remove", "purge", "destroy",
		"internal", "private", "debug", "test",
		"ssn", "social", "tax", "bank",
		"health", "medical", "diagnosis",
		"pii", "personal", "sensitive",
	}

	for _, ep := range endpoints {
		pathLower := strings.ToLower(ep.Path)
		descLower := strings.ToLower(ep.Description)

		for _, pattern := range sensitivePatterns {
			if strings.Contains(pathLower, pattern) || strings.Contains(descLower, pattern) {
				sensitive = append(sensitive, ep)
				break
			}
		}

		// DELETE methods on important resources are sensitive
		if ep.Method == "DELETE" {
			sensitive = append(sensitive, ep)
		}
	}

	return sensitive
}

// ClassifyEndpoint classifies an endpoint's sensitivity without LLM
func (e *ContextExtractor) ClassifyEndpoint(ep types.Endpoint) string {
	pathLower := strings.ToLower(ep.Path)

	// Critical
	criticalPatterns := []string{"admin", "config", "secret", "credential", "internal"}
	for _, p := range criticalPatterns {
		if strings.Contains(pathLower, p) {
			return types.SensitivityCritical
		}
	}

	// High
	highPatterns := []string{"payment", "billing", "password", "token", "key", "personal"}
	for _, p := range highPatterns {
		if strings.Contains(pathLower, p) {
			return types.SensitivityHigh
		}
	}

	// Medium - data modification endpoints
	if ep.Method == "POST" || ep.Method == "PUT" || ep.Method == "PATCH" || ep.Method == "DELETE" {
		return types.SensitivityMedium
	}

	return types.SensitivityLow
}

// SuggestAttacksHeuristic suggests attacks based on heuristics
func (e *ContextExtractor) SuggestAttacksHeuristic(ep types.Endpoint) []types.AttackVector {
	var attacks []types.AttackVector

	// Check for IDOR
	if e.hasIDParameter(ep) {
		attacks = append(attacks, types.AttackVector{
			Type:     types.AttackIDOR,
			Category: "authorization",
			Priority: "high",
			Rationale: "Endpoint has ID parameter that may reference user-specific data",
		})
	}

	// Check for injection points
	for _, param := range ep.Parameters {
		if param.Type == "string" {
			attacks = append(attacks, types.AttackVector{
				Type:        types.AttackSQLi,
				Category:    "injection",
				Priority:    "medium",
				Rationale:   "String parameter may be vulnerable to SQL injection",
				TargetParam: types.FlexibleString(param.Name),
			})
		}
	}

	// Check for mass assignment
	if (ep.Method == "POST" || ep.Method == "PUT" || ep.Method == "PATCH") && ep.Body != nil {
		attacks = append(attacks, types.AttackVector{
			Type:     types.AttackMassAssignment,
			Category: "authorization",
			Priority: "medium",
			Rationale: "Write endpoint may accept unintended fields",
		})
	}

	// Check for auth bypass on sensitive endpoints
	if e.isSensitive(ep) && ep.Auth != nil {
		attacks = append(attacks, types.AttackVector{
			Type:     types.AttackAuthBypass,
			Category: "authentication",
			Priority: "high",
			Rationale: "Sensitive endpoint requires auth - test bypass",
		})
	}

	return attacks
}

// hasIDParameter checks if endpoint has an ID-like parameter
func (e *ContextExtractor) hasIDParameter(ep types.Endpoint) bool {
	idPatterns := []string{"id", "_id", "-id", "Id"}

	// Check path
	for _, pattern := range idPatterns {
		if strings.Contains(strings.ToLower(ep.Path), pattern) {
			return true
		}
	}

	// Check parameters
	for _, param := range ep.Parameters {
		for _, pattern := range idPatterns {
			if strings.Contains(strings.ToLower(param.Name), pattern) {
				return true
			}
		}
	}

	return false
}

// isSensitive checks if an endpoint appears sensitive
func (e *ContextExtractor) isSensitive(ep types.Endpoint) bool {
	sensitivePatterns := []string{
		"admin", "payment", "password", "personal", "private",
	}

	pathLower := strings.ToLower(ep.Path)
	for _, p := range sensitivePatterns {
		if strings.Contains(pathLower, p) {
			return true
		}
	}

	return false
}
