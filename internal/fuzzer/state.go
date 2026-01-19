// Package fuzzer provides the core fuzzing engine
package fuzzer

import (
	"encoding/json"
	"regexp"
	"strings"
	"sync"
)

// StateTracker manages stateful session data across requests
type StateTracker struct {
	mu        sync.RWMutex
	variables map[string]string
	cookies   map[string]string
	tokens    map[string]string
	resources map[string][]string // Maps resource types to lists of IDs
	history   []StateChange
	maxHistory int
}

// StateChange represents a change in state
type StateChange struct {
	Action   string // "set", "delete", "extract"
	Key      string
	Value    string
	Source   string // Where it came from (e.g., "response_body", "header")
	Endpoint string
}

// NewStateTracker creates a new state tracker
func NewStateTracker() *StateTracker {
	return &StateTracker{
		variables:  make(map[string]string),
		cookies:    make(map[string]string),
		tokens:     make(map[string]string),
		resources:  make(map[string][]string),
		history:    make([]StateChange, 0),
		maxHistory: 1000,
	}
}

// SetVariable sets a state variable
func (st *StateTracker) SetVariable(name, value string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.variables[name] = value
	st.addHistory("set", name, value, "manual")
}

// GetVariable gets a state variable
func (st *StateTracker) GetVariable(name string) (string, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	val, ok := st.variables[name]
	return val, ok
}

// SetCookie sets a cookie
func (st *StateTracker) SetCookie(name, value string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.cookies[name] = value
	st.addHistory("set", "cookie:"+name, value, "cookie")
}

// GetCookie gets a cookie
func (st *StateTracker) GetCookie(name string) (string, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	val, ok := st.cookies[name]
	return val, ok
}

// GetAllCookies returns all cookies
func (st *StateTracker) GetAllCookies() map[string]string {
	st.mu.RLock()
	defer st.mu.RUnlock()
	cookies := make(map[string]string)
	for k, v := range st.cookies {
		cookies[k] = v
	}
	return cookies
}

// SetToken sets an authentication token
func (st *StateTracker) SetToken(tokenType, value string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.tokens[tokenType] = value
	st.addHistory("set", "token:"+tokenType, value, "auth")
}

// GetToken gets an authentication token
func (st *StateTracker) GetToken(tokenType string) (string, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	val, ok := st.tokens[tokenType]
	return val, ok
}

// AddResource adds a discovered resource ID
func (st *StateTracker) AddResource(resourceType, id string) {
	st.mu.Lock()
	defer st.mu.Unlock()

	// Avoid duplicates
	for _, existing := range st.resources[resourceType] {
		if existing == id {
			return
		}
	}
	st.resources[resourceType] = append(st.resources[resourceType], id)
	st.addHistory("set", "resource:"+resourceType, id, "discovery")
}

// GetResources gets all discovered resources of a type
func (st *StateTracker) GetResources(resourceType string) []string {
	st.mu.RLock()
	defer st.mu.RUnlock()

	if resources, ok := st.resources[resourceType]; ok {
		result := make([]string, len(resources))
		copy(result, resources)
		return result
	}
	return nil
}

// GetLatestResource gets the most recently discovered resource of a type
func (st *StateTracker) GetLatestResource(resourceType string) (string, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()

	if resources, ok := st.resources[resourceType]; ok && len(resources) > 0 {
		return resources[len(resources)-1], true
	}
	return "", false
}

// SubstituteVariables replaces {{varname}} placeholders in a string
func (st *StateTracker) SubstituteVariables(input string) string {
	st.mu.RLock()
	defer st.mu.RUnlock()

	// Pattern: {{variable_name}}
	re := regexp.MustCompile(`\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}`)

	return re.ReplaceAllStringFunc(input, func(match string) string {
		// Extract variable name from {{name}}
		varName := match[2 : len(match)-2]

		// Check variables first
		if val, ok := st.variables[varName]; ok {
			return val
		}

		// Check tokens
		if val, ok := st.tokens[varName]; ok {
			return val
		}

		// Check for resource:type pattern
		if strings.HasPrefix(varName, "resource_") {
			resourceType := strings.TrimPrefix(varName, "resource_")
			if resources, ok := st.resources[resourceType]; ok && len(resources) > 0 {
				return resources[len(resources)-1]
			}
		}

		// Return original if not found
		return match
	})
}

// HasUnresolvedVariables checks if a string has unresolved variables
func (st *StateTracker) HasUnresolvedVariables(input string) bool {
	re := regexp.MustCompile(`\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}`)
	return re.MatchString(st.SubstituteVariables(input))
}

// GetAllVariables returns all variables
func (st *StateTracker) GetAllVariables() map[string]string {
	st.mu.RLock()
	defer st.mu.RUnlock()

	vars := make(map[string]string)
	for k, v := range st.variables {
		vars[k] = v
	}
	return vars
}

// Clear clears all state
func (st *StateTracker) Clear() {
	st.mu.Lock()
	defer st.mu.Unlock()

	st.variables = make(map[string]string)
	st.cookies = make(map[string]string)
	st.tokens = make(map[string]string)
	st.resources = make(map[string][]string)
	st.history = make([]StateChange, 0)
}

// Clone creates a copy of the state tracker
func (st *StateTracker) Clone() *StateTracker {
	st.mu.RLock()
	defer st.mu.RUnlock()

	clone := NewStateTracker()

	for k, v := range st.variables {
		clone.variables[k] = v
	}
	for k, v := range st.cookies {
		clone.cookies[k] = v
	}
	for k, v := range st.tokens {
		clone.tokens[k] = v
	}
	for k, v := range st.resources {
		resourcesCopy := make([]string, len(v))
		copy(resourcesCopy, v)
		clone.resources[k] = resourcesCopy
	}

	return clone
}

// GetHistory returns state change history
func (st *StateTracker) GetHistory() []StateChange {
	st.mu.RLock()
	defer st.mu.RUnlock()

	history := make([]StateChange, len(st.history))
	copy(history, st.history)
	return history
}

// addHistory adds an entry to history (must be called with lock held)
func (st *StateTracker) addHistory(action, key, value, source string) {
	if len(st.history) >= st.maxHistory {
		// Remove oldest entries
		st.history = st.history[100:]
	}
	st.history = append(st.history, StateChange{
		Action: action,
		Key:    key,
		Value:  value,
		Source: source,
	})
}

// ImportFromJSON imports state from JSON
func (st *StateTracker) ImportFromJSON(data []byte) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	var imported struct {
		Variables map[string]string   `json:"variables"`
		Cookies   map[string]string   `json:"cookies"`
		Tokens    map[string]string   `json:"tokens"`
		Resources map[string][]string `json:"resources"`
	}

	if err := json.Unmarshal(data, &imported); err != nil {
		return err
	}

	for k, v := range imported.Variables {
		st.variables[k] = v
	}
	for k, v := range imported.Cookies {
		st.cookies[k] = v
	}
	for k, v := range imported.Tokens {
		st.tokens[k] = v
	}
	for k, v := range imported.Resources {
		st.resources[k] = v
	}

	return nil
}

// ExportToJSON exports state to JSON
func (st *StateTracker) ExportToJSON() ([]byte, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()

	export := struct {
		Variables map[string]string   `json:"variables"`
		Cookies   map[string]string   `json:"cookies"`
		Tokens    map[string]string   `json:"tokens"`
		Resources map[string][]string `json:"resources"`
	}{
		Variables: st.variables,
		Cookies:   st.cookies,
		Tokens:    st.tokens,
		Resources: st.resources,
	}

	return json.MarshalIndent(export, "", "  ")
}
