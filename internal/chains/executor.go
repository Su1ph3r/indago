// Package chains provides multi-step attack chain functionality
package chains

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/su1ph3r/indago/internal/fuzzer"
	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

// Executor executes attack chains
type Executor struct {
	engine      *fuzzer.Engine
	stateTracker *fuzzer.StateTracker
	maxDepth    int
	timeout     time.Duration
}

// ExecutorConfig holds executor configuration
type ExecutorConfig struct {
	MaxDepth int
	Timeout  time.Duration
}

// NewExecutor creates a new chain executor
func NewExecutor(engine *fuzzer.Engine, config ExecutorConfig) *Executor {
	if config.MaxDepth <= 0 {
		config.MaxDepth = 5
	}
	if config.Timeout <= 0 {
		config.Timeout = 5 * time.Minute
	}

	return &Executor{
		engine:       engine,
		stateTracker: fuzzer.NewStateTracker(),
		maxDepth:     config.MaxDepth,
		timeout:      config.Timeout,
	}
}

// Execute executes a single attack chain
func (e *Executor) Execute(ctx context.Context, chain *AttackChain) *ChainResult {
	result := &ChainResult{
		Chain:       chain,
		StepResults: make([]ChainStepResult, 0, len(chain.Steps)),
		Variables:   make(map[string]string),
		Success:     false,
	}

	// Set up timeout
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	// Execute each step in order
	for i, step := range chain.Steps {
		select {
		case <-ctx.Done():
			result.Error = "chain execution timed out"
			result.FailedAtStep = i
			return result
		default:
		}

		stepResult := e.executeStep(ctx, &step, result.Variables)
		result.StepResults = append(result.StepResults, stepResult)

		// Merge extracted variables
		for k, v := range stepResult.ExtractedVars {
			result.Variables[k] = v
			e.stateTracker.SetVariable(k, v)
		}

		// Check if step failed
		if !stepResult.Success {
			if step.Required {
				result.FailedAtStep = i
				result.Error = stepResult.Error
				return result
			}
			// Non-required step failed, continue
		}

		// Generate findings from step
		if stepResult.Success && step.Role == RoleAttack {
			findings := e.generateStepFindings(chain, &step, &stepResult)
			result.Findings = append(result.Findings, findings...)
		}
	}

	// Chain completed successfully if we got here
	result.Success = true

	// Generate chain-level findings
	chainFindings := e.generateChainFindings(chain, result)
	result.Findings = append(result.Findings, chainFindings...)

	return result
}

// executeStep executes a single step in the chain
func (e *Executor) executeStep(ctx context.Context, step *ChainStep, variables map[string]string) ChainStepResult {
	result := ChainStepResult{
		Step:          step,
		ExtractedVars: make(map[string]string),
		Success:       false,
	}

	// Set up step timeout
	timeout := time.Duration(step.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Prepare the endpoint with variable substitution
	endpoint := e.prepareEndpoint(step.Endpoint, variables)

	// If step has payloads, execute with each payload
	if len(step.Payloads) > 0 {
		for _, payload := range step.Payloads {
			// Substitute variables in payload value
			payloadValue := e.substituteVariables(payload.Value, variables)

			fuzzReq := payloads.FuzzRequest{
				Endpoint: endpoint,
				Param: &types.Parameter{
					Name: payload.Target,
					In:   payload.Position,
				},
				Payload: payloads.Payload{
					Value: payloadValue,
					Type:  payload.Type,
				},
				Position: payload.Position,
			}

			resp := e.executeRequest(ctx, fuzzReq)
			if resp != nil {
				result.Response = resp
				result.Success = true

				// Extract variables
				for _, extraction := range step.ExtractVars {
					value := e.extractValue(resp, extraction)
					if value != "" {
						result.ExtractedVars[extraction.SaveAs] = value
					} else if extraction.Required {
						result.Success = false
						result.Error = "required extraction failed: " + extraction.Name
						return result
					} else if extraction.Default != "" {
						result.ExtractedVars[extraction.SaveAs] = extraction.Default
					}
				}

				// Check conditions
				result.ConditionsMet = e.checkConditions(step.Conditions, resp)
				if !result.ConditionsMet && len(step.Conditions) > 0 {
					result.Success = false
					result.Error = "conditions not met"
				}

				return result
			}
		}
	} else {
		// Execute without payload (setup/verify step)
		fuzzReq := payloads.FuzzRequest{
			Endpoint: endpoint,
		}

		resp := e.executeRequest(ctx, fuzzReq)
		if resp != nil {
			result.Response = resp
			result.Success = true

			// Extract variables
			for _, extraction := range step.ExtractVars {
				value := e.extractValue(resp, extraction)
				if value != "" {
					result.ExtractedVars[extraction.SaveAs] = value
				} else if extraction.Required {
					result.Success = false
					result.Error = "required extraction failed: " + extraction.Name
					return result
				} else if extraction.Default != "" {
					result.ExtractedVars[extraction.SaveAs] = extraction.Default
				}
			}

			// Check conditions
			result.ConditionsMet = e.checkConditions(step.Conditions, resp)
			if !result.ConditionsMet && len(step.Conditions) > 0 {
				result.Success = false
				result.Error = "conditions not met"
			}

			return result
		}
	}

	result.Error = "no response received"
	return result
}

// executeRequest executes a fuzzer request
func (e *Executor) executeRequest(ctx context.Context, req payloads.FuzzRequest) *types.HTTPResponse {
	results := e.engine.Fuzz(ctx, []payloads.FuzzRequest{req})

	for result := range results {
		if result.Error == nil && result.Response != nil {
			return result.Response
		}
	}

	return nil
}

// prepareEndpoint prepares an endpoint with variable substitution
func (e *Executor) prepareEndpoint(endpoint types.Endpoint, variables map[string]string) types.Endpoint {
	prepared := endpoint

	// Substitute in path
	prepared.Path = e.substituteVariables(prepared.Path, variables)

	// Substitute in headers
	if prepared.Headers != nil {
		newHeaders := make(map[string]string)
		for k, v := range prepared.Headers {
			newHeaders[k] = e.substituteVariables(v, variables)
		}
		prepared.Headers = newHeaders
	}

	// Substitute in parameters
	for i := range prepared.Parameters {
		if str, ok := prepared.Parameters[i].Example.(string); ok {
			prepared.Parameters[i].Example = e.substituteVariables(str, variables)
		}
	}

	return prepared
}

// substituteVariables replaces {{varname}} with actual values
func (e *Executor) substituteVariables(input string, variables map[string]string) string {
	re := regexp.MustCompile(`\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}`)

	return re.ReplaceAllStringFunc(input, func(match string) string {
		varName := match[2 : len(match)-2]
		if val, ok := variables[varName]; ok {
			return val
		}
		// Try state tracker
		if val, ok := e.stateTracker.GetVariable(varName); ok {
			return val
		}
		return match
	})
}

// extractValue extracts a value from a response
func (e *Executor) extractValue(resp *types.HTTPResponse, extraction Extraction) string {
	switch extraction.Type {
	case "json":
		return e.extractJSON(resp.Body, extraction.Path)
	case "regex":
		return e.extractRegex(resp.Body, extraction.Pattern)
	case "header":
		return resp.Headers[extraction.Path]
	case "cookie":
		return e.extractCookie(resp.Headers, extraction.Path)
	default:
		return ""
	}
}

// extractJSON extracts a value using simple JSONPath
func (e *Executor) extractJSON(body, path string) string {
	if body == "" || path == "" {
		return ""
	}

	var data interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return ""
	}

	// Simple JSONPath: $.field or $.field.nested
	parts := strings.Split(strings.TrimPrefix(path, "$."), ".")
	current := data

	for _, part := range parts {
		if part == "" {
			continue
		}

		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		case []interface{}:
			if idx, err := strconv.Atoi(part); err == nil && idx < len(v) {
				current = v[idx]
			} else if len(v) > 0 {
				if m, ok := v[0].(map[string]interface{}); ok {
					current = m[part]
				}
			}
		default:
			return ""
		}
	}

	switch v := current.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%v", v)
	case bool:
		return fmt.Sprintf("%t", v)
	default:
		if current != nil {
			if b, err := json.Marshal(current); err == nil {
				return string(b)
			}
		}
		return ""
	}
}

// extractRegex extracts a value using regex
func (e *Executor) extractRegex(body, pattern string) string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}

	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}

// extractCookie extracts a cookie value
func (e *Executor) extractCookie(headers map[string]string, cookieName string) string {
	for k, v := range headers {
		if strings.EqualFold(k, "Set-Cookie") {
			parts := strings.Split(v, ";")
			if len(parts) > 0 {
				cookieParts := strings.SplitN(parts[0], "=", 2)
				if len(cookieParts) == 2 && strings.TrimSpace(cookieParts[0]) == cookieName {
					return strings.TrimSpace(cookieParts[1])
				}
			}
		}
	}
	return ""
}

// checkConditions checks if all conditions are met
func (e *Executor) checkConditions(conditions []Condition, resp *types.HTTPResponse) bool {
	for _, cond := range conditions {
		met := e.checkCondition(cond, resp)
		if cond.Negate {
			met = !met
		}
		if !met {
			return false
		}
	}
	return true
}

// checkCondition checks a single condition
func (e *Executor) checkCondition(cond Condition, resp *types.HTTPResponse) bool {
	var value string

	switch cond.Type {
	case ConditionStatusCode:
		value = fmt.Sprintf("%d", resp.StatusCode)
	case ConditionHeader:
		value = resp.Headers[cond.Field]
	case ConditionContains:
		return strings.Contains(resp.Body, cond.Value)
	case ConditionMatches:
		re, err := regexp.Compile(cond.Value)
		if err != nil {
			return false
		}
		return re.MatchString(resp.Body)
	case ConditionExists:
		return strings.Contains(resp.Body, cond.Field)
	case ConditionJSON:
		value = e.extractJSON(resp.Body, cond.Field)
	default:
		return false
	}

	switch cond.Operator {
	case OperatorEq:
		return value == cond.Value
	case OperatorNe:
		return value != cond.Value
	case OperatorGt:
		v1, _ := strconv.Atoi(value)
		v2, _ := strconv.Atoi(cond.Value)
		return v1 > v2
	case OperatorLt:
		v1, _ := strconv.Atoi(value)
		v2, _ := strconv.Atoi(cond.Value)
		return v1 < v2
	case OperatorContains:
		return strings.Contains(value, cond.Value)
	case OperatorMatches:
		re, err := regexp.Compile(cond.Value)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	default:
		return value == cond.Value
	}
}

// generateStepFindings generates findings from a successful attack step
func (e *Executor) generateStepFindings(chain *AttackChain, step *ChainStep, result *ChainStepResult) []types.Finding {
	var findings []types.Finding

	if result.Response == nil {
		return findings
	}

	// Check for common vulnerability indicators
	if result.Response.StatusCode >= 200 && result.Response.StatusCode < 300 {
		for _, payload := range step.Payloads {
			// Create finding for successful attack payload
			severity := types.SeverityMedium
			if chain.Priority == "critical" || chain.Priority == "high" {
				severity = types.SeverityHigh
			}

			finding := types.Finding{
				ID:          fmt.Sprintf("%s-%s-%d", chain.ID, step.ID, time.Now().UnixNano()),
				Type:        chain.Purpose,
				Severity:    severity,
				Confidence:  types.ConfidenceMedium,
				Title:       fmt.Sprintf("%s: %s", chain.Name, step.Name),
				Description: fmt.Sprintf("Attack chain step succeeded: %s", step.Name),
				Endpoint:    step.Endpoint.Path,
				Method:      step.Endpoint.Method,
				Parameter:   payload.Target,
				Payload:     payload.Value,
				Tags:        append(chain.Tags, "chain:"+chain.ID),
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// generateChainFindings generates findings for a completed chain
func (e *Executor) generateChainFindings(chain *AttackChain, result *ChainResult) []types.Finding {
	var findings []types.Finding

	if !result.Success {
		return findings
	}

	// Generate a finding for the completed chain
	severity := types.SeverityHigh
	if chain.Priority == "critical" {
		severity = types.SeverityCritical
	}

	finding := types.Finding{
		ID:          fmt.Sprintf("chain-%s-%d", chain.ID, time.Now().UnixNano()),
		Type:        chain.Purpose,
		Severity:    severity,
		Confidence:  types.ConfidenceHigh,
		Title:       "Attack Chain Completed: " + chain.Name,
		Description: chain.Description,
		Tags:        append(chain.Tags, "chain:"+chain.ID, "chain-complete"),
		Evidence: &types.Evidence{
			MatchedData: formatChainEvidence(result),
		},
	}

	findings = append(findings, finding)

	return findings
}

// formatChainEvidence formats chain result as evidence
func formatChainEvidence(result *ChainResult) []string {
	var evidence []string

	evidence = append(evidence, fmt.Sprintf("Chain: %s", result.Chain.Name))
	evidence = append(evidence, fmt.Sprintf("Steps completed: %d/%d", len(result.StepResults), len(result.Chain.Steps)))

	for _, stepResult := range result.StepResults {
		if stepResult.Response != nil {
			evidence = append(evidence, fmt.Sprintf("Step '%s': %d", stepResult.Step.Name, stepResult.Response.StatusCode))
		}
	}

	if len(result.Variables) > 0 {
		evidence = append(evidence, "Extracted variables:")
		for k, v := range result.Variables {
			if len(v) > 50 {
				v = v[:50] + "..."
			}
			evidence = append(evidence, fmt.Sprintf("  %s=%s", k, v))
		}
	}

	return evidence
}

// ExecuteAll executes multiple chains
func (e *Executor) ExecuteAll(ctx context.Context, chains []*AttackChain) []*ChainResult {
	var results []*ChainResult

	for _, chain := range chains {
		result := e.Execute(ctx, chain)
		results = append(results, result)
	}

	return results
}

// GetStateTracker returns the state tracker
func (e *Executor) GetStateTracker() *fuzzer.StateTracker {
	return e.stateTracker
}
