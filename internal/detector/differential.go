// Package detector provides response analysis and vulnerability detection
package detector

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// DifferentialAnalyzer compares responses across different auth contexts
type DifferentialAnalyzer struct {
	contexts   []types.AuthContext
	results    map[string]map[string]*types.HTTPResponse // endpoint -> context -> response
	thresholds DifferentialThresholds
}

// DifferentialThresholds defines thresholds for anomaly detection
type DifferentialThresholds struct {
	FieldCountDiffPercent float64 `yaml:"field_count_diff_percent" json:"field_count_diff_percent"`
	BodySizeDiffPercent   float64 `yaml:"body_size_diff_percent" json:"body_size_diff_percent"`
	MinFieldsForComparison int    `yaml:"min_fields_for_comparison" json:"min_fields_for_comparison"`
}

// DifferentialAnomaly represents a detected anomaly
type DifferentialAnomaly struct {
	Type           string   `json:"type"`
	ContextA       string   `json:"context_a"`
	ContextB       string   `json:"context_b"`
	Evidence       []string `json:"evidence"`
	Severity       string   `json:"severity"`
	Confidence     string   `json:"confidence"`
	ExtraFields    []string `json:"extra_fields,omitempty"`
	MissingFields  []string `json:"missing_fields,omitempty"`
	ValueDiffs     []string `json:"value_diffs,omitempty"`
	StatusCodeDiff []int    `json:"status_code_diff,omitempty"`
}

// NewDifferentialAnalyzer creates a new differential analyzer
func NewDifferentialAnalyzer(contexts []types.AuthContext) *DifferentialAnalyzer {
	return &DifferentialAnalyzer{
		contexts: contexts,
		results:  make(map[string]map[string]*types.HTTPResponse),
		thresholds: DifferentialThresholds{
			FieldCountDiffPercent:  0.2, // 20% difference triggers alert
			BodySizeDiffPercent:    0.3, // 30% size difference
			MinFieldsForComparison: 3,   // Minimum fields to compare
		},
	}
}

// SetThresholds sets custom thresholds
func (da *DifferentialAnalyzer) SetThresholds(thresholds DifferentialThresholds) {
	da.thresholds = thresholds
}

// GetContexts returns the configured auth contexts
func (da *DifferentialAnalyzer) GetContexts() []types.AuthContext {
	contexts := make([]types.AuthContext, len(da.contexts))
	copy(contexts, da.contexts)
	return contexts
}

// StoreResponse stores a response for a given endpoint and context
func (da *DifferentialAnalyzer) StoreResponse(endpoint, contextName string, response *types.HTTPResponse) {
	if da.results[endpoint] == nil {
		da.results[endpoint] = make(map[string]*types.HTTPResponse)
	}
	da.results[endpoint][contextName] = response
}

// AnalyzeEndpoint analyzes responses for an endpoint across all contexts
func (da *DifferentialAnalyzer) AnalyzeEndpoint(endpoint string) []DifferentialAnomaly {
	var anomalies []DifferentialAnomaly

	responses := da.results[endpoint]
	if responses == nil || len(responses) < 2 {
		return anomalies
	}

	// Compare each pair of contexts
	for i, ctxA := range da.contexts {
		respA, okA := responses[ctxA.Name]
		if !okA || respA == nil {
			continue
		}

		for j := i + 1; j < len(da.contexts); j++ {
			ctxB := da.contexts[j]
			respB, okB := responses[ctxB.Name]
			if !okB || respB == nil {
				continue
			}

			// Analyze the pair
			pairAnomalies := da.comparePair(endpoint, ctxA, ctxB, respA, respB)
			anomalies = append(anomalies, pairAnomalies...)
		}
	}

	return anomalies
}

// comparePair compares responses between two auth contexts
func (da *DifferentialAnalyzer) comparePair(endpoint string, ctxA, ctxB types.AuthContext, respA, respB *types.HTTPResponse) []DifferentialAnomaly {
	var anomalies []DifferentialAnomaly

	// Check for BOLA/IDOR: lower privilege sees higher privilege data
	if bolaAnomaly := da.checkBOLA(ctxA, ctxB, respA, respB); bolaAnomaly != nil {
		anomalies = append(anomalies, *bolaAnomaly)
	}

	// Check for horizontal access: same privilege level accessing each other's data
	if horizontalAnomaly := da.checkHorizontalAccess(ctxA, ctxB, respA, respB); horizontalAnomaly != nil {
		anomalies = append(anomalies, *horizontalAnomaly)
	}

	// Check for data leakage: lower privilege response contains sensitive fields
	if leakageAnomaly := da.checkDataLeakage(ctxA, ctxB, respA, respB); leakageAnomaly != nil {
		anomalies = append(anomalies, *leakageAnomaly)
	}

	// Check for field count differences
	if fieldAnomaly := da.checkFieldCountDifference(ctxA, ctxB, respA, respB); fieldAnomaly != nil {
		anomalies = append(anomalies, *fieldAnomaly)
	}

	// Check for unauthorized access
	if accessAnomaly := da.checkUnauthorizedAccess(ctxA, ctxB, respA, respB); accessAnomaly != nil {
		anomalies = append(anomalies, *accessAnomaly)
	}

	return anomalies
}

// checkBOLA checks for Broken Object Level Authorization
func (da *DifferentialAnalyzer) checkBOLA(ctxA, ctxB types.AuthContext, respA, respB *types.HTTPResponse) *DifferentialAnomaly {
	// Skip if same privilege level
	if ctxA.Priority == ctxB.Priority {
		return nil
	}

	// Determine which is higher/lower privilege
	var highPrivCtx, lowPrivCtx types.AuthContext
	var highPrivResp, lowPrivResp *types.HTTPResponse

	if ctxA.Priority < ctxB.Priority {
		highPrivCtx, lowPrivCtx = ctxA, ctxB
		highPrivResp, lowPrivResp = respA, respB
	} else {
		highPrivCtx, lowPrivCtx = ctxB, ctxA
		highPrivResp, lowPrivResp = respB, respA
	}

	// Both should succeed - if lower privilege gets same data, it's BOLA
	if highPrivResp.StatusCode >= 200 && highPrivResp.StatusCode < 300 &&
		lowPrivResp.StatusCode >= 200 && lowPrivResp.StatusCode < 300 {

		// Check if responses are similar enough to indicate unauthorized access
		similarity := da.calculateSimilarity(highPrivResp.Body, lowPrivResp.Body)

		if similarity > 0.9 { // 90% similar
			return &DifferentialAnomaly{
				Type:       "bola",
				ContextA:   highPrivCtx.Name,
				ContextB:   lowPrivCtx.Name,
				Severity:   types.SeverityHigh,
				Confidence: types.ConfidenceHigh,
				Evidence: []string{
					"Lower privilege context (" + lowPrivCtx.Name + ") received same data as higher privilege context (" + highPrivCtx.Name + ")",
					"Response similarity: " + formatPercent(similarity),
				},
			}
		}
	}

	return nil
}

// checkHorizontalAccess checks for horizontal privilege escalation
func (da *DifferentialAnalyzer) checkHorizontalAccess(ctxA, ctxB types.AuthContext, respA, respB *types.HTTPResponse) *DifferentialAnomaly {
	// Only applies to same privilege level with different user IDs
	if ctxA.Priority != ctxB.Priority || ctxA.UserID == "" || ctxB.UserID == "" || ctxA.UserID == ctxB.UserID {
		return nil
	}

	// Check if user A can see user B's data
	if respA.StatusCode >= 200 && respA.StatusCode < 300 {
		// Check if response A contains user B's identifiers
		if strings.Contains(respA.Body, ctxB.UserID) {
			return &DifferentialAnomaly{
				Type:       "horizontal_access",
				ContextA:   ctxA.Name,
				ContextB:   ctxB.Name,
				Severity:   types.SeverityHigh,
				Confidence: types.ConfidenceMedium,
				Evidence: []string{
					"User " + ctxA.Name + " can access data belonging to user " + ctxB.Name,
					"Found user identifier '" + ctxB.UserID + "' in response",
				},
			}
		}
	}

	return nil
}

// checkDataLeakage checks for sensitive data leakage to lower privilege contexts
func (da *DifferentialAnalyzer) checkDataLeakage(ctxA, ctxB types.AuthContext, respA, respB *types.HTTPResponse) *DifferentialAnomaly {
	// Skip if same privilege level
	if ctxA.Priority == ctxB.Priority {
		return nil
	}

	var highPrivResp, lowPrivResp *types.HTTPResponse
	var highPrivCtx, lowPrivCtx types.AuthContext

	if ctxA.Priority < ctxB.Priority {
		highPrivResp, lowPrivResp = respA, respB
		highPrivCtx, lowPrivCtx = ctxA, ctxB
	} else {
		highPrivResp, lowPrivResp = respB, respA
		highPrivCtx, lowPrivCtx = ctxB, ctxA
	}

	// Both should succeed for this check
	if lowPrivResp.StatusCode < 200 || lowPrivResp.StatusCode >= 300 {
		return nil
	}

	// Parse JSON responses
	var highData, lowData map[string]interface{}
	if err := json.Unmarshal([]byte(highPrivResp.Body), &highData); err != nil {
		return nil
	}
	if err := json.Unmarshal([]byte(lowPrivResp.Body), &lowData); err != nil {
		return nil
	}

	// Check for sensitive fields that shouldn't be in lower privilege response
	sensitiveFields := []string{
		"password", "hash", "secret", "private_key", "api_key", "token",
		"ssn", "social_security", "credit_card", "card_number", "cvv",
		"admin", "is_admin", "role", "permissions", "internal",
	}

	var leakedFields []string
	for _, field := range sensitiveFields {
		if _, inHigh := getNestedField(highData, field); inHigh {
			if _, inLow := getNestedField(lowData, field); inLow {
				leakedFields = append(leakedFields, field)
			}
		}
	}

	if len(leakedFields) > 0 {
		return &DifferentialAnomaly{
			Type:        "data_leakage",
			ContextA:    highPrivCtx.Name,
			ContextB:    lowPrivCtx.Name,
			Severity:    types.SeverityMedium,
			Confidence:  types.ConfidenceHigh,
			ExtraFields: leakedFields,
			Evidence: []string{
				"Sensitive fields visible to lower privilege context",
				"Fields: " + strings.Join(leakedFields, ", "),
			},
		}
	}

	return nil
}

// checkFieldCountDifference checks for unexpected field count differences
func (da *DifferentialAnalyzer) checkFieldCountDifference(ctxA, ctxB types.AuthContext, respA, respB *types.HTTPResponse) *DifferentialAnomaly {
	// Parse JSON responses
	var dataA, dataB map[string]interface{}
	if err := json.Unmarshal([]byte(respA.Body), &dataA); err != nil {
		return nil
	}
	if err := json.Unmarshal([]byte(respB.Body), &dataB); err != nil {
		return nil
	}

	fieldsA := countFields(dataA)
	fieldsB := countFields(dataB)

	if fieldsA < da.thresholds.MinFieldsForComparison || fieldsB < da.thresholds.MinFieldsForComparison {
		return nil
	}

	// Calculate difference
	diff := float64(abs(fieldsA-fieldsB)) / float64(max(fieldsA, fieldsB))

	if diff > da.thresholds.FieldCountDiffPercent {
		var moreFields, fewerFields string
		var extraCount, missingCount int

		if fieldsA > fieldsB {
			moreFields, fewerFields = ctxA.Name, ctxB.Name
			extraCount, missingCount = fieldsA, fieldsB
		} else {
			moreFields, fewerFields = ctxB.Name, ctxA.Name
			extraCount, missingCount = fieldsB, fieldsA
		}

		return &DifferentialAnomaly{
			Type:       "field_count_diff",
			ContextA:   moreFields,
			ContextB:   fewerFields,
			Severity:   types.SeverityLow,
			Confidence: types.ConfidenceLow,
			Evidence: []string{
				fmt.Sprintf("%s has %d fields", moreFields, extraCount),
				fmt.Sprintf("%s has %d fields", fewerFields, missingCount),
				fmt.Sprintf("Difference: %.1f%%", diff*100),
			},
		}
	}

	return nil
}

// checkUnauthorizedAccess checks if lower privilege gets access when it shouldn't
func (da *DifferentialAnalyzer) checkUnauthorizedAccess(ctxA, ctxB types.AuthContext, respA, respB *types.HTTPResponse) *DifferentialAnomaly {
	// Skip if same privilege level
	if ctxA.Priority == ctxB.Priority {
		return nil
	}

	var highPrivResp, lowPrivResp *types.HTTPResponse
	var highPrivCtx, lowPrivCtx types.AuthContext

	if ctxA.Priority < ctxB.Priority {
		highPrivResp, lowPrivResp = respA, respB
		highPrivCtx, lowPrivCtx = ctxA, ctxB
	} else {
		highPrivResp, lowPrivResp = respB, respA
		highPrivCtx, lowPrivCtx = ctxB, ctxA
	}

	// If high privilege gets 200 but low privilege also gets 200 for admin-only endpoint
	// this could be unauthorized access
	if highPrivResp.StatusCode >= 200 && highPrivResp.StatusCode < 300 &&
		lowPrivResp.StatusCode >= 200 && lowPrivResp.StatusCode < 300 {

		// Check if this looks like an admin-only endpoint
		adminPatterns := []string{"/admin", "/internal", "/manage", "/config", "/settings/admin"}
		// Note: endpoint would need to be passed in for full check

		// For now, just flag if anonymous gets same response as authenticated
		if lowPrivCtx.Priority > 100 && highPrivCtx.Priority < 100 { // Assuming anonymous has high priority number
			return &DifferentialAnomaly{
				Type:       "unauthorized_access",
				ContextA:   highPrivCtx.Name,
				ContextB:   lowPrivCtx.Name,
				Severity:   types.SeverityCritical,
				Confidence: types.ConfidenceMedium,
				Evidence: []string{
					"Unauthenticated context (" + lowPrivCtx.Name + ") received successful response",
					fmt.Sprintf("High privilege status: %d", highPrivResp.StatusCode),
					fmt.Sprintf("Low privilege status: %d", lowPrivResp.StatusCode),
				},
			}
		}

		_ = adminPatterns // Suppress unused variable warning
	}

	return nil
}

// ToFinding converts an anomaly to a Finding
func (da *DifferentialAnomaly) ToFinding(endpoint, method string) types.Finding {
	title := ""
	description := ""

	switch da.Type {
	case "bola":
		title = "Broken Object Level Authorization (BOLA)"
		description = "Lower privilege user can access higher privilege data"
	case "horizontal_access":
		title = "Horizontal Privilege Escalation"
		description = "User can access another user's data at the same privilege level"
	case "data_leakage":
		title = "Sensitive Data Leakage"
		description = "Sensitive fields exposed to lower privilege context"
	case "field_count_diff":
		title = "Response Field Count Difference"
		description = "Significant difference in response fields between auth contexts"
	case "unauthorized_access":
		title = "Unauthorized Access"
		description = "Unauthenticated or low privilege context accessing protected resource"
	}

	return types.Finding{
		ID:          generateID(),
		Type:        da.Type,
		Severity:    da.Severity,
		Confidence:  da.Confidence,
		Title:       title,
		Description: description,
		Endpoint:    endpoint,
		Method:      method,
		Evidence: &types.Evidence{
			MatchedData: da.Evidence,
			Anomalies:   append(da.ExtraFields, da.MissingFields...),
		},
		CWE: getCWEForDifferentialType(da.Type),
		Tags: []string{"differential", da.ContextA + "_vs_" + da.ContextB},
	}
}

// Helper functions

func (da *DifferentialAnalyzer) calculateSimilarity(bodyA, bodyB string) float64 {
	if bodyA == bodyB {
		return 1.0
	}

	// Simple character-level comparison
	lenA, lenB := len(bodyA), len(bodyB)
	if lenA == 0 || lenB == 0 {
		return 0.0
	}

	// Count matching characters at same positions
	minLen := min(lenA, lenB)
	matches := 0
	for i := 0; i < minLen; i++ {
		if bodyA[i] == bodyB[i] {
			matches++
		}
	}

	return float64(matches) / float64(max(lenA, lenB))
}

func getNestedField(data map[string]interface{}, field string) (interface{}, bool) {
	// Check top level
	if val, ok := data[field]; ok {
		return val, true
	}

	// Check nested fields
	for _, v := range data {
		if nested, ok := v.(map[string]interface{}); ok {
			if val, found := getNestedField(nested, field); found {
				return val, true
			}
		}
	}

	return nil, false
}

func countFields(data map[string]interface{}) int {
	count := len(data)
	for _, v := range data {
		if nested, ok := v.(map[string]interface{}); ok {
			count += countFields(nested)
		}
	}
	return count
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func formatPercent(f float64) string {
	return fmt.Sprintf("%.1f%%", f*100)
}

func getCWEForDifferentialType(anomalyType string) string {
	switch anomalyType {
	case "bola":
		return "CWE-639" // Authorization Bypass Through User-Controlled Key
	case "horizontal_access":
		return "CWE-284" // Improper Access Control
	case "data_leakage":
		return "CWE-200" // Exposure of Sensitive Information
	case "unauthorized_access":
		return "CWE-862" // Missing Authorization
	default:
		return "CWE-264" // Permissions, Privileges, and Access Controls
	}
}

// ParseAuthContexts parses auth contexts from CLI arguments
func ParseAuthContexts(args []string) []types.AuthContext {
	var contexts []types.AuthContext

	for i, arg := range args {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			continue
		}

		name := parts[0]
		token := parts[1]

		ctx := types.AuthContext{
			Name:     name,
			Token:    token,
			Priority: i,
		}

		// Detect auth type
		if strings.HasPrefix(token, "eyJ") {
			ctx.AuthType = "bearer"
		} else if strings.Contains(name, "cookie") {
			ctx.AuthType = "cookie"
		} else {
			ctx.AuthType = "bearer"
		}

		contexts = append(contexts, ctx)
	}

	return contexts
}
