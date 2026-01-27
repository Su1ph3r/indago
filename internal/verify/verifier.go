// Package verify provides finding verification capabilities
package verify

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/su1ph3r/indago/pkg/types"
)

// Verifier verifies findings with additional testing
type Verifier struct {
	client         *http.Client
	config         VerifyConfig
	variationGens  map[string]PayloadVariationGenerator
}

// VerifyConfig holds verification configuration
type VerifyConfig struct {
	Timeout           time.Duration
	MaxVariations     int
	ConfirmationCount int // Number of successful variations to confirm
	RetryCount        int
}

// DefaultVerifyConfig returns default verification config
func DefaultVerifyConfig() VerifyConfig {
	return VerifyConfig{
		Timeout:           30 * time.Second,
		MaxVariations:     5,
		ConfirmationCount: 2,
		RetryCount:        2,
	}
}

// VerificationResult holds the result of verification
type VerificationResult struct {
	Finding           types.Finding
	Verified          bool
	ConfidenceChange  float64
	SuccessfulPayloads []string
	FailedPayloads    []string
	Notes             []string
}

// PayloadVariationGenerator generates variations of payloads
type PayloadVariationGenerator interface {
	GenerateVariations(payload string, attackType string) []string
}

// NewVerifier creates a new finding verifier
func NewVerifier(config VerifyConfig) *Verifier {
	return &Verifier{
		client: &http.Client{
			Timeout: config.Timeout,
		},
		config:        config,
		variationGens: make(map[string]PayloadVariationGenerator),
	}
}

// Verify attempts to verify a finding
func (v *Verifier) Verify(ctx context.Context, finding types.Finding) (*VerificationResult, error) {
	result := &VerificationResult{
		Finding: finding,
	}

	// Generate payload variations
	variations := v.generateVariations(finding)

	successCount := 0
	for _, variation := range variations {
		if successCount >= v.config.ConfirmationCount {
			break
		}

		// Test the variation
		success, note := v.testVariation(ctx, finding, variation)

		if success {
			successCount++
			result.SuccessfulPayloads = append(result.SuccessfulPayloads, variation)
		} else {
			result.FailedPayloads = append(result.FailedPayloads, variation)
		}

		if note != "" {
			result.Notes = append(result.Notes, note)
		}
	}

	// Determine verification result
	result.Verified = successCount >= v.config.ConfirmationCount

	// Adjust confidence
	if result.Verified {
		result.ConfidenceChange = 0.2 // Increase confidence
	} else if successCount == 0 {
		result.ConfidenceChange = -0.3 // Decrease confidence
	}

	return result, nil
}

// VerifyAll verifies multiple findings
func (v *Verifier) VerifyAll(ctx context.Context, findings []types.Finding) []*VerificationResult {
	var results []*VerificationResult

	for _, finding := range findings {
		result, err := v.Verify(ctx, finding)
		if err != nil {
			result = &VerificationResult{
				Finding: finding,
				Verified: false,
				Notes:   []string{fmt.Sprintf("Verification error: %v", err)},
			}
		}
		results = append(results, result)
	}

	return results
}

// generateVariations generates payload variations for testing
func (v *Verifier) generateVariations(finding types.Finding) []string {
	var variations []string

	// Start with the original payload
	if finding.Payload != "" {
		variations = append(variations, finding.Payload)
	}

	// Generate attack-type specific variations
	switch finding.Type {
	case types.AttackSQLi:
		variations = append(variations, v.sqlVariations(finding.Payload)...)
	case types.AttackXSS:
		variations = append(variations, v.xssVariations(finding.Payload)...)
	case types.AttackCommandInject:
		variations = append(variations, v.cmdVariations(finding.Payload)...)
	case types.AttackIDOR, types.AttackBOLA:
		variations = append(variations, v.idorVariations(finding.Payload)...)
	}

	// Limit variations
	if len(variations) > v.config.MaxVariations {
		variations = variations[:v.config.MaxVariations]
	}

	return variations
}

// sqlVariations generates SQL injection variations
func (v *Verifier) sqlVariations(payload string) []string {
	if payload == "" {
		payload = "' OR 1=1--"
	}

	return []string{
		payload,
		strings.ReplaceAll(payload, "'", "\""),
		strings.ReplaceAll(payload, "--", "#"),
		payload + "/**/",
		strings.ReplaceAll(payload, " ", "/**/"),
		"1 AND 1=1",
		"1 AND 1=2",
	}
}

// xssVariations generates XSS variations
func (v *Verifier) xssVariations(payload string) []string {
	if payload == "" {
		payload = "<script>alert(1)</script>"
	}

	return []string{
		payload,
		strings.ReplaceAll(payload, "<script>", "<ScRiPt>"),
		strings.ReplaceAll(payload, "<", "%3C"),
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"javascript:alert(1)",
	}
}

// cmdVariations generates command injection variations
func (v *Verifier) cmdVariations(payload string) []string {
	if payload == "" {
		payload = ";id"
	}

	return []string{
		payload,
		strings.ReplaceAll(payload, ";", "|"),
		strings.ReplaceAll(payload, ";", "&&"),
		"`id`",
		"$(id)",
		"${IFS}id",
	}
}

// idorVariations generates IDOR variations
func (v *Verifier) idorVariations(payload string) []string {
	if payload == "" {
		payload = "1"
	}

	return []string{
		payload,
		"0",
		"-1",
		"99999999",
		"null",
		"undefined",
	}
}

// testVariation tests a single payload variation
func (v *Verifier) testVariation(ctx context.Context, finding types.Finding, payload string) (bool, string) {
	if finding.Evidence == nil || finding.Evidence.Request == nil {
		return false, "No request evidence available"
	}

	// Build request with variation
	req, err := http.NewRequestWithContext(ctx, finding.Evidence.Request.Method, finding.Evidence.Request.URL, nil)
	if err != nil {
		return false, fmt.Sprintf("Failed to create request: %v", err)
	}

	// Copy headers
	for k, val := range finding.Evidence.Request.Headers {
		req.Header.Set(k, val)
	}

	// Execute request
	resp, err := v.client.Do(req)
	if err != nil {
		return false, fmt.Sprintf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check for success indicators based on finding type
	return v.checkSuccessIndicators(finding, resp, payload)
}

// checkSuccessIndicators checks if the response indicates successful exploitation
func (v *Verifier) checkSuccessIndicators(finding types.Finding, resp *http.Response, payload string) (bool, string) {
	// Compare with original response
	if finding.Evidence != nil && finding.Evidence.Response != nil {
		originalStatus := finding.Evidence.Response.StatusCode

		// Same anomalous response is a good indicator
		if resp.StatusCode == originalStatus {
			return true, "Response matches original anomaly"
		}

		// For IDOR, 200 on different resource is good
		if finding.Type == types.AttackIDOR || finding.Type == types.AttackBOLA {
			if resp.StatusCode == 200 && originalStatus == 200 {
				return true, "Successfully accessed resource"
			}
		}
	}

	// Server errors often indicate injection success
	if resp.StatusCode >= 500 && (finding.Type == types.AttackSQLi || finding.Type == types.AttackCommandInject) {
		return true, "Server error indicates potential injection"
	}

	return false, ""
}

// FilterVerified filters findings to only verified ones
func FilterVerified(results []*VerificationResult) []types.Finding {
	var verified []types.Finding

	for _, result := range results {
		if result.Verified {
			finding := result.Finding

			// Adjust confidence
			if result.ConfidenceChange > 0 {
				if finding.Confidence == types.ConfidenceMedium {
					finding.Confidence = types.ConfidenceHigh
				} else if finding.Confidence == types.ConfidenceLow {
					finding.Confidence = types.ConfidenceMedium
				}
			}

			verified = append(verified, finding)
		}
	}

	return verified
}

// AdjustConfidence adjusts finding confidence based on verification
func AdjustConfidence(finding *types.Finding, result *VerificationResult) {
	if result.Verified {
		if finding.Confidence != types.ConfidenceHigh {
			finding.Confidence = types.ConfidenceHigh
		}
	} else if len(result.FailedPayloads) > 0 && len(result.SuccessfulPayloads) == 0 {
		finding.Confidence = types.ConfidenceLow
	}
}
