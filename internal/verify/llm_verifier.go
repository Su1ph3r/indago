package verify

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/su1ph3r/indago/internal/fuzzer"
	"github.com/su1ph3r/indago/internal/llm"
	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

// FuzzExecutor abstracts the fuzzing engine for testability.
type FuzzExecutor interface {
	Fuzz(ctx context.Context, requests []payloads.FuzzRequest) <-chan *fuzzer.FuzzResult
	GetBaseline(ctx context.Context, endpoint types.Endpoint) (*types.HTTPResponse, error)
}

// ResponseAnalyzer abstracts the response analyzer for testability.
type ResponseAnalyzer interface {
	AnalyzeResult(result *fuzzer.FuzzResult, baseline *types.HTTPResponse) []types.Finding
}

// LLMVerifier uses an LLM to assess fuzzing findings for exploitability
type LLMVerifier struct {
	provider llm.Provider
	config   types.VerificationSettings
	engine   FuzzExecutor
	analyzer ResponseAnalyzer
}

type llmFindingAssessment struct {
	FindingIndex      int      `json:"finding_index"`
	Exploitability    string   `json:"exploitability"`
	Confidence        string   `json:"confidence"`
	Analysis          string   `json:"analysis"`
	SuggestedPayloads []string `json:"suggested_payloads"`
	RelatedIssues     []string `json:"related_issues"`
}

type llmBatchResponse struct {
	Assessments   []llmFindingAssessment `json:"assessments"`
	EndpointNotes string                 `json:"endpoint_notes"`
}

// NewLLMVerifier creates a new LLM-powered finding verifier.
// engine and analyzer can be nil to disable follow-up fuzzing.
func NewLLMVerifier(provider llm.Provider, config types.VerificationSettings, engine FuzzExecutor, analyzer ResponseAnalyzer) *LLMVerifier {
	return &LLMVerifier{
		provider: provider,
		config:   config,
		engine:   engine,
		analyzer: analyzer,
	}
}

// VerifyFindings sends findings to the LLM for verification and optionally
// fuzzes suggested follow-up payloads. Returns verified findings and any
// new findings discovered during follow-up.
func (v *LLMVerifier) VerifyFindings(ctx context.Context, findings []types.Finding) (verified []types.Finding, followUp []types.Finding, err error) {
	if len(findings) == 0 {
		return findings, nil, nil
	}

	groups := groupByEndpoint(findings)

	var mu sync.Mutex
	var wg sync.WaitGroup
	concurrency := v.config.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)

	var firstErr error

	for _, groupFindings := range groups {
		chunks := chunkFindings(groupFindings, v.config.MaxFindingsPerBatch)
		for _, batch := range chunks {
			wg.Add(1)
			go func(batch []types.Finding) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				if err := v.verifyBatch(ctx, batch); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
				}

				// Fuzz follow-up payloads
				if v.config.FuzzFollowUps && v.engine != nil && v.analyzer != nil {
					for i := range batch {
						if batch[i].Verification != nil && len(batch[i].Verification.SuggestedPayloads) > 0 {
							fups := v.fuzzFollowUps(ctx, batch[i], batch[i].Verification.SuggestedPayloads)
							if len(fups) > 0 {
								mu.Lock()
								followUp = append(followUp, fups...)
								mu.Unlock()
							}
						}
					}
				}

				mu.Lock()
				verified = append(verified, batch...)
				mu.Unlock()
			}(batch)
		}
	}

	wg.Wait()

	return verified, followUp, firstErr
}

func (v *LLMVerifier) verifyBatch(ctx context.Context, findings []types.Finding) error {
	system, user := v.buildVerificationPrompt(findings)

	resp, err := v.provider.AnalyzeWithSystem(ctx, system, user)
	if err != nil {
		// On LLM failure, return findings unchanged
		return fmt.Errorf("LLM verification call failed: %w", err)
	}

	var batchResp llmBatchResponse
	if err := llm.ParseJSONResponse(resp, &batchResp); err != nil {
		return fmt.Errorf("failed to parse LLM verification response: %w", err)
	}

	for _, assessment := range batchResp.Assessments {
		if assessment.FindingIndex >= 0 && assessment.FindingIndex < len(findings) {
			v.applyAssessment(&findings[assessment.FindingIndex], assessment)
		}
	}

	return nil
}

func (v *LLMVerifier) buildVerificationPrompt(findings []types.Finding) (system, user string) {
	system = `You are an expert application security researcher verifying potential API vulnerabilities found during automated fuzzing. For each finding, analyze the evidence (request, response, matched patterns) and assess:

1. Exploitability: Is this genuinely exploitable or a false positive?
2. Confidence: How confident are you in your assessment?
3. Suggested follow-up payloads that could confirm or escalate the issue.
4. Related issues: Are multiple findings part of the same root cause?

Respond with a JSON object matching this schema:
{
  "assessments": [
    {
      "finding_index": 0,
      "exploitability": "confirmed|likely|unlikely|false_positive",
      "confidence": "high|medium|low",
      "analysis": "Brief explanation of your assessment",
      "suggested_payloads": ["payload1", "payload2"],
      "related_issues": ["finding_index:1"]
    }
  ],
  "endpoint_notes": "Optional notes about the endpoint's overall security posture"
}`

	var sb strings.Builder
	sb.WriteString("Please verify the following findings:\n\n")

	for i, f := range findings {
		sb.WriteString(fmt.Sprintf("--- Finding %d ---\n", i))
		sb.WriteString(fmt.Sprintf("Type: %s\n", f.Type))
		sb.WriteString(fmt.Sprintf("Severity: %s | Confidence: %s\n", f.Severity, f.Confidence))
		sb.WriteString(fmt.Sprintf("Title: %s\n", f.Title))
		sb.WriteString(fmt.Sprintf("Endpoint: %s %s\n", f.Method, f.Endpoint))
		if f.Parameter != "" {
			sb.WriteString(fmt.Sprintf("Parameter: %s\n", f.Parameter))
		}
		if f.Payload != "" {
			sb.WriteString(fmt.Sprintf("Payload: %s\n", f.Payload))
		}

		if f.Evidence != nil {
			if f.Evidence.Request != nil {
				sb.WriteString(fmt.Sprintf("Request: %s %s\n", f.Evidence.Request.Method, f.Evidence.Request.URL))
				if f.Evidence.Request.Body != "" {
					sb.WriteString("Request Body (untrusted content):\n```\n")
					sb.WriteString(truncateBody(f.Evidence.Request.Body, v.config.MaxRequestBody))
					sb.WriteString("\n```\n")
				}
			}
			if f.Evidence.Response != nil {
				sb.WriteString(fmt.Sprintf("Response Status: %d\n", f.Evidence.Response.StatusCode))
				if f.Evidence.Response.Body != "" {
					sb.WriteString("Response Body (untrusted content):\n```\n")
					sb.WriteString(truncateBody(f.Evidence.Response.Body, v.config.MaxBodyLength))
					sb.WriteString("\n```\n")
				}
			}
			if len(f.Evidence.MatchedData) > 0 {
				sb.WriteString(fmt.Sprintf("Matched Patterns: %s\n", strings.Join(f.Evidence.MatchedData, ", ")))
			}
		}
		sb.WriteString("\n")
	}

	user = sb.String()
	return system, user
}

func (v *LLMVerifier) applyAssessment(finding *types.Finding, assessment llmFindingAssessment) {
	meta := &types.VerificationMeta{
		OriginalConfidence: finding.Confidence,
		Exploitability:     assessment.Exploitability,
		Analysis:           assessment.Analysis,
		SuggestedPayloads:  assessment.SuggestedPayloads,
		RelatedIssues:      assessment.RelatedIssues,
		ProviderName:       v.provider.Name(),
		ModelName:          v.provider.Model(),
	}

	switch assessment.Exploitability {
	case "confirmed":
		meta.Verified = true
		meta.LLMConfidence = types.ConfidenceHigh
		finding.Confidence = types.ConfidenceHigh
	case "likely":
		meta.Verified = true
		meta.LLMConfidence = assessment.Confidence
		finding.Confidence = upgradeConfidence(finding.Confidence)
	case "unlikely":
		meta.Verified = false
		meta.LLMConfidence = assessment.Confidence
		finding.Confidence = downgradeConfidence(finding.Confidence)
	case "false_positive":
		meta.Verified = false
		meta.LLMConfidence = types.ConfidenceLow
		finding.Confidence = types.ConfidenceLow
	default:
		meta.Verified = false
		meta.LLMConfidence = assessment.Confidence
	}

	finding.Verification = meta
}

func (v *LLMVerifier) fuzzFollowUps(ctx context.Context, finding types.Finding, suggestedPayloads []string) []types.Finding {
	limit := v.config.MaxFollowUpPayloads
	if limit <= 0 {
		limit = 3
	}
	if len(suggestedPayloads) > limit {
		suggestedPayloads = suggestedPayloads[:limit]
	}

	// Determine target base URL for domain validation
	targetBase := extractBaseURL(finding)

	var fuzzReqs []payloads.FuzzRequest
	for _, payload := range suggestedPayloads {
		// Skip excessively long payloads
		if len(payload) > 2000 {
			continue
		}
		// Sanitize payload
		cleanPayload, valid := sanitizeFollowUpPayload(payload)
		if !valid {
			continue
		}
		payload = cleanPayload
		// Skip payloads containing URLs pointing outside the target domain
		if targetBase != "" && containsExternalURL(payload, targetBase) {
			continue
		}
		req := payloads.FuzzRequest{
			Endpoint: types.Endpoint{
				Method:  finding.Method,
				Path:    finding.Endpoint,
				BaseURL: extractBaseURL(finding),
			},
			Payload: payloads.Payload{
				Value:       payload,
				Type:        finding.Type,
				Category:    "verification_followup",
				Description: fmt.Sprintf("LLM-suggested follow-up for: %s", finding.Title),
			},
			Position: "body",
		}
		if finding.Parameter != "" {
			req.Param = &types.Parameter{
				Name: finding.Parameter,
				In:   "body",
			}
		}
		fuzzReqs = append(fuzzReqs, req)
	}

	if len(fuzzReqs) == 0 {
		return nil
	}

	var followUpFindings []types.Finding
	results := v.engine.Fuzz(ctx, fuzzReqs)
	for result := range results {
		if result.Error != nil {
			continue
		}
		var baseline *types.HTTPResponse
		baseline, _ = v.engine.GetBaseline(ctx, result.Request.Endpoint)
		resultFindings := v.analyzer.AnalyzeResult(result, baseline)
		for i := range resultFindings {
			resultFindings[i].Tags = append(resultFindings[i].Tags, "verification_followup")
		}
		followUpFindings = append(followUpFindings, resultFindings...)
	}

	return followUpFindings
}

func groupByEndpoint(findings []types.Finding) map[string][]types.Finding {
	groups := make(map[string][]types.Finding)
	for _, f := range findings {
		key := f.Method + ":" + f.Endpoint
		groups[key] = append(groups[key], f)
	}
	return groups
}

func chunkFindings(findings []types.Finding, size int) [][]types.Finding {
	if size <= 0 {
		size = 5
	}
	var chunks [][]types.Finding
	for i := 0; i < len(findings); i += size {
		end := i + size
		if end > len(findings) {
			end = len(findings)
		}
		chunks = append(chunks, findings[i:end])
	}
	return chunks
}

func truncateBody(body string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 2000
	}
	if len(body) <= maxLen {
		return body
	}
	return body[:maxLen] + "...[truncated]"
}

func upgradeConfidence(current string) string {
	switch current {
	case types.ConfidenceLow:
		return types.ConfidenceMedium
	case types.ConfidenceMedium:
		return types.ConfidenceHigh
	default:
		return current
	}
}

func downgradeConfidence(current string) string {
	switch current {
	case types.ConfidenceHigh:
		return types.ConfidenceMedium
	case types.ConfidenceMedium:
		return types.ConfidenceLow
	default:
		return current
	}
}

func extractBaseURL(f types.Finding) string {
	if f.Evidence != nil && f.Evidence.Request != nil && f.Evidence.Request.URL != "" {
		url := f.Evidence.Request.URL
		// Extract base URL by finding the path portion
		idx := strings.Index(url, f.Endpoint)
		if idx > 0 {
			return url[:idx]
		}
	}
	return ""
}

// sanitizeFollowUpPayload cleans and validates an LLM-suggested payload.
// Returns the cleaned payload and whether it's valid for use.
func sanitizeFollowUpPayload(payload string) (string, bool) {
	// Strip null bytes
	payload = strings.ReplaceAll(payload, "\x00", "")

	// Check for dangerous URI schemes
	lowered := strings.ToLower(strings.TrimSpace(payload))
	dangerousSchemes := []string{"file://", "data:", "javascript:", "gopher://"}
	for _, scheme := range dangerousSchemes {
		if strings.HasPrefix(lowered, scheme) || strings.Contains(lowered, scheme) {
			return "", false
		}
	}

	// Reject payloads with control characters (ASCII < 0x20 except \t, \n, \r)
	for _, r := range payload {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return "", false
		}
	}

	return payload, true
}

// llmConfirmPayloadResponse is the expected JSON schema from the LLM for confirmation payload generation.
type llmConfirmPayloadResponse struct {
	Payloads []llmConfirmPayload `json:"payloads"`
}

type llmConfirmPayload struct {
	Value          string `json:"value"`
	Position       string `json:"position"`
	Parameter      string `json:"parameter"`
	Rationale      string `json:"rationale"`
	ExpectedResult string `json:"expected_result"`
}

// llmFinalVerdict is the expected JSON schema from the LLM for final confirmation verdict.
type llmFinalVerdict struct {
	FinalExploitability string `json:"final_exploitability"`
	FinalConfidence     string `json:"final_confidence"`
	CombinedAnalysis    string `json:"combined_analysis"`
}

// ConfirmFindings runs additional confirmation passes on findings that are not yet
// definitively confirmed or ruled out. Each pass generates targeted payloads via LLM,
// fuzzes them, and re-verifies with combined evidence. maxPasses includes the initial
// verify pass (already done), so the loop runs maxPasses-1 additional passes.
func (v *LLMVerifier) ConfirmFindings(ctx context.Context, findings []types.Finding, maxPasses int) ([]types.Finding, error) {
	if v.engine == nil || v.analyzer == nil {
		return findings, fmt.Errorf("confirmation passes require fuzzer engine and analyzer")
	}
	if maxPasses < 2 {
		return findings, nil
	}
	if maxPasses > 5 {
		maxPasses = 5
	}

	for pass := 2; pass <= maxPasses; pass++ {
		candidates := filterForConfirmation(findings)
		if len(candidates) == 0 {
			log.Printf("[verify] Pass %d: no candidates remaining, stopping early", pass)
			break
		}

		log.Printf("[verify] Pass %d: %d candidates for confirmation", pass, len(candidates))

		// Build index from finding ID to slice position for updates
		idxMap := make(map[string]int, len(findings))
		for i := range findings {
			idxMap[findings[i].ID] = i
		}

		// Generate confirmation payloads via LLM
		confirmReqs := v.generateConfirmationPayloads(ctx, candidates)

		// Execute confirmation payloads
		confirmResults := v.runConfirmationFuzz(ctx, confirmReqs)

		// Final LLM verdict with combined evidence
		upgraded := 0
		for _, candidate := range candidates {
			idx, ok := idxMap[candidate.ID]
			if !ok {
				continue
			}
			extra := confirmResults[candidate.ID]
			verdict := v.finalVerify(ctx, candidate, extra, pass)

			// Apply verdict to the finding
			finding := &findings[idx]
			if finding.Verification == nil {
				finding.Verification = &types.VerificationMeta{
					OriginalConfidence: finding.Confidence,
					ProviderName:       v.provider.Name(),
					ModelName:          v.provider.Model(),
				}
			}

			result := types.ConfirmationResult{
				PassNumber:          pass,
				PayloadsExecuted:    len(confirmReqs[candidate.ID]),
				ConfirmingFindings:  len(extra),
				FinalExploitability: verdict.FinalExploitability,
				FinalConfidence:     verdict.FinalConfidence,
				CombinedAnalysis:    verdict.CombinedAnalysis,
			}
			finding.Verification.ConfirmationPasses = append(finding.Verification.ConfirmationPasses, result)

			switch verdict.FinalExploitability {
			case "confirmed":
				finding.Confidence = types.ConfidenceHigh
				finding.Verification.Verified = true
				finding.Verification.Exploitability = "confirmed"
				finding.Verification.LLMConfidence = types.ConfidenceHigh
				upgraded++
			case "likely":
				finding.Confidence = upgradeConfidence(finding.Confidence)
				finding.Verification.Exploitability = "likely"
				finding.Verification.LLMConfidence = verdict.FinalConfidence
			case "unlikely":
				finding.Confidence = downgradeConfidence(finding.Confidence)
				finding.Verification.Exploitability = "unlikely"
				finding.Verification.LLMConfidence = verdict.FinalConfidence
			case "false_positive":
				finding.Confidence = types.ConfidenceLow
				finding.Verification.Verified = false
				finding.Verification.Exploitability = "false_positive"
				finding.Verification.LLMConfidence = types.ConfidenceLow
			}

			finding.Verification.Analysis = verdict.CombinedAnalysis
		}

		log.Printf("[verify] Pass %d: %d findings upgraded to confirmed", pass, upgraded)
	}

	return findings, nil
}

// filterForConfirmation returns findings that are candidates for additional confirmation.
func filterForConfirmation(findings []types.Finding) []types.Finding {
	var candidates []types.Finding
	for _, f := range findings {
		if f.Verification == nil {
			continue
		}
		exp := f.Verification.Exploitability
		conf := f.Verification.LLMConfidence

		// Already confirmed with high confidence — skip
		if exp == "confirmed" && conf == types.ConfidenceHigh {
			continue
		}
		// Already ruled out — skip
		if exp == "false_positive" {
			continue
		}
		// Unlikely with low confidence — not worth re-testing
		if exp == "unlikely" && conf == types.ConfidenceLow {
			continue
		}
		candidates = append(candidates, f)
	}
	return candidates
}

// generateConfirmationPayloads asks the LLM to generate targeted payloads for each candidate.
func (v *LLMVerifier) generateConfirmationPayloads(ctx context.Context, candidates []types.Finding) map[string][]payloads.FuzzRequest {
	result := make(map[string][]payloads.FuzzRequest)
	var mu sync.Mutex
	var wg sync.WaitGroup

	concurrency := v.config.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)

	for _, candidate := range candidates {
		wg.Add(1)
		go func(f types.Finding) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			reqs := v.generatePayloadsForFinding(ctx, f)

			mu.Lock()
			if len(reqs) > 0 {
				result[f.ID] = reqs
			}
			mu.Unlock()
		}(candidate)
	}

	wg.Wait()
	return result
}

func (v *LLMVerifier) generatePayloadsForFinding(ctx context.Context, f types.Finding) []payloads.FuzzRequest {
	system := `You are an expert penetration tester. Given a potential vulnerability finding with its evidence, generate 2-5 targeted confirmation payloads designed to definitively prove or disprove exploitability.

Respond with JSON matching this schema:
{
  "payloads": [
    {
      "value": "the payload string",
      "position": "body|query|path|header",
      "parameter": "target parameter name",
      "rationale": "why this payload confirms the vulnerability",
      "expected_result": "what to look for in the response"
    }
  ]
}

Guidelines:
- Design payloads that produce unambiguous results (e.g., specific error messages, data leaks, timing differences)
- Vary the approach: if the original was a simple injection, try a more sophisticated variant
- Include at least one payload that tests the boundary between exploitable and not
- Keep payloads safe for testing (no destructive operations)`

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Finding Type: %s\n", f.Type))
	sb.WriteString(fmt.Sprintf("Endpoint: %s %s\n", f.Method, f.Endpoint))
	if f.Parameter != "" {
		sb.WriteString(fmt.Sprintf("Parameter: %s\n", f.Parameter))
	}
	if f.Payload != "" {
		sb.WriteString(fmt.Sprintf("Original Payload: %s\n", f.Payload))
	}
	if f.Evidence != nil && f.Evidence.Response != nil {
		sb.WriteString(fmt.Sprintf("Response Status: %d\n", f.Evidence.Response.StatusCode))
		if f.Evidence.Response.Body != "" {
			sb.WriteString("Response Body:\n```\n")
			sb.WriteString(truncateBody(f.Evidence.Response.Body, v.config.MaxBodyLength))
			sb.WriteString("\n```\n")
		}
	}
	if f.Verification != nil {
		sb.WriteString(fmt.Sprintf("Previous Assessment: %s (confidence: %s)\n", f.Verification.Exploitability, f.Verification.LLMConfidence))
		sb.WriteString(fmt.Sprintf("Analysis: %s\n", f.Verification.Analysis))
	}

	resp, err := v.provider.AnalyzeWithSystem(ctx, system, sb.String())
	if err != nil {
		log.Printf("[verify] Failed to generate confirmation payloads for %s: %v", f.ID, err)
		return nil
	}

	var parsed llmConfirmPayloadResponse
	if err := llm.ParseJSONResponse(resp, &parsed); err != nil {
		log.Printf("[verify] Failed to parse confirmation payloads for %s: %v", f.ID, err)
		return nil
	}

	limit := v.config.MaxConfirmPayloads
	if limit <= 0 {
		limit = 5
	}
	if len(parsed.Payloads) > limit {
		parsed.Payloads = parsed.Payloads[:limit]
	}

	targetBase := extractBaseURL(f)
	var reqs []payloads.FuzzRequest
	for _, p := range parsed.Payloads {
		if len(p.Value) > 2000 {
			continue
		}
		clean, valid := sanitizeFollowUpPayload(p.Value)
		if !valid {
			continue
		}
		if targetBase != "" && containsExternalURL(clean, targetBase) {
			continue
		}

		position := p.Position
		if position == "" {
			position = "body"
		}

		paramIn := position
		if paramIn == "path" || paramIn == "header" {
			paramIn = position
		}

		req := payloads.FuzzRequest{
			Endpoint: types.Endpoint{
				Method:  f.Method,
				Path:    f.Endpoint,
				BaseURL: targetBase,
			},
			Payload: payloads.Payload{
				Value:       clean,
				Type:        f.Type,
				Category:    "confirmation_pass",
				Description: fmt.Sprintf("Confirmation payload: %s", p.Rationale),
			},
			Position: position,
		}

		paramName := p.Parameter
		if paramName == "" {
			paramName = f.Parameter
		}
		if paramName != "" {
			req.Param = &types.Parameter{
				Name: paramName,
				In:   paramIn,
			}
		}

		reqs = append(reqs, req)
	}

	return reqs
}

// runConfirmationFuzz executes confirmation payloads and analyzes results.
func (v *LLMVerifier) runConfirmationFuzz(ctx context.Context, confirmReqs map[string][]payloads.FuzzRequest) map[string][]types.Finding {
	result := make(map[string][]types.Finding)

	for findingID, reqs := range confirmReqs {
		if len(reqs) == 0 {
			continue
		}

		results := v.engine.Fuzz(ctx, reqs)
		var confirmFindings []types.Finding
		for r := range results {
			if r.Error != nil {
				continue
			}
			var baseline *types.HTTPResponse
			baseline, _ = v.engine.GetBaseline(ctx, r.Request.Endpoint)
			rf := v.analyzer.AnalyzeResult(r, baseline)
			for i := range rf {
				rf[i].Tags = append(rf[i].Tags, "confirmation_pass")
			}
			confirmFindings = append(confirmFindings, rf...)
		}

		if len(confirmFindings) > 0 {
			result[findingID] = confirmFindings
		}
	}

	return result
}

// finalVerify asks the LLM for a definitive verdict given original + confirmation evidence.
func (v *LLMVerifier) finalVerify(ctx context.Context, original types.Finding, confirmFindings []types.Finding, passNum int) llmFinalVerdict {
	system := `You are an expert application security researcher making a final determination on a potential vulnerability. You have the original finding plus results from targeted confirmation payloads.

Analyze ALL evidence and provide a definitive verdict. Respond with JSON:
{
  "final_exploitability": "confirmed|likely|unlikely|false_positive",
  "final_confidence": "high|medium|low",
  "combined_analysis": "Detailed explanation of your final assessment considering all evidence"
}

Use "confirmed" only when the evidence clearly demonstrates exploitability.
Use "false_positive" when the evidence clearly shows this is not exploitable.
Use "likely"/"unlikely" when evidence is inconclusive but leans one direction.`

	var sb strings.Builder
	sb.WriteString("=== ORIGINAL FINDING ===\n")
	sb.WriteString(fmt.Sprintf("Type: %s\n", original.Type))
	sb.WriteString(fmt.Sprintf("Endpoint: %s %s\n", original.Method, original.Endpoint))
	if original.Parameter != "" {
		sb.WriteString(fmt.Sprintf("Parameter: %s\n", original.Parameter))
	}
	if original.Payload != "" {
		sb.WriteString(fmt.Sprintf("Payload: %s\n", original.Payload))
	}
	if original.Evidence != nil && original.Evidence.Response != nil {
		sb.WriteString(fmt.Sprintf("Response: %d\n", original.Evidence.Response.StatusCode))
		if original.Evidence.Response.Body != "" {
			sb.WriteString(truncateBody(original.Evidence.Response.Body, v.config.MaxBodyLength))
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n=== INITIAL VERIFICATION ===\n")
	if original.Verification != nil {
		sb.WriteString(fmt.Sprintf("Exploitability: %s\n", original.Verification.Exploitability))
		sb.WriteString(fmt.Sprintf("Confidence: %s\n", original.Verification.LLMConfidence))
		sb.WriteString(fmt.Sprintf("Analysis: %s\n", original.Verification.Analysis))
	}

	sb.WriteString(fmt.Sprintf("\n=== CONFIRMATION PASS %d ===\n", passNum))
	sb.WriteString(fmt.Sprintf("Confirmation payloads executed: results follow\n"))

	if len(confirmFindings) == 0 {
		sb.WriteString("No additional findings were triggered by confirmation payloads.\n")
	} else {
		sb.WriteString(fmt.Sprintf("%d confirmation payloads triggered findings:\n", len(confirmFindings)))
		for i, cf := range confirmFindings {
			sb.WriteString(fmt.Sprintf("  [%d] Type: %s, Severity: %s, Confidence: %s\n", i, cf.Type, cf.Severity, cf.Confidence))
			if cf.Evidence != nil && cf.Evidence.Response != nil {
				sb.WriteString(fmt.Sprintf("       Response: %d\n", cf.Evidence.Response.StatusCode))
				if cf.Evidence.Response.Body != "" {
					sb.WriteString("       Body: ")
					sb.WriteString(truncateBody(cf.Evidence.Response.Body, 500))
					sb.WriteString("\n")
				}
			}
		}
	}

	resp, err := v.provider.AnalyzeWithSystem(ctx, system, sb.String())
	if err != nil {
		log.Printf("[verify] Final verdict LLM call failed for %s: %v", original.ID, err)
		return llmFinalVerdict{
			FinalExploitability: original.Verification.Exploitability,
			FinalConfidence:     original.Verification.LLMConfidence,
			CombinedAnalysis:    fmt.Sprintf("LLM call failed during pass %d: %v", passNum, err),
		}
	}

	var verdict llmFinalVerdict
	if err := llm.ParseJSONResponse(resp, &verdict); err != nil {
		log.Printf("[verify] Failed to parse final verdict for %s: %v", original.ID, err)
		return llmFinalVerdict{
			FinalExploitability: original.Verification.Exploitability,
			FinalConfidence:     original.Verification.LLMConfidence,
			CombinedAnalysis:    fmt.Sprintf("Failed to parse LLM response during pass %d: %v", passNum, err),
		}
	}

	return verdict
}

// containsExternalURL checks if a payload contains a URL pointing outside the target domain.
func containsExternalURL(payload, targetBase string) bool {
	// Extract host from target base URL
	targetHost := targetBase
	if idx := strings.Index(targetBase, "://"); idx >= 0 {
		targetHost = targetBase[idx+3:]
	}
	targetHost = strings.TrimRight(targetHost, "/")
	if colonIdx := strings.Index(targetHost, ":"); colonIdx >= 0 {
		targetHost = targetHost[:colonIdx]
	}
	if targetHost == "" {
		return false
	}

	// Check for http:// or https:// URLs in the payload that don't point to the target
	for _, scheme := range []string{"http://", "https://"} {
		idx := 0
		for {
			pos := strings.Index(payload[idx:], scheme)
			if pos < 0 {
				break
			}
			urlStart := idx + pos + len(scheme)
			// Extract the host portion
			urlHost := payload[urlStart:]
			if slashIdx := strings.Index(urlHost, "/"); slashIdx >= 0 {
				urlHost = urlHost[:slashIdx]
			}
			if colonIdx := strings.Index(urlHost, ":"); colonIdx >= 0 {
				urlHost = urlHost[:colonIdx]
			}
			// Check if this host matches the target
			if urlHost != "" && urlHost != targetHost && !strings.HasSuffix(urlHost, "."+targetHost) {
				return true
			}
			idx = urlStart
		}
	}
	return false
}