package benchmark

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/su1ph3r/indago/internal/llm"
)

// ImprovementCategory classifies the type of improvement.
type ImprovementCategory string

const (
	CatPayloadGenerator   ImprovementCategory = "payload_generator"
	CatDetectionHeuristic ImprovementCategory = "detection_heuristic"
	CatLLMPrompt          ImprovementCategory = "llm_prompt"
	CatFilterTuning       ImprovementCategory = "filter_tuning"
)

// ImprovementProposal represents a single code change proposed by the LLM.
type ImprovementProposal struct {
	Category    ImprovementCategory `json:"category"`
	FilePath    string              `json:"file_path"`
	Action      string              `json:"action"` // "modify" or "add_code"
	CurrentCode string              `json:"current_code,omitempty"`
	NewCode     string              `json:"new_code"`
	Rationale   string              `json:"rationale"`
	Applied     bool                `json:"applied"`
	Error       string              `json:"error,omitempty"`
}

// Improver uses LLM(s) to propose and apply code improvements.
type Improver struct {
	primaryProvider llm.Provider
	localProvider   llm.Provider // optional second opinion (e.g. LM Studio)
	projectRoot     string
	maxProposals    int
}

// NewImprover creates an improver with one or two LLM providers.
func NewImprover(primary llm.Provider, local llm.Provider, projectRoot string) *Improver {
	return &Improver{
		primaryProvider: primary,
		localProvider:   local,
		projectRoot:     projectRoot,
		maxProposals:    7,
	}
}

// Propose generates improvement proposals from gap analysis.
func (imp *Improver) Propose(ctx context.Context, eval *EvaluationResult, gaps []GapAnalysis) ([]ImprovementProposal, error) {
	prompt := imp.buildPrompt(eval, gaps)

	var primaryProposals, localProposals []ImprovementProposal
	var primaryErr, localErr error

	// Get proposals from primary provider
	primaryProposals, primaryErr = imp.getProposals(ctx, imp.primaryProvider, prompt)
	if primaryErr != nil {
		// If local provider available, try it as fallback instead of failing
		if imp.localProvider != nil {
			fmt.Printf("[!] Primary provider failed (%v), falling back to local provider\n", primaryErr)
			localProposals, localErr = imp.getProposals(ctx, imp.localProvider, prompt)
			if localErr != nil {
				return nil, fmt.Errorf("both providers failed: primary: %v, local: %v", primaryErr, localErr)
			}
			return localProposals, nil
		}
		return nil, fmt.Errorf("primary LLM failed: %w", primaryErr)
	}

	// Get proposals from local provider (if available)
	if imp.localProvider != nil {
		localProposals, localErr = imp.getProposals(ctx, imp.localProvider, prompt)
		if localErr != nil {
			// Non-fatal: just use primary proposals
			localProposals = nil
		}
	}

	// Merge proposals from both providers
	merged := imp.mergeProposals(primaryProposals, localProposals)

	// Limit to max proposals
	if len(merged) > imp.maxProposals {
		merged = merged[:imp.maxProposals]
	}

	return merged, nil
}

// Apply applies proposals to the codebase, rolling back on build/test failures.
func (imp *Improver) Apply(proposals []ImprovementProposal) []ImprovementProposal {
	var results []ImprovementProposal

	for _, p := range proposals {
		applied := imp.applyOne(p)
		results = append(results, applied)
	}

	return results
}

func (imp *Improver) applyOne(p ImprovementProposal) ImprovementProposal {
	absPath := filepath.Join(imp.projectRoot, p.FilePath)

	// Read current file
	original, err := os.ReadFile(absPath)
	if err != nil {
		p.Error = fmt.Sprintf("read file: %v", err)
		return p
	}

	var newContent string
	switch p.Action {
	case "modify":
		if !strings.Contains(string(original), p.CurrentCode) {
			p.Error = "current_code not found in file"
			return p
		}
		newContent = strings.Replace(string(original), p.CurrentCode, p.NewCode, 1)
	case "add_code":
		// Add code at the end of the file (before the last closing brace if Go)
		newContent = string(original) + "\n" + p.NewCode + "\n"
	default:
		p.Error = fmt.Sprintf("unknown action: %s", p.Action)
		return p
	}

	// Write modified file
	if err := os.WriteFile(absPath, []byte(newContent), 0600); err != nil {
		p.Error = fmt.Sprintf("write file: %v", err)
		return p
	}

	// Run gofmt
	if err := runCommand(imp.projectRoot, "gofmt", "-w", absPath); err != nil {
		// Rollback
		os.WriteFile(absPath, original, 0600)
		p.Error = fmt.Sprintf("gofmt failed: %v", err)
		return p
	}

	// Build check
	if err := runCommand(imp.projectRoot, "go", "build", "./..."); err != nil {
		os.WriteFile(absPath, original, 0600)
		p.Error = fmt.Sprintf("build failed: %v", err)
		return p
	}

	// Test check
	if err := runCommand(imp.projectRoot, "go", "test",
		"./internal/detector/...", "./internal/payloads/..."); err != nil {
		os.WriteFile(absPath, original, 0600)
		p.Error = fmt.Sprintf("tests failed: %v", err)
		return p
	}

	p.Applied = true
	return p
}

func (imp *Improver) getProposals(ctx context.Context, provider llm.Provider, prompt string) ([]ImprovementProposal, error) {
	system := `You are an expert Go security engineer improving an API security fuzzer called Indago.
You produce JSON arrays of code improvement proposals. Each proposal must be GENERAL-PURPOSE —
no hardcoded target-specific values (no specific URLs, usernames, or application names).
All improvements must work against any API, not just the specific target being tested.

Return ONLY a JSON array of objects with these fields:
- category: one of "payload_generator", "detection_heuristic", "llm_prompt", "filter_tuning"
- file_path: relative path from project root (e.g., "internal/detector/anomaly.go")
- action: "modify" (replace existing code) or "add_code" (append new code)
- current_code: the exact code to replace (for "modify" only — must be a verbatim excerpt)
- new_code: the replacement or new code
- rationale: brief explanation of the general improvement

Return valid JSON only. No markdown, no explanation outside the JSON.`

	var result string
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		result, err = provider.AnalyzeWithSystem(ctx, system, prompt)
		if err == nil {
			break
		}
		if attempt < 2 {
			fmt.Printf("[!] LLM attempt %d failed: %v, retrying...\n", attempt+1, err)
			time.Sleep(5 * time.Second)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("after 3 attempts: %w", err)
	}

	return parseProposals(result)
}

func (imp *Improver) buildPrompt(eval *EvaluationResult, gaps []GapAnalysis) string {
	var b strings.Builder

	b.WriteString("# Current Benchmark Results\n\n")
	b.WriteString(fmt.Sprintf("Recall: %.2f | Precision: %.2f | F1: %.2f\n", eval.Recall, eval.Precision, eval.F1))
	b.WriteString(fmt.Sprintf("True Positives: %d | False Negatives: %d | False Positives: %d\n\n",
		len(eval.TruePositives), len(eval.FalseNegatives), len(eval.FalsePositives)))

	// False negatives detail
	b.WriteString("## False Negatives (Missed Vulnerabilities)\n\n")
	for _, g := range gaps {
		b.WriteString(fmt.Sprintf("### %s: %s\n", g.VulnID, g.VulnName))
		b.WriteString(fmt.Sprintf("- Class: %s\n", g.VulnClass))
		b.WriteString(fmt.Sprintf("- Endpoint: %s\n", g.Endpoint))
		b.WriteString(fmt.Sprintf("- Gap Type: %s\n", g.Gap))
		b.WriteString(fmt.Sprintf("- Notes: %s\n", g.Notes))
		b.WriteString(fmt.Sprintf("- Payloads Sent: %d\n", g.PayloadsSent))
		if g.ResponseCode > 0 {
			b.WriteString(fmt.Sprintf("- Sample Response Code: %d\n", g.ResponseCode))
		}
		if g.ResponseBody != "" {
			body := g.ResponseBody
			if len(body) > 200 {
				body = body[:200] + "... (truncated)"
			}
			b.WriteString(fmt.Sprintf("- Sample Response Body: %s\n", body))
		}
		b.WriteString("\n")
	}

	// False positives summary
	if len(eval.FalsePositives) > 0 {
		b.WriteString("## False Positives\n\n")
		fpSummary := make(map[string]int)
		for _, fp := range eval.FalsePositives {
			fpSummary[fp.Type]++
		}
		for t, count := range fpSummary {
			b.WriteString(fmt.Sprintf("- Type '%s': %d findings\n", t, count))
		}
		b.WriteString("\n")
	}

	// Source file excerpts (limit to 3 most relevant files to reduce prompt size)
	b.WriteString("## Relevant Source Files\n\n")
	files := imp.relevantFiles(gaps)
	if len(files) > 3 {
		files = files[:3]
	}
	for _, path := range files {
		absPath := filepath.Join(imp.projectRoot, path)
		content, err := os.ReadFile(absPath)
		if err != nil {
			continue
		}
		// Truncate large files
		text := string(content)
		if len(text) > 1500 {
			text = text[:1500] + "\n... (truncated)"
		}
		b.WriteString(fmt.Sprintf("### %s\n```go\n%s\n```\n\n", path, text))
	}

	b.WriteString("## Instructions\n\n")
	b.WriteString("Propose up to 5 improvements to fix the false negatives above.\n")
	b.WriteString("All improvements MUST be general-purpose and work against any API.\n")
	b.WriteString("Do NOT hardcode target-specific values (URLs, usernames, etc.).\n")
	b.WriteString("Focus on the most impactful changes first.\n")

	return b.String()
}

func (imp *Improver) relevantFiles(gaps []GapAnalysis) []string {
	fileSet := make(map[string]bool)

	for _, g := range gaps {
		switch g.Gap {
		case GapNoPayloads, GapPayloadIneffective:
			// Suggest payload generator files
			switch strings.ToLower(g.VulnClass) {
			case "sqli":
				fileSet["internal/payloads/injection.go"] = true
			case "bola", "idor", "bfla":
				fileSet["internal/payloads/bola.go"] = true
			case "mass_assignment":
				fileSet["internal/payloads/auth.go"] = true
			case "jwt_manipulation":
				fileSet["internal/payloads/jwt.go"] = true
			case "rate_limit":
				// Rate limit is passive, suggest passive check files
				fileSet["internal/payloads/generator.go"] = true
			case "enumeration":
				fileSet["internal/payloads/auth.go"] = true
				fileSet["internal/detector/anomaly.go"] = true
			default:
				fileSet["internal/payloads/generator.go"] = true
			}
		case GapDetectionMissed:
			fileSet["internal/detector/anomaly.go"] = true
			fileSet["internal/detector/errors.go"] = true
			fileSet["internal/detector/leaks.go"] = true
			fileSet["internal/detector/analyzer.go"] = true
		case GapFilteredOut:
			fileSet["internal/detector/filter.go"] = true
		case GapNewVulnClass:
			fileSet["internal/detector/anomaly.go"] = true
			fileSet["internal/payloads/generator.go"] = true
			fileSet["pkg/types/endpoint.go"] = true
		case GapEndpointNotScanned:
			fileSet["internal/payloads/generator.go"] = true
		}
	}

	var files []string
	for f := range fileSet {
		files = append(files, f)
	}
	return files
}

func (imp *Improver) mergeProposals(primary, local []ImprovementProposal) []ImprovementProposal {
	if len(local) == 0 {
		return primary
	}

	type proposalKey struct {
		file     string
		category ImprovementCategory
	}

	primaryMap := make(map[proposalKey]ImprovementProposal)
	for _, p := range primary {
		key := proposalKey{file: p.FilePath, category: p.Category}
		primaryMap[key] = p
	}

	var merged []ImprovementProposal

	// First, add consensus proposals (both agree on same file/category)
	localUsed := make(map[int]bool)
	for i, lp := range local {
		key := proposalKey{file: lp.FilePath, category: lp.Category}
		if _, exists := primaryMap[key]; exists {
			// Consensus: prefer primary's version (stronger reasoning)
			merged = append(merged, primaryMap[key])
			delete(primaryMap, key)
			localUsed[i] = true
		}
	}

	// Add remaining primary proposals
	for _, p := range primaryMap {
		merged = append(merged, p)
	}

	// Add unique local proposals
	for i, lp := range local {
		if !localUsed[i] {
			merged = append(merged, lp)
		}
	}

	return merged
}

func parseProposals(resp string) ([]ImprovementProposal, error) {
	// Strip markdown code fences if present
	resp = strings.TrimSpace(resp)
	if strings.HasPrefix(resp, "```") {
		lines := strings.Split(resp, "\n")
		var cleaned []string
		inBlock := false
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "```") {
				inBlock = !inBlock
				continue
			}
			if inBlock || !strings.HasPrefix(strings.TrimSpace(line), "```") {
				cleaned = append(cleaned, line)
			}
		}
		resp = strings.Join(cleaned, "\n")
	}

	// Find the JSON array
	start := strings.Index(resp, "[")
	end := strings.LastIndex(resp, "]")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON array found in response")
	}
	resp = resp[start : end+1]

	var proposals []ImprovementProposal
	if err := json.Unmarshal([]byte(resp), &proposals); err != nil {
		return nil, fmt.Errorf("parse proposals JSON: %w", err)
	}

	return proposals, nil
}

func runCommand(dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(output))
	}
	return nil
}
