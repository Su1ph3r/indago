// Package detector provides response analysis and vulnerability detection
package detector

import (
	"sort"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// FindingFilter filters and deduplicates findings
type FindingFilter struct {
	settings types.FilterSettings
}

// NewFindingFilter creates a new finding filter
func NewFindingFilter(settings types.FilterSettings) *FindingFilter {
	return &FindingFilter{
		settings: settings,
	}
}

// Filter applies filtering rules to findings
func (f *FindingFilter) Filter(findings []types.Finding) []types.Finding {
	if !f.settings.Enabled {
		return findings
	}

	var filtered []types.Finding

	for _, finding := range findings {
		// Calculate confidence score
		confidence := f.calculateConfidence(finding)

		// Filter by minimum confidence
		if confidence < f.settings.MinConfidence {
			continue
		}

		// Filter by minimum severity
		if !f.meetsSeverityThreshold(finding.Severity, f.settings.MinSeverity) {
			continue
		}

		// Update finding confidence based on calculated score
		finding.Confidence = f.confidenceToString(confidence)

		filtered = append(filtered, finding)
	}

	// Deduplicate if enabled
	if f.settings.DedupeByEndpoint {
		filtered = f.deduplicateByEndpoint(filtered)
	}

	return filtered
}

// calculateConfidence calculates a confidence score for a finding
func (f *FindingFilter) calculateConfidence(finding types.Finding) float64 {
	score := 0.5 // Base score

	// Evidence quality factors
	if finding.Evidence != nil {
		// Has response evidence
		if finding.Evidence.Response != nil {
			score += 0.1

			// Response indicates error
			if finding.Evidence.Response.StatusCode >= 500 {
				score += 0.1
			}

			// Response has matched data
			if len(finding.Evidence.MatchedData) > 0 {
				score += 0.15
			}
		}

		// Has baseline comparison
		if finding.Evidence.BaselineResp != nil {
			score += 0.1

			// Significant difference from baseline
			if finding.Evidence.Response != nil && finding.Evidence.BaselineResp != nil {
				if finding.Evidence.Response.StatusCode != finding.Evidence.BaselineResp.StatusCode {
					score += 0.1
				}
			}
		}
	}

	// Attack type confidence adjustments
	score += f.attackTypeConfidenceBoost(finding.Type)

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// attackTypeConfidenceBoost returns confidence adjustment based on attack type
func (f *FindingFilter) attackTypeConfidenceBoost(attackType string) float64 {
	// Some attack types are more reliable indicators
	highConfidenceTypes := map[string]float64{
		types.AttackSQLi:          0.05, // SQL errors are pretty reliable
		types.AttackCommandInject: 0.05,
		types.AttackPathTraversal: 0.05,
	}

	// Some types tend to have more false positives
	lowConfidenceTypes := map[string]float64{
		types.AttackXSS:                -0.05, // Reflection != exploitation
		types.AttackRateLimit:          -0.1,  // Often not a real vulnerability
		types.AttackMissingHeaders:     -0.1,  // Informational, not exploitable alone
		types.AttackContentTypeConfusion: -0.05, // Often benign parser flexibility
	}

	if boost, ok := highConfidenceTypes[attackType]; ok {
		return boost
	}
	if penalty, ok := lowConfidenceTypes[attackType]; ok {
		return penalty
	}

	return 0
}

// meetsSeverityThreshold checks if a severity meets the minimum threshold
func (f *FindingFilter) meetsSeverityThreshold(severity, minSeverity string) bool {
	severityOrder := map[string]int{
		types.SeverityCritical: 5,
		types.SeverityHigh:     4,
		types.SeverityMedium:   3,
		types.SeverityLow:      2,
		types.SeverityInfo:     1,
	}

	severityVal := severityOrder[severity]
	minVal := severityOrder[minSeverity]

	// Default to including if unknown severity
	if severityVal == 0 || minVal == 0 {
		return true
	}

	return severityVal >= minVal
}

// confidenceToString converts confidence score to string level
func (f *FindingFilter) confidenceToString(score float64) string {
	if score >= 0.8 {
		return types.ConfidenceHigh
	} else if score >= 0.5 {
		return types.ConfidenceMedium
	}
	return types.ConfidenceLow
}

// deduplicateByEndpoint removes duplicate findings for the same endpoint/type
func (f *FindingFilter) deduplicateByEndpoint(findings []types.Finding) []types.Finding {
	// Sort by severity (highest first) so we keep the most severe
	sort.Slice(findings, func(i, j int) bool {
		return severityValue(findings[i].Severity) > severityValue(findings[j].Severity)
	})

	seen := make(map[string]bool)
	var deduplicated []types.Finding

	for _, finding := range findings {
		// Create a key for deduplication
		key := f.dedupeKey(finding)

		if !seen[key] {
			seen[key] = true
			deduplicated = append(deduplicated, finding)
		}
	}

	return deduplicated
}

// dedupeKey generates a deduplication key for a finding
func (f *FindingFilter) dedupeKey(finding types.Finding) string {
	// Dedupe by endpoint + attack type + parameter
	return strings.Join([]string{
		finding.Method,
		finding.Endpoint,
		finding.Type,
		finding.Parameter,
	}, ":")
}

// severityValue returns numeric value for severity comparison
func severityValue(severity string) int {
	switch severity {
	case types.SeverityCritical:
		return 5
	case types.SeverityHigh:
		return 4
	case types.SeverityMedium:
		return 3
	case types.SeverityLow:
		return 2
	case types.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// NoiseFilter filters out common false positives and noise
type NoiseFilter struct {
	patterns []NoisePattern
}

// NoisePattern represents a pattern to filter out
type NoisePattern struct {
	Name        string
	Condition   func(finding types.Finding) bool
	Description string
}

// NewNoiseFilter creates a noise filter with default patterns
func NewNoiseFilter() *NoiseFilter {
	return &NoiseFilter{
		patterns: []NoisePattern{
			{
				Name: "generic_404",
				Condition: func(f types.Finding) bool {
					if f.Evidence == nil || f.Evidence.Response == nil {
						return false
					}
					// Filter generic 404s that aren't interesting
					return f.Evidence.Response.StatusCode == 404 &&
						f.Type != types.AttackIDOR &&
						f.Type != types.AttackBOLA
				},
				Description: "Generic 404 responses",
			},
			{
				Name: "rate_limit_normal",
				Condition: func(f types.Finding) bool {
					// Filter rate limit findings with 429 (expected behavior)
					return f.Type == types.AttackRateLimit &&
						f.Evidence != nil &&
						f.Evidence.Response != nil &&
						f.Evidence.Response.StatusCode == 429
				},
				Description: "Normal rate limiting (429 response)",
			},
			{
				Name: "empty_payload_reflection",
				Condition: func(f types.Finding) bool {
					// Filter XSS findings with empty or trivial payloads
					return f.Type == types.AttackXSS &&
						(f.Payload == "" || len(f.Payload) < 3)
				},
				Description: "Empty or trivial XSS payloads",
			},
			{
				Name: "method_tampering_options",
				Condition: func(f types.Finding) bool {
					// OPTIONS is normal CORS preflight, not a method tampering finding
					return f.Type == types.AttackMethodTampering &&
						f.Method == "OPTIONS"
				},
				Description: "Method tampering on OPTIONS (normal CORS preflight)",
			},
		},
	}
}

// Filter applies noise filtering to findings
func (n *NoiseFilter) Filter(findings []types.Finding) []types.Finding {
	var filtered []types.Finding

	for _, finding := range findings {
		isNoise := false
		for _, pattern := range n.patterns {
			if pattern.Condition(finding) {
				isNoise = true
				break
			}
		}
		if !isNoise {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

// AddPattern adds a custom noise pattern
func (n *NoiseFilter) AddPattern(pattern NoisePattern) {
	n.patterns = append(n.patterns, pattern)
}

// CombinedFilter combines multiple filters
type CombinedFilter struct {
	confidenceFilter *FindingFilter
	noiseFilter      *NoiseFilter
}

// NewCombinedFilter creates a combined filter
func NewCombinedFilter(settings types.FilterSettings) *CombinedFilter {
	return &CombinedFilter{
		confidenceFilter: NewFindingFilter(settings),
		noiseFilter:      NewNoiseFilter(),
	}
}

// Filter applies all filters in sequence
func (c *CombinedFilter) Filter(findings []types.Finding) []types.Finding {
	// First apply noise filtering
	filtered := c.noiseFilter.Filter(findings)

	// Then apply confidence/severity filtering
	filtered = c.confidenceFilter.Filter(filtered)

	return filtered
}
