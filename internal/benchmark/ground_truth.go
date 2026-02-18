// Package benchmark provides an automated benchmark loop for evaluating
// and iteratively improving Indago's detection capabilities.
package benchmark

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
	"gopkg.in/yaml.v3"
)

// GapType classifies why a vulnerability was missed.
type GapType string

const (
	GapEndpointNotScanned GapType = "GAP_ENDPOINT_NOT_SCANNED"
	GapNoPayloads         GapType = "GAP_NO_PAYLOADS"
	GapPayloadIneffective GapType = "GAP_PAYLOAD_INEFFECTIVE"
	GapDetectionMissed    GapType = "GAP_DETECTION_MISSED"
	GapFilteredOut        GapType = "GAP_FILTERED_OUT"
	GapNewVulnClass       GapType = "GAP_NEW_VULN_CLASS"
)

// Vulnerability describes a known vulnerability in the ground truth.
type Vulnerability struct {
	ID          string     `yaml:"id"`
	Name        string     `yaml:"name"`
	Class       string     `yaml:"class"`
	Endpoint    string     `yaml:"endpoint"`
	Method      string     `yaml:"method"`
	Parameter   string     `yaml:"parameter,omitempty"`
	Description string     `yaml:"description"`
	MatchRules  MatchRules `yaml:"match_rules"`
	MinMatches  int        `yaml:"min_matches"`
}

// MatchRules defines how to match findings to a ground truth vulnerability.
type MatchRules struct {
	FindingTypes    []string `yaml:"finding_types"`
	MinSeverity     string   `yaml:"min_severity,omitempty"`
	MinConfidence   string   `yaml:"min_confidence,omitempty"`
	EndpointPattern string   `yaml:"endpoint_pattern,omitempty"`
	Method          string   `yaml:"method,omitempty"`
}

// GroundTruth holds all known vulnerabilities for a target.
type GroundTruth struct {
	Vulnerabilities []Vulnerability `yaml:"vulnerabilities"`
}

// MatchResult records whether a ground truth entry was matched.
type MatchResult struct {
	Vuln     Vulnerability
	Matched  bool
	Matches  []types.Finding // findings that matched
	GapType  GapType         // populated if not matched
	GapNotes string          // human-readable gap explanation
}

// LoadGroundTruth reads a ground truth YAML file.
func LoadGroundTruth(path string) (*GroundTruth, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read ground truth: %w", err)
	}
	var gt GroundTruth
	if err := yaml.Unmarshal(data, &gt); err != nil {
		return nil, fmt.Errorf("parse ground truth: %w", err)
	}
	// Default min_matches to 1
	for i := range gt.Vulnerabilities {
		if gt.Vulnerabilities[i].MinMatches < 1 {
			gt.Vulnerabilities[i].MinMatches = 1
		}
	}
	return &gt, nil
}

// MatchFindings compares scan findings against ground truth and produces
// per-vulnerability match results along with a list of false positives.
func MatchFindings(gt *GroundTruth, findings []types.Finding) (results []MatchResult, falsePositives []types.Finding) {
	matched := make(map[int]bool) // index into findings that matched at least one vuln

	for _, vuln := range gt.Vulnerabilities {
		mr := MatchResult{Vuln: vuln}
		for i, f := range findings {
			if matchesFinding(vuln.MatchRules, f) {
				mr.Matches = append(mr.Matches, f)
				matched[i] = true
			}
		}
		mr.Matched = len(mr.Matches) >= vuln.MinMatches
		results = append(results, mr)
	}

	// False positives: findings not matched to any ground truth entry
	for i, f := range findings {
		if !matched[i] {
			falsePositives = append(falsePositives, f)
		}
	}
	return results, falsePositives
}

// matchesFinding checks if a single finding matches the given rules.
func matchesFinding(rules MatchRules, f types.Finding) bool {
	// Type match: finding type must be in the allowed list
	if !matchesAnyType(rules.FindingTypes, f.Type) {
		return false
	}

	// Endpoint pattern match (glob-style)
	if rules.EndpointPattern != "" && !matchGlob(rules.EndpointPattern, f.Endpoint) {
		return false
	}

	// Method match
	if rules.Method != "" && !strings.EqualFold(rules.Method, f.Method) {
		return false
	}

	// Severity check
	if rules.MinSeverity != "" && severityRank(f.Severity) < severityRank(rules.MinSeverity) {
		return false
	}

	// Confidence check
	if rules.MinConfidence != "" && confidenceRank(f.Confidence) < confidenceRank(rules.MinConfidence) {
		return false
	}

	return true
}

func matchesAnyType(allowed []string, findingType string) bool {
	ft := strings.ToLower(findingType)
	for _, t := range allowed {
		if strings.ToLower(t) == ft {
			return true
		}
	}
	return false
}

// matchGlob performs simple glob matching where * and {param} patterns match
// any sequence of non-slash characters within a single path segment.
func matchGlob(pattern, value string) bool {
	// Normalize
	pattern = strings.TrimRight(pattern, "/")
	value = strings.TrimRight(value, "/")

	patParts := strings.Split(pattern, "/")
	valParts := strings.Split(value, "/")

	if len(patParts) != len(valParts) {
		return false
	}

	for i, pp := range patParts {
		if pp == "*" || isTemplateParam(pp) {
			continue
		}
		vp := valParts[i]
		// Also treat value-side template params as wildcards
		if isTemplateParam(vp) {
			continue
		}
		if !strings.EqualFold(pp, vp) {
			return false
		}
	}
	return true
}

// isTemplateParam checks if a path segment is a template parameter like {username}.
func isTemplateParam(s string) bool {
	return strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func confidenceRank(c string) int {
	switch strings.ToLower(c) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
