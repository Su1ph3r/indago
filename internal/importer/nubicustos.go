package importer

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// LoadNubicustosFindings reads and parses a Nubicustos cloud audit export
func LoadNubicustosFindings(path string) (*types.NubicustosImport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read nubicustos file: %w", err)
	}

	var imp types.NubicustosImport
	if err := json.Unmarshal(data, &imp); err != nil {
		return nil, fmt.Errorf("failed to parse nubicustos findings: %w", err)
	}

	if imp.ExportSource != "" && imp.ExportSource != "nubicustos" {
		return nil, fmt.Errorf("unsupported export_source '%s', expected 'nubicustos'", imp.ExportSource)
	}

	if len(imp.Findings) == 0 {
		return nil, fmt.Errorf("no findings in nubicustos import file")
	}

	return &imp, nil
}

// EnrichEndpointsFromCloud maps cloud findings to API attack vectors and enriches endpoints
func EnrichEndpointsFromCloud(imp *types.NubicustosImport, endpoints []types.Endpoint) []types.Endpoint {
	for i := range endpoints {
		for _, finding := range imp.Findings {
			tags := mapCloudFindingToTags(finding)
			endpoints[i].Tags = appendUniqueTags(endpoints[i].Tags, tags...)

			vectors := mapCloudFindingToAttacks(finding)
			endpoints[i].SuggestedAttacks = appendUniqueAttacks(endpoints[i].SuggestedAttacks, vectors...)
		}
	}
	return endpoints
}

// mapCloudFindingToTags converts cloud findings to contextual tags
func mapCloudFindingToTags(finding types.NubicustosCloudFinding) []string {
	var tags []string
	switch {
	case strings.Contains(finding.Type, "s3_public"):
		tags = append(tags, "cloud:s3_public", "ssrf_target")
	case strings.Contains(finding.Type, "iam"):
		tags = append(tags, "cloud:iam_issue", "auth_bypass_candidate")
	case strings.Contains(finding.Type, "security_group"):
		tags = append(tags, "cloud:open_sg", "network_exposure")
	case strings.Contains(finding.Type, "rds_public"):
		tags = append(tags, "cloud:rds_public", "data_exposure")
	case strings.Contains(finding.Type, "lambda"):
		tags = append(tags, "cloud:lambda_issue", "injection_target")
	default:
		tags = append(tags, "cloud:"+finding.Type)
	}
	return tags
}

// mapCloudFindingToAttacks maps cloud findings to suggested API attack vectors
func mapCloudFindingToAttacks(finding types.NubicustosCloudFinding) []types.AttackVector {
	var attacks []types.AttackVector
	rationale := fmt.Sprintf("Cloud finding: %s (%s)", finding.Type, finding.Description)

	switch {
	case strings.Contains(finding.Type, "s3_public"):
		attacks = append(attacks,
			types.AttackVector{Type: types.AttackSSRF, Category: "cloud", Priority: "high", Rationale: rationale},
			types.AttackVector{Type: types.AttackPathTraversal, Category: "cloud", Priority: "medium", Rationale: rationale},
		)
	case strings.Contains(finding.Type, "iam"):
		attacks = append(attacks,
			types.AttackVector{Type: types.AttackAuthBypass, Category: "cloud", Priority: "high", Rationale: rationale},
			types.AttackVector{Type: types.AttackBFLA, Category: "cloud", Priority: "high", Rationale: rationale},
		)
	case strings.Contains(finding.Type, "security_group"):
		attacks = append(attacks,
			types.AttackVector{Type: types.AttackSSRF, Category: "cloud", Priority: "medium", Rationale: rationale},
		)
	case strings.Contains(finding.Type, "rds_public"):
		attacks = append(attacks,
			types.AttackVector{Type: types.AttackSQLi, Category: "cloud", Priority: "high", Rationale: rationale},
			types.AttackVector{Type: types.AttackNoSQLi, Category: "cloud", Priority: "medium", Rationale: rationale},
		)
	case strings.Contains(finding.Type, "lambda"):
		attacks = append(attacks,
			types.AttackVector{Type: types.AttackCommandInject, Category: "cloud", Priority: "high", Rationale: rationale},
			types.AttackVector{Type: types.AttackSSTI, Category: "cloud", Priority: "medium", Rationale: rationale},
		)
	}
	return attacks
}

// appendUniqueTags appends tags to a slice, skipping duplicates
func appendUniqueTags(slice []string, items ...string) []string {
	seen := make(map[string]bool)
	for _, s := range slice {
		seen[s] = true
	}
	for _, item := range items {
		if !seen[item] {
			slice = append(slice, item)
			seen[item] = true
		}
	}
	return slice
}

// appendUniqueAttacks appends attack vectors to a slice, skipping duplicates by Type
func appendUniqueAttacks(slice []types.AttackVector, items ...types.AttackVector) []types.AttackVector {
	seen := make(map[string]bool)
	for _, v := range slice {
		seen[v.Type] = true
	}
	for _, item := range items {
		if !seen[item.Type] {
			slice = append(slice, item)
			seen[item.Type] = true
		}
	}
	return slice
}
