package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/su1ph3r/indago/pkg/types"
)

// ExportAriadne exports scan findings as attack paths for Ariadne consumption
func ExportAriadne(scanResult *types.ScanResult, outputPath string) error {
	export := types.AriadneExport{
		ToolSource: "indago",
		ScanID:     scanResult.ScanID,
		Target:     scanResult.Target,
		Timestamp:  time.Now().Format(time.RFC3339),
	}

	// Group findings by endpoint key (Method:Path)
	groups := make(map[string][]types.Finding)
	groupMeta := make(map[string][2]string) // key -> [method, endpoint]

	for _, f := range scanResult.Findings {
		key := f.Method + ":" + f.Endpoint
		groups[key] = append(groups[key], f)
		if _, exists := groupMeta[key]; !exists {
			groupMeta[key] = [2]string{f.Method, f.Endpoint}
		}
	}

	// Track endpoints with auth_bypass or idor findings for prerequisite derivation
	authBypassEndpoints := make(map[string]bool)
	for key, findings := range groups {
		for _, f := range findings {
			if f.Type == "auth_bypass" || f.Type == "idor" {
				authBypassEndpoints[key] = true
				break
			}
		}
	}

	// Build attack paths
	var paths []types.AriadneAttackPath

	for key, findings := range groups {
		meta := groupMeta[key]
		method := meta[0]
		endpoint := meta[1]

		// Map findings to AriadneFinding
		var ariadneFindings []types.AriadneFinding
		highestSev := types.SeverityInfo

		for _, f := range findings {
			ariadneFindings = append(ariadneFindings, types.AriadneFinding{
				ID:          f.ID,
				Type:        f.Type,
				Severity:    f.Severity,
				Confidence:  f.Confidence,
				Title:       f.Title,
				Description: f.Description,
				Parameter:   f.Parameter,
				Payload:     f.Payload,
				CWE:         f.CWE,
			})

			if severityRank(f.Severity) < severityRank(highestSev) {
				highestSev = f.Severity
			}
		}

		// Derive prerequisites: other endpoints with auth_bypass/idor
		// that share the same path prefix
		var prerequisites []string
		var successors []string

		basePath := pathPrefix(endpoint)

		for otherKey := range authBypassEndpoints {
			if otherKey == key {
				continue
			}
			otherMeta := groupMeta[otherKey]
			otherEndpoint := otherMeta[1]
			if strings.HasPrefix(endpoint, pathPrefix(otherEndpoint)) ||
				strings.HasPrefix(otherEndpoint, basePath) {
				prerequisites = append(prerequisites, otherKey)
			}
		}

		// Successors: endpoints that share the same path prefix as this endpoint
		if authBypassEndpoints[key] {
			for otherKey := range groups {
				if otherKey == key {
					continue
				}
				otherMeta := groupMeta[otherKey]
				otherEndpoint := otherMeta[1]
				if strings.HasPrefix(otherEndpoint, basePath) {
					successors = append(successors, otherKey)
				}
			}
		}

		paths = append(paths, types.AriadneAttackPath{
			Endpoint:      endpoint,
			Method:        method,
			Severity:      highestSev,
			Findings:      ariadneFindings,
			Prerequisites: prerequisites,
			Successors:    successors,
		})
	}

	// Sort attack paths by severity (highest first)
	sort.Slice(paths, func(i, j int) bool {
		return severityRank(paths[i].Severity) < severityRank(paths[j].Severity)
	})

	export.AttackPaths = paths

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal Ariadne export: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write Ariadne export: %w", err)
	}

	return nil
}

// pathPrefix extracts the base path prefix up to (but not including) the last segment
func pathPrefix(path string) string {
	// Remove trailing slash
	path = strings.TrimRight(path, "/")
	idx := strings.LastIndex(path, "/")
	if idx <= 0 {
		return "/"
	}
	return path[:idx]
}
