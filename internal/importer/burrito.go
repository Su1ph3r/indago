package importer

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

// LoadBurritoBypasses reads and parses a BypassBurrito results file
func LoadBurritoBypasses(path string) (*types.BurritoBypassImport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read burrito bypasses file: %w", err)
	}

	var imp types.BurritoBypassImport
	if err := json.Unmarshal(data, &imp); err != nil {
		return nil, fmt.Errorf("failed to parse burrito bypasses: %w", err)
	}

	// Validate export source if set
	if imp.ExportSource != "" && imp.ExportSource != "bypass-burrito" {
		return nil, fmt.Errorf("unsupported export_source '%s', expected 'bypass-burrito'", imp.ExportSource)
	}

	if len(imp.Bypasses) == 0 {
		return nil, fmt.Errorf("no bypasses found in import file")
	}

	return &imp, nil
}

// BypassesToFuzzRequests converts BypassBurrito bypasses into FuzzRequests
// that can be fed into the fuzzing engine for re-testing.
func BypassesToFuzzRequests(imp *types.BurritoBypassImport, endpoints []types.Endpoint) []payloads.FuzzRequest {
	// Build a lookup map of method:path -> Endpoint
	endpointMap := make(map[string]types.Endpoint)
	for _, ep := range endpoints {
		key := strings.ToUpper(ep.Method) + ":" + ep.Path
		endpointMap[key] = ep
	}

	var requests []payloads.FuzzRequest

	for _, bypass := range imp.Bypasses {
		key := strings.ToUpper(bypass.Method) + ":" + bypass.Endpoint
		ep, found := endpointMap[key]

		if !found {
			// Create a minimal endpoint from the bypass data
			ep = types.Endpoint{
				Method:  strings.ToUpper(bypass.Method),
				Path:    bypass.Endpoint,
				Headers: bypass.Headers,
			}
		}

		payload := payloads.Payload{
			Value:    bypass.BypassPayload,
			Type:     bypass.VulnerabilityType,
			Category: "waf_bypass",
			Description: fmt.Sprintf("WAF bypass via %s technique",
				bypass.BypassTechnique),
			Metadata: map[string]string{
				"source":           "bypass-burrito",
				"priority":         "high",
				"bypass_technique": bypass.BypassTechnique,
			},
		}

		// Find the target parameter
		var param *types.Parameter
		if bypass.Parameter != "" {
			for i := range ep.Parameters {
				if strings.EqualFold(ep.Parameters[i].Name, bypass.Parameter) {
					param = &ep.Parameters[i]
					break
				}
			}
		}

		// Fallback to first parameter if no match
		if param == nil && len(ep.Parameters) > 0 {
			param = &ep.Parameters[0]
		}

		// Determine position
		position := "body"
		if param != nil && param.In != "" {
			position = param.In
		}

		requests = append(requests, payloads.FuzzRequest{
			Endpoint: ep,
			Param:    param,
			Payload:  payload,
			Position: position,
		})
	}

	return requests
}
