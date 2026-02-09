package importer

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// LoadTargets loads and parses a target import file from Reticustos or Ariadne
func LoadTargets(path string) (*types.TargetImport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read targets file: %w", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse targets file: %w", err)
	}

	var imp types.TargetImport
	if err := json.Unmarshal(data, &imp); err != nil {
		return nil, fmt.Errorf("failed to parse target import: %w", err)
	}

	// Auto-detect source if not set
	if imp.ExportSource == "" {
		if _, ok := raw["format"]; ok {
			imp.ExportSource = "ariadne"
		}
	}

	// Validate export source
	validSources := map[string]bool{"reticustos": true, "ariadne": true}
	if imp.ExportSource != "" && !validSources[imp.ExportSource] {
		return nil, fmt.Errorf("unsupported export_source '%s', expected 'reticustos' or 'ariadne'", imp.ExportSource)
	}

	return &imp, nil
}

// ToEndpoints converts imported endpoints to Indago Endpoint structs
func ToEndpoints(imp *types.TargetImport) []types.Endpoint {
	var endpoints []types.Endpoint

	baseURL := imp.TargetBaseURL

	for _, ep := range imp.Endpoints {
		epBaseURL := ep.BaseURL
		if epBaseURL == "" {
			epBaseURL = baseURL
		}
		if epBaseURL == "" {
			// Build from port/protocol
			protocol := ep.Protocol
			if protocol == "" {
				protocol = "https"
			}
			port := ep.Port
			if port == 0 {
				if protocol == "https" {
					port = 443
				} else {
					port = 80
				}
			}
			epBaseURL = fmt.Sprintf("%s://target:%d", protocol, port)
			log.Printf("Warning: no base URL for endpoint %s, using placeholder %s", ep.Path, epBaseURL)
		}

		method := strings.ToUpper(ep.Method)
		if method == "" {
			method = "GET"
		}

		// Convert params to Parameters
		var params []types.Parameter
		for _, p := range ep.Params {
			params = append(params, types.Parameter{
				Name: p,
				In:   "query",
				Type: "string",
			})
		}

		endpoints = append(endpoints, types.Endpoint{
			Method:     method,
			Path:       ep.Path,
			BaseURL:    epBaseURL,
			Parameters: params,
		})
	}

	return endpoints
}
