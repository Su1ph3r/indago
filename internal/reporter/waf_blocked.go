package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// ExportWAFBlocked filters findings for WAF-blocked responses and writes them
func ExportWAFBlocked(scanResult *types.ScanResult, outputPath string) error {
	var blocked []types.WAFBlockedTarget

	wafCodes := map[int]bool{403: true, 406: true, 429: true, 418: true}

	for _, f := range scanResult.Findings {
		if f.Evidence == nil || f.Evidence.Response == nil {
			continue
		}

		isBlocked := wafCodes[f.Evidence.Response.StatusCode]
		if !isBlocked {
			// Check for WAF headers
			for header := range f.Evidence.Response.Headers {
				h := strings.ToLower(header)
				if strings.Contains(h, "waf") || strings.Contains(h, "firewall") ||
					strings.Contains(h, "cloudflare") || strings.Contains(h, "akamai") {
					isBlocked = true
					break
				}
			}
		}

		if isBlocked {
			blocked = append(blocked, types.WAFBlockedTarget{
				OriginalFindingID: f.ID,
				Endpoint:          f.Endpoint,
				Method:            f.Method,
				Parameter:         f.Parameter,
				OriginalPayload:   f.Payload,
				WAFResponseCode:   f.Evidence.Response.StatusCode,
				VulnerabilityType: f.Type,
			})
		}
	}

	export := types.WAFBlockedExport{
		ExportSource: "indago",
		ScanID:       scanResult.ScanID,
		Target:       scanResult.Target,
		TotalBlocked: len(blocked),
		Targets:      blocked,
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal WAF blocked export: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write WAF blocked export: %w", err)
	}

	return nil
}
