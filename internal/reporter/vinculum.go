package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/su1ph3r/indago/pkg/types"
)

// ExportVinculum exports scan findings in Vinculum correlation format
func ExportVinculum(scanResult *types.ScanResult, outputPath string) error {
	export := types.VinculumExport{
		ToolSource: "indago",
		ScanID:     scanResult.ScanID,
		Target:     scanResult.Target,
		Timestamp:  time.Now().Format(time.RFC3339),
	}

	for _, f := range scanResult.Findings {
		vf := types.VinculumFinding{
			ID:          f.ID,
			Type:        f.Type,
			Severity:    f.Severity,
			Confidence:  f.Confidence,
			Title:       f.Title,
			Description: f.Description,
			Endpoint:    f.Endpoint,
			Method:      f.Method,
			Parameter:   f.Parameter,
			CWE:         f.CWE,
		}

		if f.Evidence != nil {
			if f.Evidence.Request != nil {
				req := f.Evidence.Request
				raw := fmt.Sprintf("%s %s\n", req.Method, req.URL)
				for k, v := range req.Headers {
					raw += fmt.Sprintf("%s: %s\n", k, v)
				}
				if req.Body != "" {
					raw += "\n" + req.Body
				}
				vf.RawRequest = raw
			}

			if f.Evidence.Response != nil {
				resp := f.Evidence.Response
				raw := fmt.Sprintf("%s\n", resp.Status)
				for k, v := range resp.Headers {
					raw += fmt.Sprintf("%s: %s\n", k, v)
				}
				body := resp.Body
				if len(body) > 2000 {
					body = body[:2000]
				}
				if body != "" {
					raw += "\n" + body
				}
				vf.RawResponse = raw
			}
		}

		export.Findings = append(export.Findings, vf)
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal Vinculum export: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write Vinculum export: %w", err)
	}

	return nil
}
