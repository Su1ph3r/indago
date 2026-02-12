// Package payloads provides attack payload generation
package payloads

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/su1ph3r/indago/pkg/types"
)

// SecurityHeaderChecker sends a baseline request and checks for missing
// API-relevant security headers. It produces at most one aggregated finding
// per endpoint listing all missing headers.
type SecurityHeaderChecker struct{}

// NewSecurityHeaderChecker creates a new security header checker.
func NewSecurityHeaderChecker() *SecurityHeaderChecker {
	return &SecurityHeaderChecker{}
}

// Type returns the checker type.
func (c *SecurityHeaderChecker) Type() string {
	return types.AttackMissingHeaders
}

// Check makes a baseline request and evaluates security headers.
func (c *SecurityHeaderChecker) Check(ctx context.Context, endpoint types.Endpoint, client *http.Client) []types.Finding {
	url := endpoint.FullPath()
	if url == "" {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, endpoint.Method, url, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	var missing []string
	highestSeverity := types.SeverityLow

	// Check HSTS
	if resp.Header.Get("Strict-Transport-Security") == "" {
		missing = append(missing, "Strict-Transport-Security (HSTS)")
	}

	// Check X-Content-Type-Options
	if !strings.EqualFold(resp.Header.Get("X-Content-Type-Options"), "nosniff") {
		missing = append(missing, "X-Content-Type-Options: nosniff")
	}

	// Check Cache-Control on auth-sensitive endpoints
	if isAuthSensitive(endpoint.Path) {
		cc := strings.ToLower(resp.Header.Get("Cache-Control"))
		if !strings.Contains(cc, "no-store") {
			missing = append(missing, "Cache-Control: no-store (auth-sensitive endpoint)")
			highestSeverity = types.SeverityMedium
		}
	}

	if len(missing) == 0 {
		return nil
	}

	return []types.Finding{
		{
			ID:          fmt.Sprintf("hdr-%s-%s", endpoint.Method, sanitizePath(endpoint.Path)),
			Type:        types.AttackMissingHeaders,
			Severity:    highestSeverity,
			Confidence:  types.ConfidenceHigh,
			Title:       "Missing API Security Headers",
			Description: fmt.Sprintf("The following security headers are missing on %s %s: %s", endpoint.Method, endpoint.Path, strings.Join(missing, "; ")),
			Endpoint:    endpoint.Path,
			Method:      endpoint.Method,
			CWE:         "CWE-693",
			Remediation: "Add the missing security headers. For APIs: set Strict-Transport-Security, X-Content-Type-Options: nosniff, and Cache-Control: no-store on sensitive endpoints.",
			Timestamp:   time.Now(),
		},
	}
}
