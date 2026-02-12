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

// CORSChecker tests for CORS misconfiguration by sending requests with
// attacker-controlled Origin headers.
type CORSChecker struct{}

// NewCORSChecker creates a new CORS checker.
func NewCORSChecker() *CORSChecker {
	return &CORSChecker{}
}

// Type returns the checker type.
func (c *CORSChecker) Type() string {
	return types.AttackCORSMisconfig
}

// Check tests CORS configuration for the endpoint.
func (c *CORSChecker) Check(ctx context.Context, endpoint types.Endpoint, client *http.Client) []types.Finding {
	url := endpoint.FullPath()
	if url == "" {
		return nil
	}

	var findings []types.Finding

	// Test 1: arbitrary origin reflection
	if f := c.testOrigin(ctx, client, endpoint, "https://evil-cors-test.com"); f != nil {
		findings = append(findings, *f)
	}

	// Test 2: null origin bypass
	if f := c.testOrigin(ctx, client, endpoint, "null"); f != nil {
		findings = append(findings, *f)
	}

	return findings
}

func (c *CORSChecker) testOrigin(ctx context.Context, client *http.Client, endpoint types.Endpoint, origin string) *types.Finding {
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, endpoint.FullPath(), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Origin", origin)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")

	if acao == "" {
		return nil
	}

	var severity string
	var title string
	var desc string

	reflected := strings.EqualFold(acao, origin)
	wildcard := acao == "*"

	switch {
	case (reflected || wildcard) && acac:
		severity = types.SeverityHigh
		title = "CORS Misconfiguration — Credentials Exposed"
		desc = fmt.Sprintf("Origin '%s' is allowed with Access-Control-Allow-Credentials: true. An attacker can read authenticated responses cross-origin.", origin)
	case reflected:
		severity = types.SeverityMedium
		title = "CORS Misconfiguration — Origin Reflected"
		desc = fmt.Sprintf("Origin '%s' is reflected in Access-Control-Allow-Origin. Cross-origin reads possible if credentials are added later.", origin)
	case wildcard:
		severity = types.SeverityLow
		title = "CORS Misconfiguration — Wildcard Origin"
		desc = "Access-Control-Allow-Origin is set to '*'. Any site can read responses (without credentials)."
	default:
		return nil
	}

	return &types.Finding{
		ID:          fmt.Sprintf("cors-%s-%s-%s", endpoint.Method, sanitizePath(endpoint.Path), origin),
		Type:        types.AttackCORSMisconfig,
		Severity:    severity,
		Confidence:  types.ConfidenceHigh,
		Title:       title,
		Description: desc,
		Endpoint:    endpoint.Path,
		Method:      endpoint.Method,
		CWE:         "CWE-942",
		Remediation: "Do not reflect arbitrary Origins. Use an explicit allowlist of trusted origins and never combine wildcard with credentials.",
		Timestamp:   time.Now(),
	}
}
