package detector

import (
	"fmt"
	"strings"
	"sync"

	"github.com/su1ph3r/indago/pkg/types"
)

// securityHeader defines a required security header and its metadata.
type securityHeader struct {
	Name        string
	CWE         string
	Description string
	Remediation string
}

// requiredSecurityHeaders lists the headers every HTTP response should include.
var requiredSecurityHeaders = []securityHeader{
	{
		Name:        "Strict-Transport-Security",
		CWE:         "CWE-319",
		Description: "The Strict-Transport-Security header (HSTS) tells browsers to only access the site over HTTPS, preventing protocol downgrade attacks and cookie hijacking.",
		Remediation: "Add the header: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
	},
	{
		Name:        "X-Content-Type-Options",
		CWE:         "CWE-693",
		Description: "The X-Content-Type-Options header prevents browsers from MIME-type sniffing a response away from the declared Content-Type, reducing the risk of drive-by downloads and content-type confusion attacks.",
		Remediation: "Add the header: X-Content-Type-Options: nosniff",
	},
	{
		Name:        "X-Frame-Options",
		CWE:         "CWE-1021",
		Description: "The X-Frame-Options header prevents the page from being embedded in iframes, protecting against clickjacking attacks.",
		Remediation: "Add the header: X-Frame-Options: DENY (or SAMEORIGIN if framing from the same origin is required)",
	},
	{
		Name:        "Content-Security-Policy",
		CWE:         "CWE-693",
		Description: "The Content-Security-Policy header restricts which resources the browser is allowed to load, mitigating cross-site scripting (XSS) and data injection attacks.",
		Remediation: "Add a Content-Security-Policy header with a restrictive policy, e.g.: Content-Security-Policy: default-src 'self'",
	},
	{
		Name:        "X-XSS-Protection",
		CWE:         "CWE-79",
		Description: "The X-XSS-Protection header enables the browser's built-in XSS filter. Although deprecated in modern browsers, it provides defense-in-depth for older clients.",
		Remediation: "Add the header: X-XSS-Protection: 1; mode=block",
	},
}

// SecurityHeaderDetector checks HTTP responses for missing security headers.
type SecurityHeaderDetector struct {
	mu      sync.Mutex
	checked map[string]bool // tracks endpoints already inspected (key: "METHOD:path")
}

// NewSecurityHeaderDetector creates a new SecurityHeaderDetector.
func NewSecurityHeaderDetector() *SecurityHeaderDetector {
	return &SecurityHeaderDetector{
		checked: make(map[string]bool),
	}
}

// Detect inspects the response headers and returns a finding for each missing
// required security header. It deduplicates by endpoint so repeated requests
// to the same method+path do not produce duplicate findings.
func (d *SecurityHeaderDetector) Detect(resp *types.HTTPResponse, method, path string) []types.Finding {
	if resp == nil {
		return nil
	}

	key := method + ":" + path

	d.mu.Lock()
	if d.checked[key] {
		d.mu.Unlock()
		return nil
	}
	d.checked[key] = true
	d.mu.Unlock()

	// Build a set of response header names (case-insensitive lookup).
	present := make(map[string]bool, len(resp.Headers))
	for name := range resp.Headers {
		present[strings.ToLower(name)] = true
	}

	var findings []types.Finding
	for _, hdr := range requiredSecurityHeaders {
		if present[strings.ToLower(hdr.Name)] {
			continue
		}

		findings = append(findings, types.Finding{
			ID:          generateID(),
			Type:        types.AttackMissingHeaders,
			Severity:    types.SeverityLow,
			Confidence:  types.ConfidenceHigh,
			Title:       fmt.Sprintf("Missing Security Header: %s", hdr.Name),
			Description: hdr.Description,
			CWE:         hdr.CWE,
			Remediation: hdr.Remediation,
			Method:      method,
			Endpoint:    path,
			References: []string{
				"https://owasp.org/www-project-secure-headers/",
			},
		})
	}

	return findings
}

// Reset clears the deduplication state so the detector can be reused across scans.
func (d *SecurityHeaderDetector) Reset() {
	d.mu.Lock()
	d.checked = make(map[string]bool)
	d.mu.Unlock()
}
