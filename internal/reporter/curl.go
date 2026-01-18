// Package reporter provides output formatting for scan results
package reporter

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// GenerateCurlCommand generates a curl command from an HTTP request
func GenerateCurlCommand(req *types.HTTPRequest) string {
	if req == nil {
		return ""
	}

	var parts []string
	parts = append(parts, "curl")

	// Method (only add if not GET)
	if req.Method != "" && req.Method != "GET" {
		parts = append(parts, "-X", req.Method)
	}

	// Headers (sorted for consistency)
	if len(req.Headers) > 0 {
		headerNames := make([]string, 0, len(req.Headers))
		for name := range req.Headers {
			headerNames = append(headerNames, name)
		}
		sort.Strings(headerNames)

		for _, name := range headerNames {
			value := req.Headers[name]
			// Skip headers that curl handles automatically
			lowerName := strings.ToLower(name)
			if lowerName == "content-length" || lowerName == "host" {
				continue
			}
			parts = append(parts, "-H", shellEscape(fmt.Sprintf("%s: %s", name, value)))
		}
	}

	// Body
	if req.Body != "" {
		parts = append(parts, "-d", shellEscape(req.Body))
	}

	// URL (always last)
	parts = append(parts, shellEscape(req.URL))

	return strings.Join(parts, " ")
}

// GenerateCurlFromFinding generates a curl command from a finding's evidence
func GenerateCurlFromFinding(finding *types.Finding) string {
	if finding == nil || finding.Evidence == nil || finding.Evidence.Request == nil {
		// Try to construct from finding data
		return generateCurlFromFindingData(finding)
	}
	return GenerateCurlCommand(finding.Evidence.Request)
}

// generateCurlFromFindingData generates a curl command from basic finding data
func generateCurlFromFindingData(finding *types.Finding) string {
	if finding == nil {
		return ""
	}

	var parts []string
	parts = append(parts, "curl")

	// Method
	if finding.Method != "" && finding.Method != "GET" {
		parts = append(parts, "-X", finding.Method)
	}

	// Build URL with payload if parameter is specified
	targetURL := finding.Endpoint
	if finding.Parameter != "" && finding.Payload != "" {
		if strings.Contains(targetURL, "?") {
			targetURL += "&" + url.QueryEscape(finding.Parameter) + "=" + url.QueryEscape(finding.Payload)
		} else {
			targetURL += "?" + url.QueryEscape(finding.Parameter) + "=" + url.QueryEscape(finding.Payload)
		}
	}

	parts = append(parts, shellEscape(targetURL))

	return strings.Join(parts, " ")
}

// GenerateReplicateSteps generates numbered steps to replicate a finding
func GenerateReplicateSteps(finding *types.Finding) []string {
	if finding == nil {
		return nil
	}

	steps := make([]string, 0, 4)

	// Step 1: Context
	step1 := fmt.Sprintf("Navigate to the target endpoint: %s %s", finding.Method, finding.Endpoint)
	steps = append(steps, step1)

	// Step 2: Parameter info
	if finding.Parameter != "" {
		step2 := fmt.Sprintf("Locate the '%s' parameter", finding.Parameter)
		steps = append(steps, step2)
	}

	// Step 3: Payload
	if finding.Payload != "" {
		step3 := fmt.Sprintf("Submit the following payload: %s", finding.Payload)
		steps = append(steps, step3)
	}

	// Step 4: Curl command
	curlCmd := GenerateCurlFromFinding(finding)
	if curlCmd != "" {
		step4 := fmt.Sprintf("Or use this curl command:\n   %s", curlCmd)
		steps = append(steps, step4)
	}

	// Number the steps
	numbered := make([]string, len(steps))
	for i, step := range steps {
		numbered[i] = fmt.Sprintf("%d. %s", i+1, step)
	}

	return numbered
}

// shellEscape safely escapes a string for use in POSIX shell commands.
// NOTE: This function is designed for POSIX shells (bash, sh, zsh) on Unix-like systems.
// On Windows, users may need to adjust the quoting style manually.
func shellEscape(s string) string {
	// If string is empty, return empty quotes
	if s == "" {
		return "''"
	}

	// Always escape if string contains any non-safe characters
	// Use a whitelist approach for safety: only allow alphanumeric, dot, dash, underscore, colon, and forward slash
	if isSafeString(s) {
		return s
	}

	// Use single quotes and escape any existing single quotes
	// Single quotes are the safest way to escape in POSIX shells
	// This handles: ' -> '\'' (end quote, escaped quote, start quote)
	escaped := strings.ReplaceAll(s, "'", "'\\''")
	return "'" + escaped + "'"
}

// isSafeString returns true if the string only contains safe characters
// that don't require escaping in shell commands
func isSafeString(s string) bool {
	for _, c := range s {
		// Whitelist: only allow alphanumeric, common URL-safe chars
		if (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '_' || c == '/' || c == ':' {
			continue
		}
		return false
	}
	return true
}

// CurlOptions provides options for curl command generation
type CurlOptions struct {
	IncludeVerbose  bool // Add -v flag
	IncludeInsecure bool // Add -k flag for SSL bypass
	IncludeFollow   bool // Add -L flag to follow redirects
	IncludeOutput   bool // Add -o flag
	OutputFile      string
	IncludeProxy    bool
	ProxyURL        string
	MaxTime         int    // Timeout in seconds
	UserAgent       string // Custom user agent
}

// GenerateCurlCommandWithOptions generates a curl command with additional options
func GenerateCurlCommandWithOptions(req *types.HTTPRequest, opts CurlOptions) string {
	if req == nil {
		return ""
	}

	var parts []string
	parts = append(parts, "curl")

	// Optional flags
	if opts.IncludeVerbose {
		parts = append(parts, "-v")
	}
	if opts.IncludeInsecure {
		parts = append(parts, "-k")
	}
	if opts.IncludeFollow {
		parts = append(parts, "-L")
	}
	if opts.MaxTime > 0 {
		parts = append(parts, "--max-time", fmt.Sprintf("%d", opts.MaxTime))
	}
	if opts.IncludeProxy && opts.ProxyURL != "" {
		parts = append(parts, "--proxy", shellEscape(opts.ProxyURL))
	}
	if opts.IncludeOutput && opts.OutputFile != "" {
		parts = append(parts, "-o", shellEscape(opts.OutputFile))
	}
	if opts.UserAgent != "" {
		parts = append(parts, "-A", shellEscape(opts.UserAgent))
	}

	// Method
	if req.Method != "" && req.Method != "GET" {
		parts = append(parts, "-X", req.Method)
	}

	// Headers (sorted for consistency)
	if len(req.Headers) > 0 {
		headerNames := make([]string, 0, len(req.Headers))
		for name := range req.Headers {
			headerNames = append(headerNames, name)
		}
		sort.Strings(headerNames)

		for _, name := range headerNames {
			value := req.Headers[name]
			lowerName := strings.ToLower(name)
			if lowerName == "content-length" || lowerName == "host" {
				continue
			}
			parts = append(parts, "-H", shellEscape(fmt.Sprintf("%s: %s", name, value)))
		}
	}

	// Body
	if req.Body != "" {
		parts = append(parts, "-d", shellEscape(req.Body))
	}

	// URL
	parts = append(parts, shellEscape(req.URL))

	return strings.Join(parts, " ")
}
