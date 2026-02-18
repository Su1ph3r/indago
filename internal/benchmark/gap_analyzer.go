package benchmark

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// GapAnalysis describes why a specific ground truth vulnerability was missed.
type GapAnalysis struct {
	VulnID       string  `json:"vuln_id"`
	VulnName     string  `json:"vuln_name"`
	VulnClass    string  `json:"vuln_class"`
	Endpoint     string  `json:"endpoint"`
	Gap          GapType `json:"gap_type"`
	Notes        string  `json:"notes"`
	PayloadsSent int     `json:"payloads_sent"`
	ResponseCode int     `json:"response_code,omitempty"`
	ResponseBody string  `json:"response_body,omitempty"`
}

// RequestLogEntry mirrors the structure of Indago's --log-requests output.
// The log is a JSON array of objects with nested request/response.
type RequestLogEntry struct {
	Endpoint     string              `json:"endpoint"`
	Method       string              `json:"method"`
	PayloadType  string              `json:"payload_type"`
	URL          string              `json:"url"`
	Response     *logEntryResponse   `json:"response,omitempty"`
	// Computed fields (populated after parsing)
	StatusCode   int    `json:"-"`
	ResponseBody string `json:"-"`
}

type logEntryResponse struct {
	StatusCode  int    `json:"status_code"`
	BodyPreview string `json:"body_preview"`
}

// AnalyzeGaps determines why each false negative occurred by examining
// the request log, findings, and known attack types.
func AnalyzeGaps(
	falseNegatives []MatchResult,
	allFindings []types.Finding,
	requestLogPath string,
	scannedEndpoints []string,
) []GapAnalysis {
	logs := loadRequestLog(requestLogPath)
	endpointSet := toSet(scannedEndpoints)

	var gaps []GapAnalysis
	for _, fn := range falseNegatives {
		gap := analyzeOneGap(fn, logs, endpointSet, allFindings)
		gaps = append(gaps, gap)
	}
	return gaps
}

func analyzeOneGap(
	fn MatchResult,
	logs []RequestLogEntry,
	scannedEndpoints map[string]bool,
	allFindings []types.Finding,
) GapAnalysis {
	ga := GapAnalysis{
		VulnID:    fn.Vuln.ID,
		VulnName:  fn.Vuln.Name,
		VulnClass: fn.Vuln.Class,
		Endpoint:  fn.Vuln.Endpoint,
	}

	// 1. Was the endpoint scanned at all?
	if !endpointWasScanned(fn.Vuln, scannedEndpoints) {
		ga.Gap = GapEndpointNotScanned
		ga.Notes = fmt.Sprintf("Endpoint %s %s was not present in the scanned endpoint list",
			fn.Vuln.Method, fn.Vuln.Endpoint)
		return ga
	}

	// 2. Were findings created for this endpoint but with wrong type/severity?
	// Check this before the payload log, since findings imply the endpoint was fuzzed.
	filteredFindings := findingsForEndpoint(allFindings, fn.Vuln)
	if len(filteredFindings) > 0 {
		ga.Gap = GapFilteredOut
		ga.Notes = fmt.Sprintf("Found %d findings for this endpoint but none matched ground truth rules. "+
			"Finding types present: %s", len(filteredFindings), findingTypesSummary(filteredFindings))
		return ga
	}

	// 3. Were any payloads of the right type sent to this endpoint?
	relevantLogs := filterLogs(logs, fn.Vuln)
	classPayloads := filterLogsByClass(relevantLogs, fn.Vuln.Class)

	if len(classPayloads) == 0 {
		if !isKnownAttackClass(fn.Vuln.Class) {
			ga.Gap = GapNewVulnClass
			ga.Notes = fmt.Sprintf("No attack generator exists for class '%s'", fn.Vuln.Class)
		} else {
			ga.Gap = GapNoPayloads
			ga.Notes = fmt.Sprintf("No payloads of type '%s' were generated for endpoint %s",
				fn.Vuln.Class, fn.Vuln.Endpoint)
		}
		ga.PayloadsSent = len(relevantLogs)
		return ga
	}

	ga.PayloadsSent = len(classPayloads)

	// 4. Payloads were sent but no findings were generated at all
	// Check response codes to see if the vuln was triggered
	triggeredResponse := findTriggeredResponse(classPayloads, fn.Vuln.Class)
	if triggeredResponse != nil {
		ga.Gap = GapDetectionMissed
		ga.Notes = fmt.Sprintf("Payloads appear to have triggered the vulnerability (response code %d) "+
			"but the response analyzer did not create a finding", triggeredResponse.StatusCode)
		ga.ResponseCode = triggeredResponse.StatusCode
		body := triggeredResponse.ResponseBody
		if len(body) > 500 {
			body = body[:500]
		}
		ga.ResponseBody = body
	} else {
		ga.Gap = GapPayloadIneffective
		ga.Notes = fmt.Sprintf("Sent %d payloads of type '%s' but none triggered a detectable response",
			len(classPayloads), fn.Vuln.Class)
		if len(classPayloads) > 0 {
			ga.ResponseCode = classPayloads[0].StatusCode
			body := classPayloads[0].ResponseBody
			if len(body) > 500 {
				body = body[:500]
			}
			ga.ResponseBody = body
		}
	}

	return ga
}

func endpointWasScanned(vuln Vulnerability, scanned map[string]bool) bool {
	if vuln.Endpoint == "*" {
		return len(scanned) > 0
	}
	// Check if any scanned endpoint matches the pattern
	for ep := range scanned {
		if matchGlob(vuln.Endpoint, ep) {
			return true
		}
	}
	return false
}

func filterLogs(logs []RequestLogEntry, vuln Vulnerability) []RequestLogEntry {
	var result []RequestLogEntry
	for _, l := range logs {
		if vuln.Method != "" && vuln.Method != "*" && !strings.EqualFold(l.Method, vuln.Method) {
			continue
		}
		if vuln.Endpoint != "" && vuln.Endpoint != "*" {
			if !matchGlob(vuln.Endpoint, l.Endpoint) {
				continue
			}
		}
		result = append(result, l)
	}
	return result
}

func filterLogsByClass(logs []RequestLogEntry, class string) []RequestLogEntry {
	var result []RequestLogEntry
	classAliases := classToPayloadTypes(class)
	for _, l := range logs {
		for _, alias := range classAliases {
			if strings.Contains(strings.ToLower(l.PayloadType), alias) {
				result = append(result, l)
				break
			}
		}
	}
	return result
}

func classToPayloadTypes(class string) []string {
	switch strings.ToLower(class) {
	case "sqli":
		return []string{"sqli", "sql_injection", "sql"}
	case "bola":
		return []string{"bola", "idor", "bfla", "auth_bypass"}
	case "mass_assignment":
		return []string{"mass_assignment", "mass_assign"}
	case "data_exposure":
		return []string{"data_exposure", "data_leak", "sensitive"}
	case "enumeration":
		return []string{"enumeration", "enum", "auth_bypass", "brute"}
	case "rate_limit":
		return []string{"rate_limit", "rate"}
	case "jwt_manipulation":
		return []string{"jwt", "token", "auth"}
	default:
		return []string{class}
	}
}

func isKnownAttackClass(class string) bool {
	known := map[string]bool{
		"sqli": true, "nosqli": true, "command_injection": true, "xss": true,
		"auth_bypass": true, "mass_assignment": true, "bola": true, "bfla": true,
		"idor": true, "rate_limit": true, "data_exposure": true, "ssrf": true,
		"path_traversal": true, "ldap_injection": true, "xpath_injection": true,
		"ssti": true, "jwt_manipulation": true,
	}
	return known[strings.ToLower(class)]
}

func findingsForEndpoint(findings []types.Finding, vuln Vulnerability) []types.Finding {
	var result []types.Finding
	for _, f := range findings {
		if vuln.Endpoint != "" && vuln.Endpoint != "*" {
			if !matchGlob(vuln.Endpoint, f.Endpoint) {
				continue
			}
		}
		if vuln.Method != "" && vuln.Method != "*" {
			if !strings.EqualFold(vuln.Method, f.Method) {
				continue
			}
		}
		result = append(result, f)
	}
	return result
}

func findingTypesSummary(findings []types.Finding) string {
	seen := make(map[string]bool)
	for _, f := range findings {
		seen[f.Type] = true
	}
	var types []string
	for t := range seen {
		types = append(types, t)
	}
	return strings.Join(types, ", ")
}

func findTriggeredResponse(logs []RequestLogEntry, class string) *RequestLogEntry {
	for _, l := range logs {
		switch strings.ToLower(class) {
		case "sqli":
			if l.StatusCode == 500 || strings.Contains(strings.ToLower(l.ResponseBody), "error") ||
				strings.Contains(strings.ToLower(l.ResponseBody), "sql") {
				return &l
			}
		case "bola":
			if l.StatusCode == 200 || l.StatusCode == 204 {
				return &l
			}
		case "mass_assignment":
			if l.StatusCode == 200 && strings.Contains(l.ResponseBody, "admin") {
				return &l
			}
		case "data_exposure":
			if l.StatusCode == 200 && (strings.Contains(l.ResponseBody, "password") ||
				strings.Contains(l.ResponseBody, "email")) {
				return &l
			}
		case "jwt_manipulation":
			if l.StatusCode == 200 {
				return &l
			}
		default:
			if l.StatusCode >= 200 && l.StatusCode < 300 {
				return &l
			}
		}
	}
	return nil
}

func loadRequestLog(path string) []RequestLogEntry {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil
	}

	// The request log is a JSON array (may have trailing comma issues)
	data = bytes.TrimSpace(data)

	var entries []RequestLogEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		// Try JSONL fallback
		for _, line := range splitLines(data) {
			if len(line) == 0 {
				continue
			}
			var entry RequestLogEntry
			if jsonErr := json.Unmarshal(line, &entry); jsonErr == nil {
				entries = append(entries, entry)
			}
		}
	}

	// Populate computed fields from nested response
	for i := range entries {
		if entries[i].Response != nil {
			entries[i].StatusCode = entries[i].Response.StatusCode
			entries[i].ResponseBody = entries[i].Response.BodyPreview
		}
	}

	return entries
}

func toSet(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, item := range items {
		s[item] = true
	}
	return s
}
