// Package waf provides WAF detection and bypass capabilities
package waf

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/su1ph3r/indago/internal/llm"
	"github.com/su1ph3r/indago/pkg/types"
)

// WAFDetector detects and analyzes WAF presence
type WAFDetector struct {
	mu            sync.RWMutex
	fingerprints  []WAFFingerprint
	provider      llm.Provider
	detectedWAF   *DetectedWAF
	blockCount    int
	totalBlocks   int
	blockHistory  []BlockEvent
	threshold     int
	enabled       bool
	bypassEnabled bool
}

// DetectedWAF represents a detected WAF
type DetectedWAF struct {
	Name            string            `json:"name"`
	Vendor          string            `json:"vendor"`
	Confidence      float64           `json:"confidence"`
	DetectionMethod string            `json:"detection_method"`
	Indicators      []string          `json:"indicators"`
	FirstSeen       time.Time         `json:"first_seen"`
	Headers         map[string]string `json:"headers,omitempty"`
}

// BlockEvent represents a blocked request
type BlockEvent struct {
	Timestamp      time.Time `json:"timestamp"`
	Endpoint       string    `json:"endpoint"`
	Payload        string    `json:"payload"`
	StatusCode     int       `json:"status_code"`
	ResponseTime   time.Duration `json:"response_time"`
	BlockSignature string    `json:"block_signature"`
}

// WAFFingerprint defines patterns for identifying a specific WAF
type WAFFingerprint struct {
	Name           string
	Vendor         string
	HeaderPatterns map[string]*regexp.Regexp
	BodyPatterns   []*regexp.Regexp
	StatusCodes    []int
	CookiePatterns []*regexp.Regexp
}

// NewWAFDetector creates a new WAF detector
func NewWAFDetector(provider llm.Provider, threshold int, bypassEnabled bool) *WAFDetector {
	wd := &WAFDetector{
		fingerprints:  getWAFFingerprints(),
		provider:      provider,
		threshold:     threshold,
		blockHistory:  make([]BlockEvent, 0),
		enabled:       true,
		bypassEnabled: bypassEnabled,
	}

	return wd
}

// getWAFFingerprints returns known WAF fingerprints
func getWAFFingerprints() []WAFFingerprint {
	return []WAFFingerprint{
		{
			Name:   "Cloudflare",
			Vendor: "Cloudflare",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server":          regexp.MustCompile(`(?i)cloudflare`),
				"CF-RAY":          regexp.MustCompile(`.+`),
				"CF-Cache-Status": regexp.MustCompile(`.+`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)attention required.*cloudflare`),
				regexp.MustCompile(`(?i)cloudflare ray id`),
				regexp.MustCompile(`(?i)please enable cookies`),
			},
			StatusCodes: []int{403, 503, 520, 521, 522, 523, 524},
			CookiePatterns: []*regexp.Regexp{
				regexp.MustCompile(`__cf`),
				regexp.MustCompile(`cf_clearance`),
			},
		},
		{
			Name:   "AWS WAF",
			Vendor: "Amazon",
			HeaderPatterns: map[string]*regexp.Regexp{
				"X-AMZ-CF-ID":  regexp.MustCompile(`.+`),
				"X-AMZ-CF-POP": regexp.MustCompile(`.+`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)request blocked`),
				regexp.MustCompile(`(?i)aws waf`),
			},
			StatusCodes: []int{403},
		},
		{
			Name:   "Akamai",
			Vendor: "Akamai",
			HeaderPatterns: map[string]*regexp.Regexp{
				"X-Akamai-Transformed": regexp.MustCompile(`.+`),
				"Akamai-Origin-Hop":    regexp.MustCompile(`.+`),
				"Server":               regexp.MustCompile(`(?i)akamai`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)access denied`),
				regexp.MustCompile(`(?i)akamai reference`),
			},
			StatusCodes: []int{403},
		},
		{
			Name:   "Imperva/Incapsula",
			Vendor: "Imperva",
			HeaderPatterns: map[string]*regexp.Regexp{
				"X-CDN":   regexp.MustCompile(`(?i)incapsula`),
				"X-Iinfo": regexp.MustCompile(`.+`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)incapsula incident`),
				regexp.MustCompile(`(?i)request unsuccessful`),
				regexp.MustCompile(`(?i)pardon our interruption`),
			},
			StatusCodes: []int{403},
			CookiePatterns: []*regexp.Regexp{
				regexp.MustCompile(`incap_ses`),
				regexp.MustCompile(`visid_incap`),
			},
		},
		{
			Name:   "ModSecurity",
			Vendor: "Trustwave",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)mod_security|modsecurity`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)mod_security`),
				regexp.MustCompile(`(?i)not acceptable`),
				regexp.MustCompile(`(?i)rules triggered`),
			},
			StatusCodes: []int{403, 406, 501},
		},
		{
			Name:   "F5 BIG-IP ASM",
			Vendor: "F5",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server":           regexp.MustCompile(`(?i)bigip`),
				"X-WA-Info":        regexp.MustCompile(`.+`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)request rejected`),
				regexp.MustCompile(`(?i)the requested url was rejected`),
			},
			StatusCodes: []int{403},
			CookiePatterns: []*regexp.Regexp{
				regexp.MustCompile(`TS[a-zA-Z0-9]+`),
				regexp.MustCompile(`BIGipServer`),
			},
		},
		{
			Name:   "Sucuri",
			Vendor: "GoDaddy/Sucuri",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server":           regexp.MustCompile(`(?i)sucuri`),
				"X-Sucuri-ID":      regexp.MustCompile(`.+`),
				"X-Sucuri-Block":   regexp.MustCompile(`.+`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)access denied.*sucuri`),
				regexp.MustCompile(`(?i)sucuri website firewall`),
			},
			StatusCodes: []int{403},
		},
		{
			Name:   "Barracuda",
			Vendor: "Barracuda",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)barracuda`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)barracuda`),
				regexp.MustCompile(`(?i)you have been blocked`),
			},
			StatusCodes: []int{403},
		},
		{
			Name:   "Fortinet FortiWeb",
			Vendor: "Fortinet",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Server": regexp.MustCompile(`(?i)fortiWeb`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)fortiweb`),
				regexp.MustCompile(`(?i)attack was detected`),
			},
			StatusCodes: []int{403},
		},
		{
			Name:   "Citrix NetScaler",
			Vendor: "Citrix",
			HeaderPatterns: map[string]*regexp.Regexp{
				"Via":    regexp.MustCompile(`(?i)netscaler`),
				"Server": regexp.MustCompile(`(?i)netscaler`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)netscaler`),
				regexp.MustCompile(`(?i)ns_af`),
			},
			StatusCodes: []int{403},
			CookiePatterns: []*regexp.Regexp{
				regexp.MustCompile(`ns_af`),
				regexp.MustCompile(`citrix_ns`),
			},
		},
		{
			Name:   "Radware AppWall",
			Vendor: "Radware",
			HeaderPatterns: map[string]*regexp.Regexp{
				"X-SL-CompState": regexp.MustCompile(`.+`),
			},
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)unauthorized activity`),
				regexp.MustCompile(`(?i)radware`),
			},
			StatusCodes: []int{403, 406},
		},
		{
			Name:   "Wordfence",
			Vendor: "Defiant",
			BodyPatterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)wordfence`),
				regexp.MustCompile(`(?i)generated by wordfence`),
				regexp.MustCompile(`(?i)your access to this site has been limited`),
			},
			StatusCodes: []int{403, 503},
		},
	}
}

// AnalyzeResponse analyzes a response for WAF indicators
func (wd *WAFDetector) AnalyzeResponse(resp *types.HTTPResponse, endpoint string, payload string) *DetectedWAF {
	if resp == nil || !wd.enabled {
		return nil
	}

	// Check if this looks like a block
	isBlocked := wd.isBlockedResponse(resp)

	if isBlocked {
		wd.mu.Lock()
		wd.blockCount++
		wd.totalBlocks++

		// Record block event
		wd.blockHistory = append(wd.blockHistory, BlockEvent{
			Timestamp:    time.Now(),
			Endpoint:     endpoint,
			Payload:      payload,
			StatusCode:   resp.StatusCode,
			ResponseTime: resp.ResponseTime,
		})

		// Keep history manageable
		if len(wd.blockHistory) > 1000 {
			wd.blockHistory = wd.blockHistory[100:]
		}
		wd.mu.Unlock()
	}

	// Try to fingerprint the WAF
	for _, fp := range wd.fingerprints {
		if detected := wd.matchFingerprint(fp, resp); detected != nil {
			wd.mu.Lock()
			wd.detectedWAF = detected
			wd.mu.Unlock()
			return detected
		}
	}

	// Generic WAF detection
	if isBlocked {
		generic := wd.detectGenericWAF(resp)
		if generic != nil {
			wd.mu.Lock()
			if wd.detectedWAF == nil {
				wd.detectedWAF = generic
			}
			wd.mu.Unlock()
			return generic
		}
	}

	return nil
}

// matchFingerprint checks if a response matches a WAF fingerprint
func (wd *WAFDetector) matchFingerprint(fp WAFFingerprint, resp *types.HTTPResponse) *DetectedWAF {
	indicators := make([]string, 0)
	confidence := 0.0

	// Check headers
	for headerName, pattern := range fp.HeaderPatterns {
		for respHeader, respValue := range resp.Headers {
			if strings.EqualFold(respHeader, headerName) && pattern.MatchString(respValue) {
				indicators = append(indicators, "Header: "+headerName+"="+respValue)
				confidence += 0.3
			}
		}
	}

	// Check body patterns
	for _, pattern := range fp.BodyPatterns {
		if pattern.MatchString(resp.Body) {
			match := pattern.FindString(resp.Body)
			if len(match) > 100 {
				match = match[:100] + "..."
			}
			indicators = append(indicators, "Body pattern: "+match)
			confidence += 0.25
		}
	}

	// Check status codes
	for _, code := range fp.StatusCodes {
		if resp.StatusCode == code {
			indicators = append(indicators, "Status code: "+string(rune(code)))
			confidence += 0.15
		}
	}

	// Check cookie patterns
	if cookieHeader, ok := resp.Headers["Set-Cookie"]; ok {
		for _, pattern := range fp.CookiePatterns {
			if pattern.MatchString(cookieHeader) {
				indicators = append(indicators, "Cookie pattern matched")
				confidence += 0.2
			}
		}
	}

	if confidence >= 0.3 && len(indicators) > 0 {
		if confidence > 1.0 {
			confidence = 1.0
		}
		return &DetectedWAF{
			Name:            fp.Name,
			Vendor:          fp.Vendor,
			Confidence:      confidence,
			DetectionMethod: "fingerprint",
			Indicators:      indicators,
			FirstSeen:       time.Now(),
			Headers:         resp.Headers,
		}
	}

	return nil
}

// isBlockedResponse determines if a response indicates blocking
func (wd *WAFDetector) isBlockedResponse(resp *types.HTTPResponse) bool {
	// Check status codes
	blockStatusCodes := []int{403, 406, 429, 503}
	for _, code := range blockStatusCodes {
		if resp.StatusCode == code {
			return true
		}
	}

	// Check for common block phrases
	blockPhrases := []string{
		"access denied",
		"forbidden",
		"blocked",
		"request rejected",
		"not acceptable",
		"unauthorized activity",
		"suspicious activity",
		"security violation",
		"attack detected",
		"malicious request",
	}

	bodyLower := strings.ToLower(resp.Body)
	for _, phrase := range blockPhrases {
		if strings.Contains(bodyLower, phrase) {
			return true
		}
	}

	// Check for suspiciously fast rejection (potential WAF)
	if resp.ResponseTime < 50*time.Millisecond && resp.StatusCode >= 400 {
		return true
	}

	return false
}

// detectGenericWAF creates a generic WAF detection when no fingerprint matches
func (wd *WAFDetector) detectGenericWAF(resp *types.HTTPResponse) *DetectedWAF {
	indicators := make([]string, 0)

	if resp.StatusCode == 403 {
		indicators = append(indicators, "403 Forbidden response")
	}
	if resp.StatusCode == 406 {
		indicators = append(indicators, "406 Not Acceptable response")
	}
	if resp.StatusCode == 429 {
		indicators = append(indicators, "429 Too Many Requests")
	}

	bodyLower := strings.ToLower(resp.Body)
	if strings.Contains(bodyLower, "access denied") {
		indicators = append(indicators, "Access denied message")
	}
	if strings.Contains(bodyLower, "blocked") {
		indicators = append(indicators, "Block message in response")
	}

	if len(indicators) > 0 {
		return &DetectedWAF{
			Name:            "Unknown WAF",
			Vendor:          "Unknown",
			Confidence:      0.5,
			DetectionMethod: "heuristic",
			Indicators:      indicators,
			FirstSeen:       time.Now(),
			Headers:         resp.Headers,
		}
	}

	return nil
}

// IsWAFDetected returns whether a WAF has been detected
func (wd *WAFDetector) IsWAFDetected() bool {
	wd.mu.RLock()
	defer wd.mu.RUnlock()
	return wd.detectedWAF != nil
}

// GetDetectedWAF returns the detected WAF
func (wd *WAFDetector) GetDetectedWAF() *DetectedWAF {
	wd.mu.RLock()
	defer wd.mu.RUnlock()
	return wd.detectedWAF
}

// ShouldTriggerBypass checks if bypass should be triggered
func (wd *WAFDetector) ShouldTriggerBypass() bool {
	wd.mu.RLock()
	defer wd.mu.RUnlock()
	return wd.bypassEnabled && wd.blockCount >= wd.threshold
}

// ResetBlockCount resets the consecutive block counter
func (wd *WAFDetector) ResetBlockCount() {
	wd.mu.Lock()
	defer wd.mu.Unlock()
	wd.blockCount = 0
}

// GetBlockCount returns the current consecutive block count
func (wd *WAFDetector) GetBlockCount() int {
	wd.mu.RLock()
	defer wd.mu.RUnlock()
	return wd.blockCount
}

// GetTotalBlocks returns the total number of blocks
func (wd *WAFDetector) GetTotalBlocks() int {
	wd.mu.RLock()
	defer wd.mu.RUnlock()
	return wd.totalBlocks
}

// GetBlockHistory returns the block history
func (wd *WAFDetector) GetBlockHistory() []BlockEvent {
	wd.mu.RLock()
	defer wd.mu.RUnlock()

	history := make([]BlockEvent, len(wd.blockHistory))
	copy(history, wd.blockHistory)
	return history
}

// GenerateBypassPayloads uses LLM to generate WAF bypass payloads
func (wd *WAFDetector) GenerateBypassPayloads(ctx context.Context, originalPayload string, attackType string) ([]BypassStrategy, error) {
	if wd.provider == nil {
		return wd.generateStaticBypasses(originalPayload, attackType), nil
	}

	return wd.generateLLMBypasses(ctx, originalPayload, attackType)
}

// generateLLMBypasses generates bypasses using LLM
func (wd *WAFDetector) generateLLMBypasses(ctx context.Context, originalPayload string, attackType string) ([]BypassStrategy, error) {
	wafName := "Unknown"
	if wd.detectedWAF != nil {
		wafName = wd.detectedWAF.Name
	}

	prompt := buildBypassPrompt(originalPayload, attackType, wafName)

	var strategies []BypassStrategy
	err := wd.provider.AnalyzeStructured(ctx, prompt, &strategies)
	if err != nil {
		// Fall back to static bypasses
		return wd.generateStaticBypasses(originalPayload, attackType), nil
	}

	return strategies, nil
}

// generateStaticBypasses generates bypasses without LLM
func (wd *WAFDetector) generateStaticBypasses(originalPayload string, attackType string) []BypassStrategy {
	var strategies []BypassStrategy

	switch attackType {
	case "sqli":
		strategies = append(strategies, generateSQLiBypasses(originalPayload)...)
	case "xss":
		strategies = append(strategies, generateXSSBypasses(originalPayload)...)
	case "command_injection":
		strategies = append(strategies, generateCommandBypasses(originalPayload)...)
	default:
		strategies = append(strategies, generateGenericBypasses(originalPayload)...)
	}

	return strategies
}

// buildBypassPrompt builds the prompt for LLM bypass generation
func buildBypassPrompt(originalPayload string, attackType string, wafName string) string {
	return `Generate WAF bypass variations for the following payload.

Original Payload: ` + originalPayload + `
Attack Type: ` + attackType + `
Detected WAF: ` + wafName + `

Generate 5 bypass variations using these techniques:
1. Encoding variations (URL encoding, double encoding, unicode)
2. Case variations and character substitution
3. Comment insertion and string concatenation
4. Whitespace manipulation
5. Alternative syntax and equivalent commands

Respond with JSON array only:
[
  {
    "original_payload": "the original",
    "bypass_payloads": ["bypass1", "bypass2"],
    "technique": "encoding",
    "rationale": "why this might work"
  }
]`
}

// SetEnabled enables/disables WAF detection
func (wd *WAFDetector) SetEnabled(enabled bool) {
	wd.mu.Lock()
	defer wd.mu.Unlock()
	wd.enabled = enabled
}
