package payloads

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// IDORGenerator generates IDOR attack payloads
type IDORGenerator struct {
	config types.IDORSettings
}

// NewIDORGenerator creates a new IDOR payload generator
func NewIDORGenerator(config types.IDORSettings) *IDORGenerator {
	return &IDORGenerator{config: config}
}

// Type returns the attack type
func (g *IDORGenerator) Type() string {
	return types.AttackIDOR
}

// Generate generates IDOR payloads for a parameter
func (g *IDORGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	// Only target ID-like parameters
	if !g.isIDParameter(param) {
		return payloads
	}

	// Get original value
	originalValue := g.getOriginalValue(param)

	// Generate based on value type
	if g.isNumericID(originalValue) {
		payloads = append(payloads, g.generateNumericPayloads(originalValue)...)
	}

	if g.isUUID(originalValue) && g.config.TestUUIDs {
		payloads = append(payloads, g.generateUUIDPayloads(originalValue)...)
	}

	// Generic IDOR payloads
	payloads = append(payloads, g.generateGenericPayloads()...)

	return payloads
}

// isIDParameter checks if a parameter is ID-like
func (g *IDORGenerator) isIDParameter(param *types.Parameter) bool {
	nameLower := strings.ToLower(param.Name)

	idPatterns := []string{
		"id", "_id", "-id", "Id",
		"user", "account", "customer",
		"order", "invoice", "document",
		"file", "resource", "item",
		"profile", "member", "tenant",
	}

	for _, pattern := range idPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}

	// Check if it's in path and looks like an ID
	if param.In == "path" && (param.Type == "integer" || param.Type == "string") {
		return true
	}

	return false
}

// getOriginalValue extracts the original value
func (g *IDORGenerator) getOriginalValue(param *types.Parameter) string {
	if param.Example != nil {
		switch v := param.Example.(type) {
		case string:
			return v
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		case int:
			return strconv.Itoa(v)
		}
	}
	return ""
}

// isNumericID checks if value is a numeric ID
func (g *IDORGenerator) isNumericID(value string) bool {
	_, err := strconv.Atoi(value)
	return err == nil
}

// isUUID checks if value is a UUID
func (g *IDORGenerator) isUUID(value string) bool {
	uuidPattern := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	return uuidPattern.MatchString(value)
}

// generateNumericPayloads generates payloads for numeric IDs
func (g *IDORGenerator) generateNumericPayloads(original string) []Payload {
	var payloads []Payload

	num, _ := strconv.Atoi(original)

	// Increment/decrement
	for i := 1; i <= g.config.IDRange; i++ {
		// Increment
		payloads = append(payloads, Payload{
			Value:       strconv.Itoa(num + i),
			Type:        types.AttackIDOR,
			Category:    "authorization",
			Description: fmt.Sprintf("ID incremented by %d", i),
			Metadata:    map[string]string{"original": original, "offset": strconv.Itoa(i)},
		})

		// Decrement (if positive)
		if num-i > 0 {
			payloads = append(payloads, Payload{
				Value:       strconv.Itoa(num - i),
				Type:        types.AttackIDOR,
				Category:    "authorization",
				Description: fmt.Sprintf("ID decremented by %d", i),
				Metadata:    map[string]string{"original": original, "offset": strconv.Itoa(-i)},
			})
		}
	}

	// Special values
	specialValues := []struct {
		value string
		desc  string
	}{
		{"0", "Zero ID"},
		{"1", "First ID (often admin)"},
		{"-1", "Negative ID"},
		{"999999999", "Large ID"},
		{"2147483647", "Max int32"},
		{original + "0", "ID with trailing zero"},
		{"00" + original, "ID with leading zeros"},
	}

	for _, sv := range specialValues {
		payloads = append(payloads, Payload{
			Value:       sv.value,
			Type:        types.AttackIDOR,
			Category:    "authorization",
			Description: sv.desc,
		})
	}

	return payloads
}

// generateUUIDPayloads generates payloads for UUID IDs
func (g *IDORGenerator) generateUUIDPayloads(original string) []Payload {
	var payloads []Payload

	// Null UUID
	payloads = append(payloads, Payload{
		Value:       "00000000-0000-0000-0000-000000000000",
		Type:        types.AttackIDOR,
		Category:    "authorization",
		Description: "Null UUID",
	})

	// Max UUID
	payloads = append(payloads, Payload{
		Value:       "ffffffff-ffff-ffff-ffff-ffffffffffff",
		Type:        types.AttackIDOR,
		Category:    "authorization",
		Description: "Max UUID",
	})

	// Manipulate original UUID
	if len(original) >= 36 {
		// Change last character
		modified := original[:35]
		lastChar := original[35]
		var newChar byte
		if lastChar == 'f' {
			newChar = '0'
		} else if lastChar >= '0' && lastChar <= '9' {
			newChar = lastChar + 1
		} else {
			newChar = lastChar + 1
		}
		payloads = append(payloads, Payload{
			Value:       modified + string(newChar),
			Type:        types.AttackIDOR,
			Category:    "authorization",
			Description: "UUID with modified last character",
			Metadata:    map[string]string{"original": original},
		})

		// Version 1 UUID manipulation (time-based)
		payloads = append(payloads, Payload{
			Value:       original[:14] + "1" + original[15:],
			Type:        types.AttackIDOR,
			Category:    "authorization",
			Description: "UUID version manipulation",
		})
	}

	// Common test UUIDs
	testUUIDs := []struct {
		value string
		desc  string
	}{
		{"11111111-1111-1111-1111-111111111111", "Test UUID pattern"},
		{"admin0000-0000-0000-0000-000000000000", "Admin-prefixed UUID"},
		{"user00000-0000-0000-0000-000000000001", "User UUID variant"},
	}

	for _, tu := range testUUIDs {
		payloads = append(payloads, Payload{
			Value:       tu.value,
			Type:        types.AttackIDOR,
			Category:    "authorization",
			Description: tu.desc,
		})
	}

	return payloads
}

// generateGenericPayloads generates generic IDOR payloads
func (g *IDORGenerator) generateGenericPayloads() []Payload {
	var payloads []Payload

	genericValues := []struct {
		value string
		desc  string
	}{
		{"admin", "Admin username"},
		{"administrator", "Administrator username"},
		{"root", "Root user"},
		{"system", "System user"},
		{"self", "Self reference"},
		{"me", "Current user shortcut"},
		{"current", "Current context"},
		{"*", "Wildcard"},
		{"null", "Null string"},
		{"undefined", "Undefined"},
		{"[]", "Empty array"},
		{"{}", "Empty object"},
	}

	for _, gv := range genericValues {
		payloads = append(payloads, Payload{
			Value:       gv.value,
			Type:        types.AttackIDOR,
			Category:    "authorization",
			Description: gv.desc,
		})
	}

	return payloads
}
