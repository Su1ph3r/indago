package payloads

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// BOLAGenerator generates Broken Object Level Authorization attack payloads
type BOLAGenerator struct{}

// NewBOLAGenerator creates a new BOLA payload generator
func NewBOLAGenerator() *BOLAGenerator {
	return &BOLAGenerator{}
}

// Type returns the attack type
func (g *BOLAGenerator) Type() string {
	return types.AttackBOLA
}

// Generate generates BOLA payloads for a parameter
func (g *BOLAGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	// Target ID-like parameters in any position
	if !g.isObjectReference(param) {
		return payloads
	}

	originalValue := g.getOriginalValue(param)

	// Generate based on the type of ID
	if g.isNumericID(originalValue) {
		payloads = append(payloads, g.numericBOLAPayloads(originalValue)...)
	} else if g.isUUID(originalValue) {
		payloads = append(payloads, g.uuidBOLAPayloads(originalValue)...)
	}

	// Generic object reference manipulation
	payloads = append(payloads, g.genericBOLAPayloads()...)

	return payloads
}

// isObjectReference checks if parameter references an object
func (g *BOLAGenerator) isObjectReference(param *types.Parameter) bool {
	nameLower := strings.ToLower(param.Name)

	// Common object reference patterns
	objectPatterns := []string{
		"id", "_id", "-id",
		"user", "account", "customer", "client",
		"order", "invoice", "transaction", "payment",
		"file", "document", "resource", "item",
		"profile", "member", "tenant", "org",
		"project", "workspace", "team",
		"message", "comment", "post", "thread",
		"session", "token", "key",
	}

	for _, pattern := range objectPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}

	// Path parameters are often object references
	if param.In == "path" {
		return true
	}

	return false
}

// getOriginalValue extracts the original value from parameter
func (g *BOLAGenerator) getOriginalValue(param *types.Parameter) string {
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

// isNumericID checks if value is numeric
func (g *BOLAGenerator) isNumericID(value string) bool {
	_, err := strconv.Atoi(value)
	return err == nil
}

// isUUID checks if value is a UUID
func (g *BOLAGenerator) isUUID(value string) bool {
	uuidPattern := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	return uuidPattern.MatchString(value)
}

// numericBOLAPayloads generates payloads for numeric object IDs
func (g *BOLAGenerator) numericBOLAPayloads(original string) []Payload {
	var payloads []Payload

	num, _ := strconv.Atoi(original)

	// Access other users' objects via ID manipulation
	testIDs := []struct {
		value int
		desc  string
	}{
		{1, "First object (often admin)"},
		{0, "Zero ID"},
		{num + 1, "Next object"},
		{num - 1, "Previous object"},
		{num + 100, "Object +100"},
		{num + 1000, "Object +1000"},
		{999999, "High numbered object"},
		{2147483647, "Max int32 object"},
	}

	for _, t := range testIDs {
		if t.value != num { // Don't test the original value
			payloads = append(payloads, Payload{
				Value:       strconv.Itoa(t.value),
				Type:        types.AttackBOLA,
				Category:    "authorization",
				Description: fmt.Sprintf("BOLA: %s", t.desc),
				Metadata:    map[string]string{"original": original},
			})
		}
	}

	return payloads
}

// uuidBOLAPayloads generates payloads for UUID object IDs
func (g *BOLAGenerator) uuidBOLAPayloads(original string) []Payload {
	var payloads []Payload

	// Known test/system UUIDs
	testUUIDs := []struct {
		value string
		desc  string
	}{
		{"00000000-0000-0000-0000-000000000000", "Null UUID"},
		{"00000000-0000-0000-0000-000000000001", "First sequential UUID"},
		{"11111111-1111-1111-1111-111111111111", "Pattern UUID"},
		{"ffffffff-ffff-ffff-ffff-ffffffffffff", "Max UUID"},
	}

	for _, t := range testUUIDs {
		payloads = append(payloads, Payload{
			Value:       t.value,
			Type:        types.AttackBOLA,
			Category:    "authorization",
			Description: fmt.Sprintf("BOLA: %s", t.desc),
			Metadata:    map[string]string{"original": original},
		})
	}

	// Modify original UUID slightly
	if len(original) >= 36 {
		// Increment last character
		modified := original[:35]
		lastChar := original[35]
		var newChar byte
		if lastChar >= '0' && lastChar < '9' {
			newChar = lastChar + 1
		} else if lastChar == '9' {
			newChar = 'a'
		} else if lastChar >= 'a' && lastChar < 'f' {
			newChar = lastChar + 1
		} else {
			newChar = '0'
		}

		payloads = append(payloads, Payload{
			Value:       modified + string(newChar),
			Type:        types.AttackBOLA,
			Category:    "authorization",
			Description: "BOLA: Adjacent UUID",
			Metadata:    map[string]string{"original": original},
		})
	}

	return payloads
}

// genericBOLAPayloads generates generic object reference bypass payloads
func (g *BOLAGenerator) genericBOLAPayloads() []Payload {
	return []Payload{
		{
			Value:       "admin",
			Type:        types.AttackBOLA,
			Category:    "authorization",
			Description: "BOLA: Admin object reference",
		},
		{
			Value:       "system",
			Type:        types.AttackBOLA,
			Category:    "authorization",
			Description: "BOLA: System object reference",
		},
		{
			Value:       "root",
			Type:        types.AttackBOLA,
			Category:    "authorization",
			Description: "BOLA: Root object reference",
		},
		{
			Value:       "*",
			Type:        types.AttackBOLA,
			Category:    "authorization",
			Description: "BOLA: Wildcard reference",
		},
		{
			Value:       "all",
			Type:        types.AttackBOLA,
			Category:    "authorization",
			Description: "BOLA: All objects reference",
		},
	}
}
