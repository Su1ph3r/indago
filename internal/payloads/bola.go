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
	} else {
		payloads = append(payloads, g.stringBOLAPayloads(param, originalValue)...)
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

// stringBOLAPayloads generates payloads for string-based object identifiers (e.g., usernames)
func (g *BOLAGenerator) stringBOLAPayloads(param *types.Parameter, original string) []Payload {
	var payloads []Payload

	// Common test usernames for horizontal privilege escalation
	commonUsers := []string{
		"admin", "administrator", "root", "test", "user",
		"user1", "user2", "guest", "demo", "operator",
		"service", "api", "default",
	}

	// If we have an original value, generate variants
	if original != "" {
		// Try sequential variants (name1 → name2, name3)
		if idx := indexOfTrailingNumber(original); idx >= 0 {
			prefix := original[:idx]
			numStr := original[idx:]
			if num, err := strconv.Atoi(numStr); err == nil {
				for _, delta := range []int{-1, 1, 2, 10, 100} {
					variant := fmt.Sprintf("%s%d", prefix, num+delta)
					if variant != original {
						payloads = append(payloads, Payload{
							Value:       variant,
							Type:        types.AttackBOLA,
							Category:    "authorization",
							Description: fmt.Sprintf("BOLA: Sequential string ID variant (%s)", variant),
							Metadata:    map[string]string{"original": original},
						})
					}
				}
			}
		}

		// Add common users that differ from original
		for _, u := range commonUsers {
			if u != original {
				payloads = append(payloads, Payload{
					Value:       u,
					Type:        types.AttackBOLA,
					Category:    "authorization",
					Description: fmt.Sprintf("BOLA: Common username (%s)", u),
					Metadata:    map[string]string{"original": original},
				})
			}
		}
	} else {
		// No original value — use common usernames directly
		for _, u := range commonUsers {
			payloads = append(payloads, Payload{
				Value:       u,
				Type:        types.AttackBOLA,
				Category:    "authorization",
				Description: fmt.Sprintf("BOLA: Common username (%s)", u),
			})
		}
	}

	// Slug-like path parameters often accept slugs
	nameLower := strings.ToLower(param.Name)
	if strings.Contains(nameLower, "slug") || strings.Contains(nameLower, "name") || strings.Contains(nameLower, "handle") {
		slugPayloads := []string{"test-item", "default-item", "first-item", "example"}
		for _, s := range slugPayloads {
			if s != original {
				payloads = append(payloads, Payload{
					Value:       s,
					Type:        types.AttackBOLA,
					Category:    "authorization",
					Description: fmt.Sprintf("BOLA: Slug variant (%s)", s),
					Metadata:    map[string]string{"original": original},
				})
			}
		}
	}

	return payloads
}

// indexOfTrailingNumber returns the index where trailing digits start, or -1
func indexOfTrailingNumber(s string) int {
	if len(s) == 0 {
		return -1
	}
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	if i == len(s) || i == 0 {
		return -1 // no trailing number, or entire string is digits
	}
	return i
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
