package fuzzer

import (
	"encoding/base64"
	"net/http"
	"strings"
	"sync"

	"github.com/su1ph3r/indago/pkg/types"
)

// SessionManager manages authentication and session state
type SessionManager struct {
	mu        sync.RWMutex
	config    types.HTTPSettings
	cookies   map[string]string
	headers   map[string]string
	authToken string
	authType  string
}

// NewSessionManager creates a new session manager
func NewSessionManager(config types.HTTPSettings) *SessionManager {
	sm := &SessionManager{
		config:  config,
		cookies: make(map[string]string),
		headers: make(map[string]string),
	}

	// Initialize with config
	for k, v := range config.Cookies {
		sm.cookies[k] = v
	}

	for k, v := range config.Headers {
		sm.headers[k] = v
	}

	// Parse auth header
	if config.AuthHeader != "" {
		sm.parseAuthHeader(config.AuthHeader)
	} else if config.AuthToken != "" {
		sm.authToken = config.AuthToken
		sm.authType = "bearer"
	}

	return sm
}

// Apply applies session state to an HTTP request
func (sm *SessionManager) Apply(req *http.Request) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Apply custom headers
	for key, value := range sm.headers {
		req.Header.Set(key, value)
	}

	// Apply authentication
	if sm.authToken != "" {
		switch sm.authType {
		case "bearer":
			req.Header.Set("Authorization", "Bearer "+sm.authToken)
		case "basic":
			req.Header.Set("Authorization", "Basic "+sm.authToken)
		case "api_key":
			// API key can be in header or query, default to header
			req.Header.Set("X-API-Key", sm.authToken)
		default:
			// Custom auth header
			req.Header.Set("Authorization", sm.authToken)
		}
	}

	// Apply cookies
	if len(sm.cookies) > 0 {
		var cookieStr strings.Builder
		first := true
		for name, value := range sm.cookies {
			if !first {
				cookieStr.WriteString("; ")
			}
			cookieStr.WriteString(name)
			cookieStr.WriteString("=")
			cookieStr.WriteString(value)
			first = false
		}
		req.Header.Set("Cookie", cookieStr.String())
	}
}

// UpdateFromResponse updates session state from a response
func (sm *SessionManager) UpdateFromResponse(resp *http.Response) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Extract Set-Cookie headers
	for _, cookie := range resp.Cookies() {
		sm.cookies[cookie.Name] = cookie.Value
	}
}

// SetCookie sets a cookie
func (sm *SessionManager) SetCookie(name, value string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.cookies[name] = value
}

// SetHeader sets a header
func (sm *SessionManager) SetHeader(name, value string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.headers[name] = value
}

// SetAuth sets authentication
func (sm *SessionManager) SetAuth(authType, token string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.authType = authType
	sm.authToken = token
}

// SetBasicAuth sets basic authentication
func (sm *SessionManager) SetBasicAuth(username, password string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.authType = "basic"
	sm.authToken = base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

// SetBearerToken sets bearer token authentication
func (sm *SessionManager) SetBearerToken(token string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.authType = "bearer"
	sm.authToken = token
}

// GetCookie gets a cookie value
func (sm *SessionManager) GetCookie(name string) string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.cookies[name]
}

// GetHeader gets a header value
func (sm *SessionManager) GetHeader(name string) string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.headers[name]
}

// Clear clears all session state
func (sm *SessionManager) Clear() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.cookies = make(map[string]string)
	sm.headers = make(map[string]string)
	sm.authToken = ""
	sm.authType = ""
}

// parseAuthHeader parses an authorization header
func (sm *SessionManager) parseAuthHeader(header string) {
	// Format: "Authorization: Bearer xxx" or just "Bearer xxx"
	header = strings.TrimPrefix(header, "Authorization:")
	header = strings.TrimSpace(header)

	parts := strings.SplitN(header, " ", 2)
	if len(parts) == 2 {
		sm.authType = strings.ToLower(parts[0])
		sm.authToken = parts[1]
	} else {
		// Assume it's a raw token
		sm.authToken = header
	}
}

// Clone creates a copy of the session manager
func (sm *SessionManager) Clone() *SessionManager {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	clone := &SessionManager{
		config:    sm.config,
		cookies:   make(map[string]string),
		headers:   make(map[string]string),
		authToken: sm.authToken,
		authType:  sm.authType,
	}

	for k, v := range sm.cookies {
		clone.cookies[k] = v
	}

	for k, v := range sm.headers {
		clone.headers[k] = v
	}

	return clone
}

// AuthHandler handles authentication flows
type AuthHandler struct {
	session *SessionManager
	config  *types.AuthConfig
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(session *SessionManager, config *types.AuthConfig) *AuthHandler {
	return &AuthHandler{
		session: session,
		config:  config,
	}
}

// ConfigureAuth configures authentication based on the auth config
func (h *AuthHandler) ConfigureAuth() {
	if h.config == nil {
		return
	}

	switch h.config.Type {
	case "bearer":
		h.session.SetBearerToken(h.config.Value)
	case "basic":
		if h.config.Extra != nil {
			username := h.config.Extra["username"]
			password := h.config.Extra["password"]
			h.session.SetBasicAuth(username, password)
		}
	case "api_key":
		h.session.SetAuth("api_key", h.config.Value)
		if h.config.HeaderName != "" {
			h.session.SetHeader(h.config.HeaderName, h.config.Value)
		}
	}
}

// RequestInterceptor can modify requests before they are sent
type RequestInterceptor func(*http.Request) error

// ResponseInterceptor can process responses after they are received
type ResponseInterceptor func(*http.Response) error
