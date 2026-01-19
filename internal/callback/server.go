// Package callback provides callback/out-of-band detection capabilities
package callback

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/su1ph3r/indago/pkg/types"
)

// CallbackServer handles HTTP and DNS callbacks for OOB detection
type CallbackServer struct {
	mu           sync.RWMutex
	httpPort     int
	dnsPort      int
	externalURL  string
	dnsDomain    string
	pending      map[string]*PendingCallback
	received     chan *CallbackEvent
	httpServer   *http.Server
	dnsServer    net.PacketConn
	timeout      time.Duration
	running      bool
}

// PendingCallback represents a callback we're waiting for
type PendingCallback struct {
	ID         string           `json:"id"`
	Token      string           `json:"token"`
	RequestID  string           `json:"request_id"`
	AttackType string           `json:"attack_type"`
	Endpoint   types.Endpoint   `json:"endpoint"`
	Payload    string           `json:"payload"`
	CreatedAt  time.Time        `json:"created_at"`
	ExpiresAt  time.Time        `json:"expires_at"`
	Received   bool             `json:"received"`
	ReceivedAt time.Time        `json:"received_at,omitempty"`
}

// CallbackEvent represents a received callback
type CallbackEvent struct {
	Token      string            `json:"token"`
	Type       string            `json:"type"` // http, dns
	SourceIP   string            `json:"source_ip"`
	Timestamp  time.Time         `json:"timestamp"`
	Data       map[string]string `json:"data"`
	Method     string            `json:"method,omitempty"`
	Path       string            `json:"path,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	DNSQuery   string            `json:"dns_query,omitempty"`
	QueryType  string            `json:"query_type,omitempty"`
}

// CallbackSettings holds callback server configuration
type CallbackSettings struct {
	HTTPPort    int           `yaml:"http_port" json:"http_port"`
	DNSPort     int           `yaml:"dns_port" json:"dns_port"`
	ExternalURL string        `yaml:"external_url" json:"external_url"`
	DNSDomain   string        `yaml:"dns_domain" json:"dns_domain"`
	Timeout     time.Duration `yaml:"timeout" json:"timeout"`
}

// NewCallbackServer creates a new callback server
func NewCallbackServer(settings CallbackSettings) *CallbackServer {
	if settings.HTTPPort == 0 {
		settings.HTTPPort = 8888
	}
	if settings.DNSPort == 0 {
		settings.DNSPort = 5353
	}
	if settings.Timeout == 0 {
		settings.Timeout = 30 * time.Second
	}

	return &CallbackServer{
		httpPort:    settings.HTTPPort,
		dnsPort:     settings.DNSPort,
		externalURL: settings.ExternalURL,
		dnsDomain:   settings.DNSDomain,
		pending:     make(map[string]*PendingCallback),
		received:    make(chan *CallbackEvent, 1000),
		timeout:     settings.Timeout,
	}
}

// Start starts the callback servers
func (cs *CallbackServer) Start(ctx context.Context) error {
	cs.mu.Lock()
	if cs.running {
		cs.mu.Unlock()
		return nil
	}
	cs.running = true
	cs.mu.Unlock()

	// Start HTTP server
	go cs.startHTTPServer(ctx)

	// Start DNS server
	go cs.startDNSServer(ctx)

	// Start cleanup goroutine
	go cs.cleanupExpired(ctx)

	return nil
}

// Stop stops the callback servers
func (cs *CallbackServer) Stop() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.running = false

	if cs.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cs.httpServer.Shutdown(ctx)
	}

	if cs.dnsServer != nil {
		cs.dnsServer.Close()
	}

	close(cs.received)

	return nil
}

// startHTTPServer starts the HTTP callback server
func (cs *CallbackServer) startHTTPServer(ctx context.Context) {
	mux := http.NewServeMux()

	// Main callback handler
	mux.HandleFunc("/c/", cs.handleCallback)
	mux.HandleFunc("/callback/", cs.handleCallback)

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Catch-all for any path (some payloads might not use our expected paths)
	mux.HandleFunc("/", cs.handleCatchAll)

	cs.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", cs.httpPort),
		Handler: mux,
	}

	if err := cs.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		// Log error but don't crash
	}
}

// handleCallback handles incoming HTTP callbacks
func (cs *CallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Extract token from path
	path := r.URL.Path
	var token string

	if strings.HasPrefix(path, "/c/") {
		token = strings.TrimPrefix(path, "/c/")
	} else if strings.HasPrefix(path, "/callback/") {
		token = strings.TrimPrefix(path, "/callback/")
	}

	// Remove any trailing path
	if idx := strings.Index(token, "/"); idx > 0 {
		token = token[:idx]
	}

	// Record callback
	event := &CallbackEvent{
		Token:     token,
		Type:      "http",
		SourceIP:  getClientIP(r),
		Timestamp: time.Now(),
		Method:    r.Method,
		Path:      r.URL.Path,
		Headers:   make(map[string]string),
		Data:      make(map[string]string),
	}

	// Capture headers
	for k, v := range r.Header {
		if len(v) > 0 {
			event.Headers[k] = v[0]
		}
	}

	// Capture body
	if r.Body != nil {
		body, _ := io.ReadAll(r.Body)
		event.Body = string(body)
	}

	// Capture query params
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			event.Data[k] = v[0]
		}
	}

	cs.recordCallback(token, event)

	// Return a minimal response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("1"))
}

// handleCatchAll handles requests to any path
func (cs *CallbackServer) handleCatchAll(w http.ResponseWriter, r *http.Request) {
	// Try to extract token from various places
	var token string

	// Check query params
	token = r.URL.Query().Get("token")
	if token == "" {
		token = r.URL.Query().Get("id")
	}

	// Check path for potential token
	if token == "" {
		parts := strings.Split(r.URL.Path, "/")
		for _, part := range parts {
			if len(part) >= 16 && isHex(part) {
				token = part
				break
			}
		}
	}

	event := &CallbackEvent{
		Token:     token,
		Type:      "http",
		SourceIP:  getClientIP(r),
		Timestamp: time.Now(),
		Method:    r.Method,
		Path:      r.URL.Path,
		Data:      make(map[string]string),
	}

	if token != "" {
		cs.recordCallback(token, event)
	}

	w.WriteHeader(http.StatusOK)
}

// startDNSServer starts the DNS callback server
func (cs *CallbackServer) startDNSServer(ctx context.Context) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", cs.dnsPort))
	if err != nil {
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return
	}

	cs.mu.Lock()
	cs.dnsServer = conn
	cs.mu.Unlock()

	buf := make([]byte, 512)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		// Parse DNS query
		if n > 12 {
			query := parseDNSQuery(buf[:n])
			if query != "" {
				// Extract token from subdomain
				token := cs.extractTokenFromDNS(query)

				event := &CallbackEvent{
					Token:     token,
					Type:      "dns",
					SourceIP:  remoteAddr.IP.String(),
					Timestamp: time.Now(),
					DNSQuery:  query,
					QueryType: "A",
					Data:      make(map[string]string),
				}

				cs.recordCallback(token, event)

				// Send a minimal DNS response
				response := buildDNSResponse(buf[:n])
				conn.WriteToUDP(response, remoteAddr)
			}
		}
	}
}

// extractTokenFromDNS extracts the token from a DNS query
func (cs *CallbackServer) extractTokenFromDNS(query string) string {
	// Token is typically the first subdomain
	// e.g., abc123.callback.example.com -> abc123
	parts := strings.Split(query, ".")
	if len(parts) > 0 {
		// Check if first part looks like a token
		if len(parts[0]) >= 8 && isHex(parts[0]) {
			return parts[0]
		}
	}
	return query
}

// RegisterCallback registers a pending callback
func (cs *CallbackServer) RegisterCallback(requestID, attackType string, endpoint types.Endpoint, payload string) string {
	token := generateToken()

	cs.mu.Lock()
	cs.pending[token] = &PendingCallback{
		ID:         generateToken(),
		Token:      token,
		RequestID:  requestID,
		AttackType: attackType,
		Endpoint:   endpoint,
		Payload:    payload,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(cs.timeout),
	}
	cs.mu.Unlock()

	return token
}

// recordCallback records a received callback
func (cs *CallbackServer) recordCallback(token string, event *CallbackEvent) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if pending, exists := cs.pending[token]; exists {
		pending.Received = true
		pending.ReceivedAt = event.Timestamp
	}

	// Send to channel
	select {
	case cs.received <- event:
	default:
		// Channel full, drop oldest
	}
}

// GetHTTPCallback returns the HTTP callback URL for a token
func (cs *CallbackServer) GetHTTPCallback(token string) string {
	if cs.externalURL != "" {
		return cs.externalURL + "/c/" + token
	}
	return fmt.Sprintf("http://localhost:%d/c/%s", cs.httpPort, token)
}

// GetDNSCallback returns the DNS callback domain for a token
func (cs *CallbackServer) GetDNSCallback(token string) string {
	if cs.dnsDomain != "" {
		return token + "." + cs.dnsDomain
	}
	return token + ".callback.local"
}

// WaitForCallback waits for a callback with the given token
func (cs *CallbackServer) WaitForCallback(ctx context.Context, token string) (*CallbackEvent, error) {
	deadline := time.Now().Add(cs.timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case event := <-cs.received:
			if event.Token == token {
				return event, nil
			}
			// Put back events for other tokens
			select {
			case cs.received <- event:
			default:
			}
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}

	return nil, fmt.Errorf("timeout waiting for callback")
}

// CheckCallback checks if a callback was received for a token
func (cs *CallbackServer) CheckCallback(token string) (*PendingCallback, bool) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if pending, exists := cs.pending[token]; exists {
		return pending, pending.Received
	}
	return nil, false
}

// GetPendingCallbacks returns all pending callbacks
func (cs *CallbackServer) GetPendingCallbacks() []*PendingCallback {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	var pending []*PendingCallback
	for _, p := range cs.pending {
		pending = append(pending, p)
	}
	return pending
}

// GetReceivedCallbacks returns callbacks that were received
func (cs *CallbackServer) GetReceivedCallbacks() []*PendingCallback {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	var received []*PendingCallback
	for _, p := range cs.pending {
		if p.Received {
			received = append(received, p)
		}
	}
	return received
}

// cleanupExpired removes expired pending callbacks
func (cs *CallbackServer) cleanupExpired(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cs.mu.Lock()
			now := time.Now()
			for token, pending := range cs.pending {
				if now.After(pending.ExpiresAt) && !pending.Received {
					delete(cs.pending, token)
				}
			}
			cs.mu.Unlock()
		}
	}
}

// ToFinding converts a received callback to a Finding
func (cb *PendingCallback) ToFinding() types.Finding {
	severity := types.SeverityHigh
	if cb.AttackType == "blind_ssrf" || cb.AttackType == "blind_xxe" {
		severity = types.SeverityCritical
	}

	return types.Finding{
		ID:          cb.ID,
		Type:        cb.AttackType,
		Severity:    severity,
		Confidence:  types.ConfidenceHigh,
		Title:       fmt.Sprintf("Out-of-Band %s Detected", strings.ToUpper(cb.AttackType)),
		Description: fmt.Sprintf("Received callback confirming %s vulnerability", cb.AttackType),
		Endpoint:    cb.Endpoint.Path,
		Method:      cb.Endpoint.Method,
		Payload:     cb.Payload,
		Timestamp:   cb.ReceivedAt,
		Evidence: &types.Evidence{
			MatchedData: []string{
				"Callback received at: " + cb.ReceivedAt.Format(time.RFC3339),
				"Token: " + cb.Token,
			},
		},
		Tags: []string{"oob", "callback", cb.AttackType},
	}
}

// Helper functions

func generateToken() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// parseDNSQuery extracts the query name from a DNS packet
func parseDNSQuery(packet []byte) string {
	if len(packet) < 12 {
		return ""
	}

	// Skip header (12 bytes), parse question
	offset := 12
	var labels []string

	for offset < len(packet) {
		length := int(packet[offset])
		if length == 0 {
			break
		}
		offset++
		if offset+length > len(packet) {
			break
		}
		labels = append(labels, string(packet[offset:offset+length]))
		offset += length
	}

	return strings.Join(labels, ".")
}

// buildDNSResponse builds a minimal DNS response
func buildDNSResponse(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}

	response := make([]byte, len(query)+16)
	copy(response, query)

	// Set response flags
	response[2] = 0x81 // Response, recursion desired
	response[3] = 0x80 // Recursion available

	// Set answer count to 1
	response[6] = 0
	response[7] = 1

	// Add answer (point to localhost)
	answerOffset := len(query)
	response[answerOffset] = 0xc0   // Pointer to name
	response[answerOffset+1] = 0x0c // Offset 12
	response[answerOffset+2] = 0    // Type A
	response[answerOffset+3] = 1
	response[answerOffset+4] = 0 // Class IN
	response[answerOffset+5] = 1
	response[answerOffset+6] = 0 // TTL
	response[answerOffset+7] = 0
	response[answerOffset+8] = 0
	response[answerOffset+9] = 60
	response[answerOffset+10] = 0 // RDLENGTH
	response[answerOffset+11] = 4
	response[answerOffset+12] = 127 // 127.0.0.1
	response[answerOffset+13] = 0
	response[answerOffset+14] = 0
	response[answerOffset+15] = 1

	return response[:answerOffset+16]
}

// GetStatus returns the server status as JSON
func (cs *CallbackServer) GetStatus() ([]byte, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	status := struct {
		Running     bool `json:"running"`
		HTTPPort    int  `json:"http_port"`
		DNSPort     int  `json:"dns_port"`
		ExternalURL string `json:"external_url"`
		PendingCount int `json:"pending_count"`
		ReceivedCount int `json:"received_count"`
	}{
		Running:     cs.running,
		HTTPPort:    cs.httpPort,
		DNSPort:     cs.dnsPort,
		ExternalURL: cs.externalURL,
	}

	for _, p := range cs.pending {
		if p.Received {
			status.ReceivedCount++
		} else {
			status.PendingCount++
		}
	}

	return json.Marshal(status)
}
