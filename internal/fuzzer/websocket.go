package fuzzer

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"nhooyr.io/websocket"

	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

// WebSocketFuzzer handles fuzzing of WebSocket endpoints
type WebSocketFuzzer struct {
	handshakeTimeout time.Duration
	readTimeout      time.Duration
	authHeader       string
}

// NewWebSocketFuzzer creates a new WebSocket fuzzer
func NewWebSocketFuzzer(config types.Config) *WebSocketFuzzer {
	handshakeTimeout := config.Attacks.WebSocket.HandshakeTimeout
	if handshakeTimeout == 0 {
		handshakeTimeout = 10 * time.Second
	}
	readTimeout := config.Attacks.WebSocket.ReadTimeout
	if readTimeout == 0 {
		readTimeout = 5 * time.Second
	}
	return &WebSocketFuzzer{
		handshakeTimeout: handshakeTimeout,
		readTimeout:      readTimeout,
		authHeader:       config.HTTP.AuthHeader,
	}
}

// Fuzz executes WebSocket fuzz requests and returns results on a channel
func (f *WebSocketFuzzer) Fuzz(ctx context.Context, requests []payloads.FuzzRequest) <-chan *FuzzResult {
	results := make(chan *FuzzResult, len(requests))

	go func() {
		defer close(results)
		for _, req := range requests {
			select {
			case <-ctx.Done():
				return
			default:
				result := f.executeRequest(ctx, req)
				results <- result
			}
		}
	}()

	return results
}

// executeRequest executes a single WebSocket fuzz request
func (f *WebSocketFuzzer) executeRequest(ctx context.Context, req payloads.FuzzRequest) *FuzzResult {
	start := time.Now()
	result := &FuzzResult{
		Request:   &req,
		Timestamp: start,
	}

	wsURL := f.buildWSURL(req.Endpoint)

	// Build dial options
	opts := &websocket.DialOptions{
		HTTPHeader: http.Header{},
	}

	// Set origin if specified in metadata
	if origin := req.Payload.Metadata["origin"]; origin != "" {
		opts.HTTPHeader.Set("Origin", origin)
	}

	// Handle auth stripping
	stripAuth := req.Payload.Metadata["strip_auth"]
	if stripAuth != "true" && f.authHeader != "" {
		parts := strings.SplitN(f.authHeader, " ", 2)
		if len(parts) == 2 {
			opts.HTTPHeader.Set("Authorization", f.authHeader)
		} else {
			opts.HTTPHeader.Set("Authorization", f.authHeader)
		}
	}

	// Set auth token override if specified
	if token := req.Payload.Metadata["auth_token"]; token != "" {
		opts.HTTPHeader.Set("Authorization", "Bearer "+token)
	}

	// Copy endpoint headers
	for k, v := range req.Endpoint.Headers {
		if stripAuth == "true" && strings.EqualFold(k, "Authorization") {
			continue
		}
		opts.HTTPHeader.Set(k, v)
	}

	// Perform WebSocket handshake
	dialCtx, dialCancel := context.WithTimeout(ctx, f.handshakeTimeout)
	defer dialCancel()

	conn, resp, err := websocket.Dial(dialCtx, wsURL, opts)
	if err != nil {
		result.Error = fmt.Errorf("websocket dial failed: %w", err)
		result.Duration = time.Since(start)
		// Still capture the HTTP response from the failed handshake
		if resp != nil {
			result.Response = httpResponseToTypes(resp)
		}
		result.ActualRequest = &types.HTTPRequest{
			Method:  "GET",
			URL:     wsURL,
			Headers: headerToMap(opts.HTTPHeader),
		}
		return result
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// Build the actual request record
	result.ActualRequest = &types.HTTPRequest{
		Method:  "GET",
		URL:     wsURL,
		Headers: headerToMap(opts.HTTPHeader),
	}

	// Record successful upgrade
	statusCode := 101
	if resp != nil {
		statusCode = resp.StatusCode
	}

	responseBody := ""

	// If payload has a message value, send it over the WebSocket
	if req.Payload.Value != "" {
		writeCtx, writeCancel := context.WithTimeout(ctx, f.readTimeout)
		err = conn.Write(writeCtx, websocket.MessageText, []byte(req.Payload.Value))
		writeCancel()
		if err != nil {
			result.Error = fmt.Errorf("websocket write failed: %w", err)
			result.Duration = time.Since(start)
			result.Response = &types.HTTPResponse{
				StatusCode: statusCode,
				Status:     fmt.Sprintf("%d WebSocket Upgrade", statusCode),
				Headers:    make(map[string]string),
				Body:       fmt.Sprintf("Write error: %v", err),
			}
			return result
		}

		// Read response
		readCtx, readCancel := context.WithTimeout(ctx, f.readTimeout)
		_, msg, readErr := conn.Read(readCtx)
		readCancel()
		if readErr != nil {
			// Timeout or close is not necessarily an error for fuzzing
			responseBody = fmt.Sprintf("Read: %v", readErr)
		} else {
			responseBody = string(msg)
		}
	}

	result.Duration = time.Since(start)
	result.Response = &types.HTTPResponse{
		StatusCode:   statusCode,
		Status:       fmt.Sprintf("%d WebSocket Upgrade", statusCode),
		Headers:      responseHeadersFromHTTP(resp),
		Body:         responseBody,
		ResponseTime: result.Duration,
	}

	return result
}

// buildWSURL converts an HTTP endpoint URL to a WebSocket URL
func (f *WebSocketFuzzer) buildWSURL(endpoint types.Endpoint) string {
	fullURL := endpoint.FullPath()
	fullURL = strings.Replace(fullURL, "https://", "wss://", 1)
	fullURL = strings.Replace(fullURL, "http://", "ws://", 1)
	// If no ws scheme was applied, prefix with ws://
	if !strings.HasPrefix(fullURL, "ws://") && !strings.HasPrefix(fullURL, "wss://") {
		fullURL = "ws://" + fullURL
	}
	return fullURL
}

// httpResponseToTypes converts an http.Response to types.HTTPResponse
func httpResponseToTypes(resp *http.Response) *types.HTTPResponse {
	if resp == nil {
		return nil
	}
	return &types.HTTPResponse{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Headers:    responseHeadersFromHTTP(resp),
	}
}

// responseHeadersFromHTTP extracts headers from an HTTP response
func responseHeadersFromHTTP(resp *http.Response) map[string]string {
	headers := make(map[string]string)
	if resp == nil {
		return headers
	}
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	return headers
}

// headerToMap converts http.Header to map[string]string
func headerToMap(h http.Header) map[string]string {
	m := make(map[string]string)
	for k, v := range h {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	return m
}

// FilterWebSocketRequests separates WebSocket-tagged requests from HTTP requests
func FilterWebSocketRequests(requests []payloads.FuzzRequest) (httpReqs, wsReqs []payloads.FuzzRequest) {
	for _, req := range requests {
		if req.Payload.Metadata != nil && req.Payload.Metadata["transport"] == "websocket" {
			wsReqs = append(wsReqs, req)
		} else {
			httpReqs = append(httpReqs, req)
		}
	}
	return
}
