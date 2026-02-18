// Package fuzzer provides the core fuzzing engine
package fuzzer

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

// Engine is the core fuzzing engine
type Engine struct {
	config      types.Config
	client      *http.Client
	rateLimiter *RateLimiter
	session     *SessionManager
	mu          sync.Mutex
	stats       *Stats
}

// FuzzResult represents the result of a fuzz request
type FuzzResult struct {
	Request       *payloads.FuzzRequest
	ActualRequest *types.HTTPRequest // The actual HTTP request that was sent (with payload, session headers, etc.)
	Response      *types.HTTPResponse
	Baseline      *types.HTTPResponse
	Error         error
	Duration      time.Duration
	Timestamp     time.Time
}

// Stats tracks fuzzing statistics
type Stats struct {
	mu             sync.Mutex
	TotalRequests  int
	SuccessCount   int
	ErrorCount     int
	AnomalyCount   int
	StartTime      time.Time
	EndTime        time.Time
	RequestsPerSec float64
}

// NewEngine creates a new fuzzing engine
func NewEngine(config types.Config) *Engine {
	// Create HTTP client
	transport := &http.Transport{
		MaxIdleConns:        config.Scan.Concurrency * 2,
		MaxIdleConnsPerHost: config.Scan.Concurrency,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.Scan.VerifySSL,
		},
	}

	// Configure proxy if specified
	if config.HTTP.ProxyURL != "" {
		proxyURL, err := url.Parse(config.HTTP.ProxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Scan.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !config.Scan.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= config.Scan.MaxRedirects {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	return &Engine{
		config:      config,
		client:      client,
		rateLimiter: NewRateLimiter(config.Scan.RateLimit),
		session:     NewSessionManager(config.HTTP),
		stats:       &Stats{},
	}
}

// Fuzz starts fuzzing the given requests
func (e *Engine) Fuzz(ctx context.Context, requests []payloads.FuzzRequest) <-chan *FuzzResult {
	e.stats.StartTime = time.Now()
	e.stats.TotalRequests = len(requests)

	// Create worker pool
	workers := e.config.Scan.Concurrency
	if workers < 1 {
		workers = 10
	}

	// Create a fresh results channel for this Fuzz call so the engine is reusable.
	// Workers send to this local variable, not a struct field, to avoid a race
	// condition if Fuzz() is called again while workers are still running.
	results := make(chan *FuzzResult, workers*10)

	// Request channel for workers
	reqChan := make(chan payloads.FuzzRequest, workers*2)

	// Use a local WaitGroup so concurrent Fuzz() calls are independent.
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go e.worker(ctx, reqChan, results, &wg)
	}

	// Feed requests to workers
	go func() {
		for _, req := range requests {
			select {
			case <-ctx.Done():
				break
			case reqChan <- req:
			}
		}
		close(reqChan)
	}()

	// Wait for completion and close results channel
	go func() {
		wg.Wait()
		e.stats.mu.Lock()
		e.stats.EndTime = time.Now()
		duration := e.stats.EndTime.Sub(e.stats.StartTime).Seconds()
		if duration > 0 {
			e.stats.RequestsPerSec = float64(e.stats.TotalRequests) / duration
		}
		e.stats.mu.Unlock()
		close(results)
	}()

	return results
}

// worker processes fuzz requests.
// It sends results to the provided channel (local to the Fuzz() call) to avoid
// a race condition on the struct field when Fuzz() is called multiple times.
func (e *Engine) worker(ctx context.Context, requests <-chan payloads.FuzzRequest, results chan<- *FuzzResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for req := range requests {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Rate limit
		e.rateLimiter.Wait(ctx)

		// Execute request
		result := e.executeRequest(ctx, req)
		results <- result

		// Update stats
		e.stats.mu.Lock()
		if result.Error != nil {
			e.stats.ErrorCount++
		} else {
			e.stats.SuccessCount++
		}
		e.stats.mu.Unlock()
	}
}

// executeRequest executes a single fuzz request
func (e *Engine) executeRequest(ctx context.Context, fuzzReq payloads.FuzzRequest) *FuzzResult {
	result := &FuzzResult{
		Request:   &fuzzReq,
		Timestamp: time.Now(),
	}

	// Build the HTTP request
	httpReq, bodyStr, err := e.buildRequest(ctx, fuzzReq)
	if err != nil {
		result.Error = fmt.Errorf("failed to build request: %w", err)
		return result
	}

	// Save diff-auth Authorization before session.Apply overwrites it.
	// Only preserve if explicitly set in ep.Headers (from diff-auth context),
	// not from parameter examples which contain placeholder values like "Bearer <token>".
	diffAuthHeader := ""
	if _, hasDiffAuth := fuzzReq.Endpoint.Headers["Authorization"]; hasDiffAuth {
		diffAuthHeader = httpReq.Header.Get("Authorization")
	}

	// Apply session/auth
	e.session.Apply(httpReq)

	// Restore diff-auth header if it was set (from ep.Headers)
	if diffAuthHeader != "" {
		httpReq.Header.Set("Authorization", diffAuthHeader)
	}

	// Re-apply header fuzz payload after session.Apply() so the fuzz value
	// (e.g. a malicious JWT in the Authorization header) is not overwritten
	// by the session's default auth token.
	if fuzzReq.Position == "header" && fuzzReq.Param != nil {
		httpReq.Header.Set(fuzzReq.Param.Name, fuzzReq.Payload.Value)
	}

	// Capture the actual request (after session headers applied)
	actualHeaders := make(map[string]string)
	for key, values := range httpReq.Header {
		actualHeaders[key] = strings.Join(values, ", ")
	}
	result.ActualRequest = &types.HTTPRequest{
		Method:  httpReq.Method,
		URL:     httpReq.URL.String(),
		Headers: actualHeaders,
		Body:    bodyStr,
	}

	// Execute request with retry
	start := time.Now()
	resp, err := e.executeWithRetry(httpReq)
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err
		return result
	}

	result.Response = resp
	return result
}

// buildRequest builds an HTTP request from a fuzz request.
// Returns the http.Request and the request body string (for evidence capture).
func (e *Engine) buildRequest(ctx context.Context, fuzzReq payloads.FuzzRequest) (*http.Request, string, error) {
	ep := fuzzReq.Endpoint

	// Build URL with path parameters
	targetURL := ep.BaseURL + ep.Path

	// Apply payload to the appropriate location
	var body string
	queryParams := url.Values{}
	headerParams := make(map[string]string)

	for _, param := range ep.Parameters {
		value := e.getParamValue(&param)

		// If this is the target parameter, use the payload
		if fuzzReq.Param != nil && param.Name == fuzzReq.Param.Name && param.In == fuzzReq.Position {
			value = fuzzReq.Payload.Value
		}

		switch param.In {
		case "query":
			queryParams.Set(param.Name, value)
		case "path":
			targetURL = replacePathParam(targetURL, param.Name, value)
		case "header":
			// Skip Authorization from parameter examples — auth is managed by
			// session.Apply (--auth-header) and diff-auth contexts (ep.Headers).
			// Only include Authorization if this parameter is the active fuzz target
			// (e.g., JWT manipulation payloads targeting the Authorization header).
			isFuzzTarget := fuzzReq.Param != nil && param.Name == fuzzReq.Param.Name && param.In == fuzzReq.Position
			if strings.EqualFold(param.Name, "Authorization") && !isFuzzTarget {
				continue
			}
			headerParams[param.Name] = value
		}
	}

	// Add query string
	if len(queryParams) > 0 {
		targetURL += "?" + queryParams.Encode()
	}

	// Build body for POST/PUT/PATCH
	if ep.Body != nil && (ep.Method == "POST" || ep.Method == "PUT" || ep.Method == "PATCH") {
		body = e.buildBody(ep.Body, fuzzReq)
	}

	// Determine the HTTP method — may be overridden by payload metadata
	method := ep.Method
	if m, ok := fuzzReq.Payload.Metadata["override_method"]; ok && m != "" {
		if isValidHTTPMethod(m) {
			method = m
		}
	}

	// Create request
	var req *http.Request
	var err error

	if body != "" {
		req, err = http.NewRequestWithContext(ctx, method, targetURL, stringReader(body))
	} else {
		req, err = http.NewRequestWithContext(ctx, method, targetURL, nil)
	}

	if err != nil {
		return nil, "", err
	}

	// Apply header parameters from the endpoint spec (includes fuzz payloads)
	for key, value := range headerParams {
		req.Header.Set(key, value)
	}

	// Set headers
	for key, value := range ep.Headers {
		req.Header.Set(key, value)
	}

	// Set default headers from config
	for key, value := range e.config.HTTP.Headers {
		if req.Header.Get(key) == "" {
			req.Header.Set(key, value)
		}
	}

	// Set User-Agent
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", e.config.HTTP.UserAgent)
	}

	// Set Content-Type for body
	if body != "" && req.Header.Get("Content-Type") == "" {
		if ep.Body != nil && ep.Body.ContentType != "" {
			req.Header.Set("Content-Type", ep.Body.ContentType)
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
	}

	// Apply payload metadata overrides
	if ct, ok := fuzzReq.Payload.Metadata["override_content_type"]; ok && ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if _, ok := fuzzReq.Payload.Metadata["remove_content_type"]; ok {
		req.Header.Del("Content-Type")
	}
	if hdr, ok := fuzzReq.Payload.Metadata["inject_header"]; ok && hdr != "" {
		if val, ok2 := fuzzReq.Payload.Metadata["inject_header_value"]; ok2 {
			if isAllowedOverrideHeader(hdr) {
				req.Header.Set(hdr, val)
			}
		}
	}

	return req, body, nil
}

// buildBody builds the request body.
//
// When the fuzz target is a body parameter, the payload is injected into that
// field while all other body fields retain their example/default values.
//
// When the fuzz target is NOT a body parameter (e.g. path, query, header),
// the body is still populated from the endpoint's schema so that
// PUT/POST/PATCH requests carry a valid body and don't get rejected with 400.
func (e *Engine) buildBody(body *types.RequestBody, fuzzReq payloads.FuzzRequest) string {
	targetingBody := fuzzReq.Position == "body" && fuzzReq.Param != nil

	// If we have a top-level Example string, use it as the base body.
	if body.Example != nil {
		switch v := body.Example.(type) {
		case string:
			if targetingBody {
				return injectPayloadIntoJSON(v, fuzzReq.Param.Name, fuzzReq.Payload.Value)
			}
			return v
		}
	}

	// No top-level example -- build body from Fields if available.
	if len(body.Fields) > 0 {
		obj := make(map[string]interface{})
		for _, f := range body.Fields {
			// If this field is the fuzz target, inject the payload.
			if targetingBody && f.Name == fuzzReq.Param.Name {
				obj[f.Name] = fuzzReq.Payload.Value
				continue
			}
			// Otherwise, use the field's example or a type-appropriate default.
			obj[f.Name] = fieldValue(f)
		}
		data, err := json.Marshal(obj)
		if err != nil {
			return ""
		}
		return string(data)
	}

	return ""
}

// fieldValue returns an appropriate value for a BodyField: its Example if
// set, otherwise a zero-value placeholder based on its declared type.
func fieldValue(f types.BodyField) interface{} {
	if f.Example != nil {
		return f.Example
	}
	switch f.Type {
	case "integer", "number":
		return 0
	case "boolean":
		return false
	case "array":
		return []interface{}{}
	case "object":
		return map[string]interface{}{}
	default: // "string" and anything else
		return ""
	}
}

// getParamValue gets the value for a parameter
func (e *Engine) getParamValue(param *types.Parameter) string {
	if param.Example != nil {
		switch v := param.Example.(type) {
		case string:
			return v
		case float64:
			return fmt.Sprintf("%v", v)
		}
	}
	if param.Default != nil {
		switch v := param.Default.(type) {
		case string:
			return v
		case float64:
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

// executeWithRetry executes a request with retry logic
func (e *Engine) executeWithRetry(req *http.Request) (*types.HTTPResponse, error) {
	var lastErr error

	for attempt := 0; attempt <= e.config.Scan.MaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(e.config.Scan.RetryDelay)
		}

		resp, err := e.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		// Read response
		httpResp, err := readResponse(resp)
		if err != nil {
			lastErr = err
			resp.Body.Close()
			continue
		}

		return httpResp, nil
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", e.config.Scan.MaxRetries, lastErr)
}

// GetStats returns current statistics
func (e *Engine) GetStats() *Stats {
	e.stats.mu.Lock()
	defer e.stats.mu.Unlock()

	// Return a copy
	return &Stats{
		TotalRequests:  e.stats.TotalRequests,
		SuccessCount:   e.stats.SuccessCount,
		ErrorCount:     e.stats.ErrorCount,
		AnomalyCount:   e.stats.AnomalyCount,
		StartTime:      e.stats.StartTime,
		EndTime:        e.stats.EndTime,
		RequestsPerSec: e.stats.RequestsPerSec,
	}
}

// Client returns the underlying HTTP client for use by passive checks.
func (e *Engine) Client() *http.Client { return e.client }

// isValidHTTPMethod validates that a method string is a known HTTP method.
func isValidHTTPMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE":
		return true
	}
	return false
}

// isAllowedOverrideHeader validates that a header name is in the allowlist for metadata injection.
func isAllowedOverrideHeader(header string) bool {
	switch strings.ToLower(header) {
	case "x-http-method-override", "x-method-override", "x-http-method":
		return true
	}
	return false
}

// GetBaseline fetches a baseline response for comparison
func (e *Engine) GetBaseline(ctx context.Context, endpoint types.Endpoint) (*types.HTTPResponse, error) {
	// Build a request without any payloads
	fuzzReq := payloads.FuzzRequest{
		Endpoint: endpoint,
	}

	httpReq, _, err := e.buildRequest(ctx, fuzzReq)
	if err != nil {
		return nil, err
	}

	e.session.Apply(httpReq)
	e.rateLimiter.Wait(ctx)

	return e.executeWithRetry(httpReq)
}

// Helper functions

func replacePathParam(path, name, value string) string {
	// Replace {name} and :name patterns
	path = replaceAll(path, "{"+name+"}", value)
	path = replaceAll(path, ":"+name, value)
	return path
}

func replaceAll(s, old, new string) string {
	for {
		i := indexOf(s, old)
		if i < 0 {
			break
		}
		s = s[:i] + new + s[i+len(old):]
	}
	return s
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func injectPayloadIntoJSON(rawJSON, field, payload string) string {
	// Parse into a generic map, replace the target field, re-marshal.
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(rawJSON), &obj); err != nil {
		// Not valid JSON -- fall back to returning the original string.
		return rawJSON
	}
	obj[field] = payload
	data, err := json.Marshal(obj)
	if err != nil {
		return rawJSON
	}
	return string(data)
}
