// Package fuzzer provides the core fuzzing engine
package fuzzer

import (
	"context"
	"net/http"
	"sync"

	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

// MultiAuthExecutor executes requests with multiple auth contexts
type MultiAuthExecutor struct {
	engine   *Engine
	contexts []types.AuthContext
	results  map[string]map[string]*FuzzResult // endpoint -> context -> result
	mu       sync.RWMutex
}

// MultiAuthResult represents the result of multi-auth execution
type MultiAuthResult struct {
	Endpoint types.Endpoint
	Results  map[string]*FuzzResult // context name -> result
}

// NewMultiAuthExecutor creates a new multi-auth executor
func NewMultiAuthExecutor(engine *Engine, contexts []types.AuthContext) *MultiAuthExecutor {
	return &MultiAuthExecutor{
		engine:   engine,
		contexts: contexts,
		results:  make(map[string]map[string]*FuzzResult),
	}
}

// ExecuteWithContexts executes a request with all auth contexts
func (mae *MultiAuthExecutor) ExecuteWithContexts(ctx context.Context, req payloads.FuzzRequest) *MultiAuthResult {
	endpointKey := req.Endpoint.Method + ":" + req.Endpoint.Path

	result := &MultiAuthResult{
		Endpoint: req.Endpoint,
		Results:  make(map[string]*FuzzResult),
	}

	// Execute request for each context
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, authCtx := range mae.contexts {
		wg.Add(1)
		go func(authContext types.AuthContext) {
			defer wg.Done()

			// Clone the request and apply auth context
			contextReq := mae.applyAuthContext(req, authContext)

			// Execute the request
			fuzzResult := mae.engine.executeRequest(ctx, contextReq)

			mu.Lock()
			result.Results[authContext.Name] = fuzzResult
			mu.Unlock()
		}(authCtx)
	}

	wg.Wait()

	// Store results
	mae.mu.Lock()
	mae.results[endpointKey] = make(map[string]*FuzzResult)
	for name, res := range result.Results {
		mae.results[endpointKey][name] = res
	}
	mae.mu.Unlock()

	return result
}

// applyAuthContext applies an auth context to a fuzz request
func (mae *MultiAuthExecutor) applyAuthContext(req payloads.FuzzRequest, authCtx types.AuthContext) payloads.FuzzRequest {
	// Clone the endpoint headers
	clonedHeaders := make(map[string]string)
	for k, v := range req.Endpoint.Headers {
		clonedHeaders[k] = v
	}

	// Apply auth context headers
	for k, v := range authCtx.Headers {
		clonedHeaders[k] = v
	}

	// Apply auth token based on type
	switch authCtx.AuthType {
	case "bearer":
		clonedHeaders["Authorization"] = "Bearer " + authCtx.Token
	case "basic":
		clonedHeaders["Authorization"] = "Basic " + authCtx.Token
	case "api_key":
		clonedHeaders["X-API-Key"] = authCtx.Token
	case "cookie":
		// Cookies are handled separately
	default:
		if authCtx.Token != "" {
			clonedHeaders["Authorization"] = authCtx.Token
		}
	}

	// Clone the endpoint with new headers
	clonedEndpoint := req.Endpoint
	clonedEndpoint.Headers = clonedHeaders

	return payloads.FuzzRequest{
		Endpoint: clonedEndpoint,
		Param:    req.Param,
		Payload:  req.Payload,
		Original: req.Original,
		Position: req.Position,
	}
}

// FuzzWithContexts fuzzes all endpoints with all auth contexts
func (mae *MultiAuthExecutor) FuzzWithContexts(ctx context.Context, requests []payloads.FuzzRequest) <-chan *MultiAuthResult {
	results := make(chan *MultiAuthResult, mae.engine.config.Scan.Concurrency*2)

	go func() {
		defer close(results)

		// Group requests by endpoint to avoid duplicate analysis
		endpointRequests := make(map[string][]payloads.FuzzRequest)
		for _, req := range requests {
			key := req.Endpoint.Method + ":" + req.Endpoint.Path
			endpointRequests[key] = append(endpointRequests[key], req)
		}

		// Process each endpoint
		for _, reqs := range endpointRequests {
			for _, req := range reqs {
				select {
				case <-ctx.Done():
					return
				default:
					mae.engine.rateLimiter.Wait(ctx)
					result := mae.ExecuteWithContexts(ctx, req)
					results <- result
				}
			}
		}
	}()

	return results
}

// GetResults returns all stored results
func (mae *MultiAuthExecutor) GetResults() map[string]map[string]*FuzzResult {
	mae.mu.RLock()
	defer mae.mu.RUnlock()

	// Return a copy
	copy := make(map[string]map[string]*FuzzResult)
	for k, v := range mae.results {
		copy[k] = make(map[string]*FuzzResult)
		for k2, v2 := range v {
			copy[k][k2] = v2
		}
	}
	return copy
}

// GetContexts returns the auth contexts
func (mae *MultiAuthExecutor) GetContexts() []types.AuthContext {
	return mae.contexts
}

// ApplyContextToRequest applies an auth context to an http.Request
func ApplyContextToRequest(req *http.Request, authCtx types.AuthContext) {
	// Apply headers
	for k, v := range authCtx.Headers {
		req.Header.Set(k, v)
	}

	// Apply auth based on type
	switch authCtx.AuthType {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+authCtx.Token)
	case "basic":
		req.Header.Set("Authorization", "Basic "+authCtx.Token)
	case "api_key":
		req.Header.Set("X-API-Key", authCtx.Token)
	case "cookie":
		// Cookies handled below
	default:
		if authCtx.Token != "" {
			req.Header.Set("Authorization", authCtx.Token)
		}
	}
}

// CompareContextResults compares results between two auth contexts
func CompareContextResults(resultA, resultB *FuzzResult) []string {
	var differences []string

	if resultA == nil || resultB == nil {
		return differences
	}

	if resultA.Error != nil && resultB.Error == nil {
		differences = append(differences, "Context A had error, Context B succeeded")
	} else if resultA.Error == nil && resultB.Error != nil {
		differences = append(differences, "Context A succeeded, Context B had error")
	}

	if resultA.Response != nil && resultB.Response != nil {
		respA, respB := resultA.Response, resultB.Response

		if respA.StatusCode != respB.StatusCode {
			differences = append(differences, "Status code difference")
		}

		if len(respA.Body) != len(respB.Body) {
			differences = append(differences, "Response body length difference")
		}

		if respA.ResponseTime*2 < respB.ResponseTime || respB.ResponseTime*2 < respA.ResponseTime {
			differences = append(differences, "Significant response time difference")
		}
	}

	return differences
}
