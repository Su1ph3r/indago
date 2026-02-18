package fuzzer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

// --- RateLimiter tests ---

func TestNewRateLimiter_Positive(t *testing.T) {
	rl := NewRateLimiter(10)
	if !rl.enabled {
		t.Fatal("expected rate limiter to be enabled with positive rate")
	}
	if !rl.Allow() {
		t.Fatal("expected Allow() to return true for fresh limiter")
	}
}

func TestNewRateLimiter_Zero(t *testing.T) {
	rl := NewRateLimiter(0)
	if rl.enabled {
		t.Fatal("expected rate limiter to be disabled with zero rate")
	}
	// Disabled limiter should always allow
	if !rl.Allow() {
		t.Fatal("expected Allow() to return true when disabled")
	}
}

func TestNewRateLimiter_Negative(t *testing.T) {
	rl := NewRateLimiter(-5)
	if rl.enabled {
		t.Fatal("expected rate limiter to be disabled with negative rate")
	}
}

func TestRateLimiter_Wait(t *testing.T) {
	rl := NewRateLimiter(100)
	ctx := context.Background()
	if err := rl.Wait(ctx); err != nil {
		t.Fatalf("Wait() returned error: %v", err)
	}
}

func TestRateLimiter_Wait_Disabled(t *testing.T) {
	rl := NewRateLimiter(0)
	ctx := context.Background()
	if err := rl.Wait(ctx); err != nil {
		t.Fatalf("Wait() on disabled limiter returned error: %v", err)
	}
}

func TestRateLimiter_SetRate(t *testing.T) {
	rl := NewRateLimiter(10)
	rl.SetRate(50)
	if !rl.enabled {
		t.Fatal("expected limiter to remain enabled after SetRate(50)")
	}

	// Setting to zero should disable
	rl.SetRate(0)
	if rl.enabled {
		t.Fatal("expected limiter to be disabled after SetRate(0)")
	}
	if !rl.Allow() {
		t.Fatal("expected Allow() to return true when disabled")
	}

	// Re-enable
	rl.SetRate(20)
	if !rl.enabled {
		t.Fatal("expected limiter to be re-enabled after SetRate(20)")
	}
}

// --- AdaptiveRateLimiter tests ---

func TestNewAdaptiveRateLimiter(t *testing.T) {
	arl := NewAdaptiveRateLimiter(10, 1, 100)
	if arl.baseRate != 10 {
		t.Fatalf("expected baseRate=10, got %f", arl.baseRate)
	}
	if arl.minRate != 1 {
		t.Fatalf("expected minRate=1, got %f", arl.minRate)
	}
	if arl.maxRate != 100 {
		t.Fatalf("expected maxRate=100, got %f", arl.maxRate)
	}
	if arl.currentRate != 10 {
		t.Fatalf("expected currentRate=10, got %f", arl.currentRate)
	}
}

func TestAdaptiveRateLimiter_RecordSuccess(t *testing.T) {
	arl := NewAdaptiveRateLimiter(10, 1, 100)
	arl.RecordSuccess()
	if arl.successCount != 1 {
		t.Fatalf("expected successCount=1, got %d", arl.successCount)
	}
}

func TestAdaptiveRateLimiter_RecordError_429(t *testing.T) {
	arl := NewAdaptiveRateLimiter(10, 1, 100)
	initialRate := arl.CurrentRate()

	arl.RecordError(429)

	newRate := arl.CurrentRate()
	expectedRate := initialRate * 0.5
	if newRate != expectedRate {
		t.Fatalf("expected rate to halve from %f to %f, got %f", initialRate, expectedRate, newRate)
	}
}

func TestAdaptiveRateLimiter_RecordError_429_MinRate(t *testing.T) {
	arl := NewAdaptiveRateLimiter(2, 1.5, 100)
	// 2 * 0.5 = 1.0, but min is 1.5 so should clamp
	arl.RecordError(429)
	rate := arl.CurrentRate()
	if rate != 1.5 {
		t.Fatalf("expected rate to be clamped to minRate=1.5, got %f", rate)
	}
}

func TestAdaptiveRateLimiter_CurrentRate(t *testing.T) {
	arl := NewAdaptiveRateLimiter(25, 5, 50)
	if arl.CurrentRate() != 25 {
		t.Fatalf("expected CurrentRate()=25, got %f", arl.CurrentRate())
	}
}

func TestAdaptiveRateLimiter_Wait(t *testing.T) {
	arl := NewAdaptiveRateLimiter(100, 1, 200)
	ctx := context.Background()
	if err := arl.Wait(ctx); err != nil {
		t.Fatalf("Wait() returned error: %v", err)
	}
}

// --- TokenBucket tests ---

func TestNewTokenBucket(t *testing.T) {
	tb := NewTokenBucket(10, 5)
	if tb.maxTokens != 10 {
		t.Fatalf("expected maxTokens=10, got %f", tb.maxTokens)
	}
	if tb.refillRate != 5 {
		t.Fatalf("expected refillRate=5, got %f", tb.refillRate)
	}
}

func TestTokenBucket_Take(t *testing.T) {
	tb := NewTokenBucket(10, 5)
	// Should succeed - we start with 10 tokens
	if !tb.Take(5) {
		t.Fatal("expected Take(5) to succeed with 10 tokens")
	}
	if !tb.Take(5) {
		t.Fatal("expected Take(5) to succeed with 5 remaining tokens")
	}
	// Should fail - no tokens left (approximately; refill is tiny)
	if tb.Take(5) {
		t.Fatal("expected Take(5) to fail with ~0 tokens")
	}
}

func TestTokenBucket_TakeWait(t *testing.T) {
	tb := NewTokenBucket(5, 100) // high refill rate for fast test
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Drain tokens
	tb.Take(5)

	// TakeWait should eventually succeed as tokens refill
	if err := tb.TakeWait(ctx, 1); err != nil {
		t.Fatalf("TakeWait() returned error: %v", err)
	}
}

func TestTokenBucket_TakeWait_ContextCancel(t *testing.T) {
	tb := NewTokenBucket(1, 1) // 1 token/sec refill
	tb.Take(1)                 // drain

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := tb.TakeWait(ctx, 1)
	if err == nil {
		t.Fatal("expected TakeWait() to return error on context cancellation")
	}
}

// --- StateTracker tests ---

func TestNewStateTracker(t *testing.T) {
	st := NewStateTracker()
	if st == nil {
		t.Fatal("expected non-nil StateTracker")
	}
	if len(st.variables) != 0 {
		t.Fatal("expected empty variables map")
	}
}

func TestStateTracker_SetGetVariable(t *testing.T) {
	st := NewStateTracker()
	st.SetVariable("user_id", "12345")

	val, ok := st.GetVariable("user_id")
	if !ok {
		t.Fatal("expected variable to exist")
	}
	if val != "12345" {
		t.Fatalf("expected '12345', got '%s'", val)
	}

	// Non-existent variable
	_, ok = st.GetVariable("nonexistent")
	if ok {
		t.Fatal("expected nonexistent variable to return false")
	}
}

func TestStateTracker_SubstituteVariables(t *testing.T) {
	st := NewStateTracker()
	st.SetVariable("user_id", "42")
	st.SetVariable("name", "test")

	result := st.SubstituteVariables("User {{user_id}} is {{name}}")
	if result != "User 42 is test" {
		t.Fatalf("expected 'User 42 is test', got '%s'", result)
	}
}

func TestStateTracker_SubstituteVariables_Unresolved(t *testing.T) {
	st := NewStateTracker()
	st.SetVariable("known", "value")

	result := st.SubstituteVariables("{{known}} and {{unknown}}")
	if result != "value and {{unknown}}" {
		t.Fatalf("expected 'value and {{unknown}}', got '%s'", result)
	}
}

func TestStateTracker_HasUnresolvedVariables(t *testing.T) {
	st := NewStateTracker()
	st.SetVariable("a", "1")

	if st.HasUnresolvedVariables("{{a}}") {
		t.Fatal("expected no unresolved variables for '{{a}}'")
	}
	if !st.HasUnresolvedVariables("{{a}} {{b}}") {
		t.Fatal("expected unresolved variables for '{{a}} {{b}}'")
	}
	if st.HasUnresolvedVariables("no variables here") {
		t.Fatal("expected no unresolved variables in plain string")
	}
}

func TestStateTracker_Cookies(t *testing.T) {
	st := NewStateTracker()
	st.SetCookie("session", "abc123")
	st.SetCookie("theme", "dark")

	val, ok := st.GetCookie("session")
	if !ok || val != "abc123" {
		t.Fatalf("expected cookie 'session'='abc123', got '%s', ok=%v", val, ok)
	}

	_, ok = st.GetCookie("missing")
	if ok {
		t.Fatal("expected missing cookie to return false")
	}

	cookies := st.GetAllCookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}
	if cookies["session"] != "abc123" || cookies["theme"] != "dark" {
		t.Fatal("cookie values don't match")
	}

	// Verify GetAllCookies returns a copy
	cookies["session"] = "modified"
	val, _ = st.GetCookie("session")
	if val != "abc123" {
		t.Fatal("modifying returned cookie map should not affect original")
	}
}

func TestStateTracker_Resources(t *testing.T) {
	st := NewStateTracker()
	st.AddResource("user", "1")
	st.AddResource("user", "2")
	st.AddResource("user", "3")

	resources := st.GetResources("user")
	if len(resources) != 3 {
		t.Fatalf("expected 3 resources, got %d", len(resources))
	}

	// Test deduplication
	st.AddResource("user", "2")
	resources = st.GetResources("user")
	if len(resources) != 3 {
		t.Fatalf("expected 3 resources after adding duplicate, got %d", len(resources))
	}

	latest, ok := st.GetLatestResource("user")
	if !ok || latest != "3" {
		t.Fatalf("expected latest resource '3', got '%s'", latest)
	}

	// Non-existent resource type
	_, ok = st.GetLatestResource("order")
	if ok {
		t.Fatal("expected false for non-existent resource type")
	}
	if r := st.GetResources("order"); r != nil {
		t.Fatal("expected nil for non-existent resource type")
	}
}

func TestStateTracker_Clone(t *testing.T) {
	st := NewStateTracker()
	st.SetVariable("key", "val")
	st.SetCookie("sid", "xyz")
	st.SetToken("bearer", "tok123")
	st.AddResource("item", "i1")

	clone := st.Clone()

	// Verify clone has same data
	v, ok := clone.GetVariable("key")
	if !ok || v != "val" {
		t.Fatal("clone should have same variable")
	}
	c, ok := clone.GetCookie("sid")
	if !ok || c != "xyz" {
		t.Fatal("clone should have same cookie")
	}
	tok, ok := clone.GetToken("bearer")
	if !ok || tok != "tok123" {
		t.Fatal("clone should have same token")
	}
	res := clone.GetResources("item")
	if len(res) != 1 || res[0] != "i1" {
		t.Fatal("clone should have same resources")
	}

	// Modify original, verify clone is independent
	st.SetVariable("key", "modified")
	v, _ = clone.GetVariable("key")
	if v != "val" {
		t.Fatal("modifying original should not affect clone")
	}
}

func TestStateTracker_ImportExportJSON(t *testing.T) {
	st := NewStateTracker()
	st.SetVariable("host", "example.com")
	st.SetVariable("port", "8080")
	st.SetCookie("session", "abc")
	st.SetToken("jwt", "eyJ...")
	st.AddResource("user", "u1")
	st.AddResource("user", "u2")

	// Export
	data, err := st.ExportToJSON()
	if err != nil {
		t.Fatalf("ExportToJSON() error: %v", err)
	}

	// Import into new tracker
	st2 := NewStateTracker()
	if err := st2.ImportFromJSON(data); err != nil {
		t.Fatalf("ImportFromJSON() error: %v", err)
	}

	// Verify
	v, ok := st2.GetVariable("host")
	if !ok || v != "example.com" {
		t.Fatal("imported variable 'host' mismatch")
	}
	v, ok = st2.GetVariable("port")
	if !ok || v != "8080" {
		t.Fatal("imported variable 'port' mismatch")
	}
	c, ok := st2.GetCookie("session")
	if !ok || c != "abc" {
		t.Fatal("imported cookie mismatch")
	}
	tok, ok := st2.GetToken("jwt")
	if !ok || tok != "eyJ..." {
		t.Fatal("imported token mismatch")
	}
	res := st2.GetResources("user")
	if len(res) != 2 {
		t.Fatalf("expected 2 imported resources, got %d", len(res))
	}
}

func TestStateTracker_ImportJSON_Invalid(t *testing.T) {
	st := NewStateTracker()
	err := st.ImportFromJSON([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// --- DryRunSimulator tests ---

func TestNewDryRunSimulator(t *testing.T) {
	sim := NewDryRunSimulator()
	if sim == nil {
		t.Fatal("expected non-nil simulator")
	}
}

func TestDryRunSimulator_Simulate(t *testing.T) {
	sim := NewDryRunSimulator()

	param := &types.Parameter{Name: "id", In: "query"}
	requests := []payloads.FuzzRequest{
		{
			Endpoint: types.Endpoint{Path: "/users", Method: "GET"},
			Param:    param,
			Payload:  payloads.Payload{Type: "sqli", Value: "' OR 1=1--", Description: "SQL injection"},
			Position: "query",
		},
		{
			Endpoint: types.Endpoint{Path: "/users", Method: "GET"},
			Param:    param,
			Payload:  payloads.Payload{Type: "xss", Value: "<script>alert(1)</script>", Description: "XSS"},
			Position: "query",
		},
		{
			Endpoint: types.Endpoint{Path: "/admin", Method: "POST"},
			Payload:  payloads.Payload{Type: "auth_bypass", Value: "admin", Description: "Auth bypass"},
			Position: "body",
		},
	}

	results := sim.Simulate(requests)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// Verify first result
	r := results[0]
	if r.Endpoint != "/users" {
		t.Fatalf("expected endpoint '/users', got '%s'", r.Endpoint)
	}
	if r.Method != "GET" {
		t.Fatalf("expected method 'GET', got '%s'", r.Method)
	}
	if r.Parameter != "id" {
		t.Fatalf("expected parameter 'id', got '%s'", r.Parameter)
	}
	if r.PayloadType != "sqli" {
		t.Fatalf("expected payload type 'sqli', got '%s'", r.PayloadType)
	}

	// Third result has no param
	if results[2].Parameter != "" {
		t.Fatalf("expected empty parameter for request without param, got '%s'", results[2].Parameter)
	}
}

func TestDryRunSimulator_GroupByEndpoint(t *testing.T) {
	sim := NewDryRunSimulator()

	results := []SimulateResult{
		{Endpoint: "/users", Method: "GET", PayloadType: "sqli"},
		{Endpoint: "/users", Method: "GET", PayloadType: "xss"},
		{Endpoint: "/admin", Method: "POST", PayloadType: "auth_bypass"},
	}

	grouped := sim.GroupByEndpoint(results)
	if len(grouped) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(grouped))
	}
	if len(grouped["GET /users"]) != 2 {
		t.Fatalf("expected 2 results for 'GET /users', got %d", len(grouped["GET /users"]))
	}
	if len(grouped["POST /admin"]) != 1 {
		t.Fatalf("expected 1 result for 'POST /admin', got %d", len(grouped["POST /admin"]))
	}
}

func TestDryRunSimulator_GetSummary(t *testing.T) {
	sim := NewDryRunSimulator()

	results := []SimulateResult{
		{Endpoint: "/users", Method: "GET", PayloadType: "sqli", Parameter: "id"},
		{Endpoint: "/users", Method: "GET", PayloadType: "xss", Parameter: "id"},
		{Endpoint: "/admin", Method: "POST", PayloadType: "auth_bypass", Parameter: "role"},
		{Endpoint: "/admin", Method: "POST", PayloadType: "sqli", Parameter: "name"},
	}

	summary := sim.GetSummary(results)
	if summary.TotalRequests != 4 {
		t.Fatalf("expected TotalRequests=4, got %d", summary.TotalRequests)
	}
	if summary.UniqueEndpoints != 2 {
		t.Fatalf("expected UniqueEndpoints=2, got %d", summary.UniqueEndpoints)
	}
	if summary.ByAttackType["sqli"] != 2 {
		t.Fatalf("expected 2 sqli attacks, got %d", summary.ByAttackType["sqli"])
	}
	if summary.ByAttackType["xss"] != 1 {
		t.Fatalf("expected 1 xss attack, got %d", summary.ByAttackType["xss"])
	}
	if summary.ByParameter["id"] != 2 {
		t.Fatalf("expected parameter 'id' count=2, got %d", summary.ByParameter["id"])
	}
}

// --- Extractor tests ---

func TestNewExtractor(t *testing.T) {
	st := NewStateTracker()
	ext := NewExtractor(st, true)
	if ext == nil {
		t.Fatal("expected non-nil extractor")
	}
	if ext.state != st {
		t.Fatal("expected extractor state to match provided state tracker")
	}
}

func TestExtractor_AddRule_GetRules(t *testing.T) {
	ext := NewExtractor(nil, false)
	rule := ExtractionRule{
		Name:   "auth_token",
		Type:   "json",
		Path:   "$.token",
		SaveAs: "auth_token",
	}
	ext.AddRule(rule)

	rules := ext.GetRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Name != "auth_token" {
		t.Fatalf("expected rule name 'auth_token', got '%s'", rules[0].Name)
	}

	// Verify GetRules returns a copy
	rules[0].Name = "modified"
	rulesAgain := ext.GetRules()
	if rulesAgain[0].Name != "auth_token" {
		t.Fatal("modifying returned rules should not affect original")
	}
}

func TestExtractor_AddRules(t *testing.T) {
	ext := NewExtractor(nil, false)
	rules := []ExtractionRule{
		{Name: "rule1", Type: "json"},
		{Name: "rule2", Type: "regex"},
	}
	ext.AddRules(rules)
	if len(ext.GetRules()) != 2 {
		t.Fatalf("expected 2 rules after AddRules, got %d", len(ext.GetRules()))
	}
}

// --- RequestDeduplicator tests ---

func TestNewRequestDeduplicator(t *testing.T) {
	dedup := NewRequestDeduplicator()
	if dedup == nil {
		t.Fatal("expected non-nil deduplicator")
	}
}

func TestRequestDeduplicator_Deduplicate(t *testing.T) {
	dedup := NewRequestDeduplicator()

	param := &types.Parameter{Name: "q", In: "query"}
	requests := []payloads.FuzzRequest{
		{
			Endpoint: types.Endpoint{Path: "/search", Method: "GET"},
			Param:    param,
			Payload:  payloads.Payload{Type: "sqli", Value: "' OR 1=1"},
		},
		{
			Endpoint: types.Endpoint{Path: "/search", Method: "GET"},
			Param:    param,
			Payload:  payloads.Payload{Type: "sqli", Value: "' OR 1=1"}, // duplicate
		},
		{
			Endpoint: types.Endpoint{Path: "/search", Method: "GET"},
			Param:    param,
			Payload:  payloads.Payload{Type: "xss", Value: "<script>"},
		},
	}

	unique := dedup.Deduplicate(requests)
	if len(unique) != 2 {
		t.Fatalf("expected 2 unique requests, got %d", len(unique))
	}
}

func TestRequestDeduplicator_RemovedCount(t *testing.T) {
	dedup := NewRequestDeduplicator()

	requests := []payloads.FuzzRequest{
		{Endpoint: types.Endpoint{Path: "/a", Method: "GET"}, Payload: payloads.Payload{Value: "1"}},
		{Endpoint: types.Endpoint{Path: "/a", Method: "GET"}, Payload: payloads.Payload{Value: "1"}},
		{Endpoint: types.Endpoint{Path: "/b", Method: "GET"}, Payload: payloads.Payload{Value: "2"}},
	}

	dedup.Deduplicate(requests)
	removed := dedup.RemovedCount(3)
	if removed != 1 {
		t.Fatalf("expected 1 removed, got %d", removed)
	}
}

// --- ResponseComparator tests ---

func TestResponseComparator_Compare_Identical(t *testing.T) {
	comp := NewResponseComparator(0.1)

	baseline := &types.HTTPResponse{
		StatusCode:    200,
		Body:          `{"status":"ok"}`,
		ContentLength: 15,
		Headers:       map[string]string{"Content-Type": "application/json"},
	}
	fuzzed := &types.HTTPResponse{
		StatusCode:    200,
		Body:          `{"status":"ok"}`,
		ContentLength: 15,
		Headers:       map[string]string{"Content-Type": "application/json"},
	}

	result := comp.Compare(baseline, fuzzed)
	if result.IsAnomaly {
		t.Fatal("identical responses should not be flagged as anomaly")
	}
	if !result.StatusCodeMatch {
		t.Fatal("status codes should match")
	}
	if result.BodySimilarity != 1.0 {
		t.Fatalf("expected body similarity 1.0, got %f", result.BodySimilarity)
	}
}

func TestResponseComparator_Compare_DifferentStatus(t *testing.T) {
	comp := NewResponseComparator(0.1)

	baseline := &types.HTTPResponse{
		StatusCode:    200,
		Body:          `ok`,
		ContentLength: 2,
		Headers:       map[string]string{},
	}
	fuzzed := &types.HTTPResponse{
		StatusCode:    500,
		Body:          `internal server error`,
		ContentLength: 21,
		Headers:       map[string]string{},
	}

	result := comp.Compare(baseline, fuzzed)
	if result.StatusCodeMatch {
		t.Fatal("status codes should not match")
	}
	if result.StatusCodeDiff != 300 {
		t.Fatalf("expected status code diff 300, got %d", result.StatusCodeDiff)
	}
	if !result.IsAnomaly {
		t.Fatal("large status code difference should be anomaly")
	}
}

func TestResponseComparator_Compare_NilInputs(t *testing.T) {
	comp := NewResponseComparator(0.1)

	result := comp.Compare(nil, nil)
	if !result.IsAnomaly {
		t.Fatal("nil inputs should be flagged as anomaly")
	}

	resp := &types.HTTPResponse{StatusCode: 200, Headers: map[string]string{}}
	result = comp.Compare(resp, nil)
	if !result.IsAnomaly {
		t.Fatal("nil fuzzed response should be anomaly")
	}

	result = comp.Compare(nil, resp)
	if !result.IsAnomaly {
		t.Fatal("nil baseline should be anomaly")
	}
}

func TestResponseComparator_Compare_HeaderChanges(t *testing.T) {
	comp := NewResponseComparator(0.1)

	baseline := &types.HTTPResponse{
		StatusCode:    200,
		Body:          "ok",
		ContentLength: 2,
		Headers:       map[string]string{"X-Custom": "value1"},
	}
	fuzzed := &types.HTTPResponse{
		StatusCode:    200,
		Body:          "ok",
		ContentLength: 2,
		Headers:       map[string]string{"X-Custom": "value2", "X-New": "added"},
	}

	result := comp.Compare(baseline, fuzzed)
	if len(result.HeaderChanges) == 0 {
		t.Fatal("expected header changes to be detected")
	}
}

func TestResponseComparator_DefaultThreshold(t *testing.T) {
	comp := NewResponseComparator(0) // zero should use default
	if comp.threshold != 0.1 {
		t.Fatalf("expected default threshold 0.1, got %f", comp.threshold)
	}

	comp = NewResponseComparator(-1) // negative should use default
	if comp.threshold != 0.1 {
		t.Fatalf("expected default threshold 0.1, got %f", comp.threshold)
	}
}

// --- Engine tests with httptest ---

func TestNewEngine(t *testing.T) {
	cfg := *types.DefaultConfig()
	cfg.Scan.Concurrency = 2
	cfg.Scan.RateLimit = 0 // disable rate limiting for tests

	engine := NewEngine(cfg)
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if engine.client == nil {
		t.Fatal("expected non-nil HTTP client")
	}
}

func TestEngine_Fuzz_SimpleServer(t *testing.T) {
	// Create a test server that returns 200 with a JSON body
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	cfg := *types.DefaultConfig()
	cfg.Scan.Concurrency = 2
	cfg.Scan.RateLimit = 0
	cfg.Scan.MaxRetries = 0
	cfg.Scan.Timeout = 5 * time.Second

	engine := NewEngine(cfg)

	param := types.Parameter{Name: "id", In: "query", Example: "1"}
	requests := []payloads.FuzzRequest{
		{
			Endpoint: types.Endpoint{
				BaseURL: server.URL,
				Path:    "/api/users",
				Method:  "GET",
				Parameters: []types.Parameter{param},
				Headers: map[string]string{},
			},
			Param:    &param,
			Payload:  payloads.Payload{Type: "sqli", Value: "' OR 1=1--", Metadata: map[string]string{}},
			Position: "query",
		},
		{
			Endpoint: types.Endpoint{
				BaseURL: server.URL,
				Path:    "/api/users",
				Method:  "GET",
				Parameters: []types.Parameter{param},
				Headers: map[string]string{},
			},
			Param:    &param,
			Payload:  payloads.Payload{Type: "xss", Value: "<script>alert(1)</script>", Metadata: map[string]string{}},
			Position: "query",
		},
	}

	ctx := context.Background()
	resultsCh := engine.Fuzz(ctx, requests)

	var results []*FuzzResult
	for r := range resultsCh {
		results = append(results, r)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	for i, r := range results {
		if r.Error != nil {
			t.Fatalf("result[%d] had error: %v", i, r.Error)
		}
		if r.Response == nil {
			t.Fatalf("result[%d] had nil response", i)
		}
		if r.Response.StatusCode != 200 {
			t.Fatalf("result[%d] expected status 200, got %d", i, r.Response.StatusCode)
		}
		if r.ActualRequest == nil {
			t.Fatalf("result[%d] had nil ActualRequest", i)
		}
		if r.Duration <= 0 {
			t.Fatalf("result[%d] had zero/negative duration", i)
		}
	}

	// Verify stats
	stats := engine.GetStats()
	if stats.TotalRequests != 2 {
		t.Fatalf("expected TotalRequests=2, got %d", stats.TotalRequests)
	}
	if stats.SuccessCount != 2 {
		t.Fatalf("expected SuccessCount=2, got %d", stats.SuccessCount)
	}
	if stats.ErrorCount != 0 {
		t.Fatalf("expected ErrorCount=0, got %d", stats.ErrorCount)
	}
}

func TestEngine_Fuzz_ServerErrors(t *testing.T) {
	// Server that returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "internal error")
	}))
	defer server.Close()

	cfg := *types.DefaultConfig()
	cfg.Scan.Concurrency = 1
	cfg.Scan.RateLimit = 0
	cfg.Scan.MaxRetries = 0
	cfg.Scan.Timeout = 5 * time.Second

	engine := NewEngine(cfg)

	requests := []payloads.FuzzRequest{
		{
			Endpoint: types.Endpoint{
				BaseURL: server.URL,
				Path:    "/api/test",
				Method:  "GET",
				Headers: map[string]string{},
			},
			Payload:  payloads.Payload{Type: "test", Value: "payload", Metadata: map[string]string{}},
			Position: "query",
		},
	}

	ctx := context.Background()
	resultsCh := engine.Fuzz(ctx, requests)

	var results []*FuzzResult
	for r := range resultsCh {
		results = append(results, r)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	// Server returned 500, but that's still a valid HTTP response, not an error
	r := results[0]
	if r.Error != nil {
		t.Fatalf("expected no error for HTTP 500, got: %v", r.Error)
	}
	if r.Response.StatusCode != 500 {
		t.Fatalf("expected status 500, got %d", r.Response.StatusCode)
	}
}

func TestEngine_Fuzz_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // slow response
		w.WriteHeader(200)
	}))
	defer server.Close()

	cfg := *types.DefaultConfig()
	cfg.Scan.Concurrency = 1
	cfg.Scan.RateLimit = 0
	cfg.Scan.MaxRetries = 0
	cfg.Scan.Timeout = 5 * time.Second

	engine := NewEngine(cfg)

	// Create many requests
	var requests []payloads.FuzzRequest
	for i := 0; i < 100; i++ {
		requests = append(requests, payloads.FuzzRequest{
			Endpoint: types.Endpoint{
				BaseURL: server.URL,
				Path:    fmt.Sprintf("/api/test/%d", i),
				Method:  "GET",
				Headers: map[string]string{},
			},
			Payload:  payloads.Payload{Type: "test", Value: "v", Metadata: map[string]string{}},
			Position: "query",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	resultsCh := engine.Fuzz(ctx, requests)

	var results []*FuzzResult
	for r := range resultsCh {
		results = append(results, r)
	}

	// Should have processed fewer than all 100 requests due to cancellation
	if len(results) >= 100 {
		t.Fatalf("expected fewer than 100 results due to context cancellation, got %d", len(results))
	}
}

func TestEngine_Client(t *testing.T) {
	cfg := *types.DefaultConfig()
	engine := NewEngine(cfg)
	client := engine.Client()
	if client == nil {
		t.Fatal("expected non-nil client from Engine.Client()")
	}
}

func TestEngine_GetStats(t *testing.T) {
	cfg := *types.DefaultConfig()
	engine := NewEngine(cfg)

	stats := engine.GetStats()
	if stats.TotalRequests != 0 {
		t.Fatalf("expected TotalRequests=0 before fuzzing, got %d", stats.TotalRequests)
	}
	if stats.SuccessCount != 0 {
		t.Fatalf("expected SuccessCount=0 before fuzzing, got %d", stats.SuccessCount)
	}
}

func TestEngine_Fuzz_HeaderParamInjection(t *testing.T) {
	// Test that header parameters (e.g. Authorization) are sent with fuzz payloads
	// and that the fuzz payload survives session.Apply() overwriting.
	var receivedAuth string
	var receivedCustom string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedCustom = r.Header.Get("X-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	cfg := *types.DefaultConfig()
	cfg.Scan.Concurrency = 1
	cfg.Scan.RateLimit = 0
	cfg.Scan.MaxRetries = 0
	cfg.Scan.Timeout = 5 * time.Second
	// Set a session auth token so session.Apply() will set Authorization
	cfg.HTTP.AuthToken = "legitimate-token"

	engine := NewEngine(cfg)

	// Test 1: JWT payload targeting Authorization header must override session token
	authParam := types.Parameter{Name: "Authorization", In: "header", Example: "Bearer original"}
	jwtPayload := "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWV9."
	requests := []payloads.FuzzRequest{
		{
			Endpoint: types.Endpoint{
				BaseURL:    server.URL,
				Path:       "/api/admin",
				Method:     "GET",
				Parameters: []types.Parameter{authParam},
				Headers:    map[string]string{},
			},
			Param:    &authParam,
			Payload:  payloads.Payload{Type: "jwt_manipulation", Value: jwtPayload, Metadata: map[string]string{}},
			Position: "header",
		},
	}

	ctx := context.Background()
	resultsCh := engine.Fuzz(ctx, requests)
	for r := range resultsCh {
		if r.Error != nil {
			t.Fatalf("header injection request failed: %v", r.Error)
		}
	}

	if receivedAuth != jwtPayload {
		t.Fatalf("expected Authorization header to be JWT payload %q, got %q", jwtPayload, receivedAuth)
	}

	// Test 2: Custom header parameter (X-Api-Key) injection
	apiKeyParam := types.Parameter{Name: "X-Api-Key", In: "header", Example: "valid-key"}
	requests = []payloads.FuzzRequest{
		{
			Endpoint: types.Endpoint{
				BaseURL:    server.URL,
				Path:       "/api/data",
				Method:     "GET",
				Parameters: []types.Parameter{apiKeyParam},
				Headers:    map[string]string{},
			},
			Param:    &apiKeyParam,
			Payload:  payloads.Payload{Type: "auth_bypass", Value: "invalid-key-probe", Metadata: map[string]string{}},
			Position: "header",
		},
	}

	resultsCh = engine.Fuzz(ctx, requests)
	for r := range resultsCh {
		if r.Error != nil {
			t.Fatalf("custom header injection request failed: %v", r.Error)
		}
		// Verify ActualRequest captured the fuzz header
		if r.ActualRequest == nil {
			t.Fatal("expected ActualRequest to be set")
		}
		if got := r.ActualRequest.Headers["X-Api-Key"]; got != "invalid-key-probe" {
			t.Fatalf("expected ActualRequest to capture X-Api-Key='invalid-key-probe', got %q", got)
		}
	}

	if receivedCustom != "invalid-key-probe" {
		t.Fatalf("expected X-Api-Key header to be 'invalid-key-probe', got %q", receivedCustom)
	}
}

// --- RequestCache tests ---

func TestNewRequestCache(t *testing.T) {
	cache := NewRequestCache(nil)
	if cache == nil {
		t.Fatal("expected non-nil cache with nil config")
	}
	if cache.maxSize != 10000 {
		t.Fatalf("expected default maxSize=10000, got %d", cache.maxSize)
	}
}

func TestRequestCache_BaselineRoundTrip(t *testing.T) {
	cache := NewRequestCache(DefaultCacheConfig())
	ep := types.Endpoint{Method: "GET", BaseURL: "http://example.com", Path: "/users"}
	resp := &types.HTTPResponse{StatusCode: 200, Body: "ok", Headers: map[string]string{}}

	// Initially no baseline
	_, ok := cache.GetBaseline(ep)
	if ok {
		t.Fatal("expected no baseline initially")
	}

	cache.SetBaseline(ep, resp)

	cached, ok := cache.GetBaseline(ep)
	if !ok {
		t.Fatal("expected baseline to be cached")
	}
	if cached.StatusCode != 200 {
		t.Fatalf("expected cached status 200, got %d", cached.StatusCode)
	}
}

func TestRequestCache_IsDuplicate(t *testing.T) {
	cache := NewRequestCache(DefaultCacheConfig())
	req := payloads.FuzzRequest{
		Endpoint: types.Endpoint{Method: "GET", BaseURL: "http://test.com", Path: "/api"},
		Payload:  payloads.Payload{Type: "sqli", Value: "' OR 1=1"},
		Position: "query",
	}

	if cache.IsDuplicate(req) {
		t.Fatal("should not be duplicate before marking")
	}

	cache.MarkSeen(req)

	if !cache.IsDuplicate(req) {
		t.Fatal("should be duplicate after marking")
	}
}

func TestRequestCache_Stats(t *testing.T) {
	cache := NewRequestCache(DefaultCacheConfig())
	stats := cache.Stats()
	if stats.BaselineEntries != 0 || stats.ResponseEntries != 0 || stats.Fingerprints != 0 {
		t.Fatal("expected all zero stats for fresh cache")
	}
}

// --- SessionManager tests ---

func TestNewSessionManager(t *testing.T) {
	settings := types.HTTPSettings{
		Headers:   map[string]string{"X-Custom": "value"},
		Cookies:   map[string]string{"sid": "abc"},
		UserAgent: "TestAgent",
	}
	sm := NewSessionManager(settings)
	if sm == nil {
		t.Fatal("expected non-nil session manager")
	}
	if sm.GetCookie("sid") != "abc" {
		t.Fatal("expected cookie 'sid' to be initialized")
	}
	if sm.GetHeader("X-Custom") != "value" {
		t.Fatal("expected header 'X-Custom' to be initialized")
	}
}

func TestSessionManager_Apply(t *testing.T) {
	settings := types.HTTPSettings{
		Headers:   map[string]string{},
		Cookies:   map[string]string{"session": "xyz"},
		AuthToken: "my-token",
	}
	sm := NewSessionManager(settings)

	req := httptest.NewRequest("GET", "http://example.com/api", nil)
	sm.Apply(req)

	auth := req.Header.Get("Authorization")
	if auth != "Bearer my-token" {
		t.Fatalf("expected 'Bearer my-token', got '%s'", auth)
	}

	cookie := req.Header.Get("Cookie")
	if cookie == "" {
		t.Fatal("expected Cookie header to be set")
	}
}

func TestSessionManager_SetBearerToken(t *testing.T) {
	sm := NewSessionManager(types.HTTPSettings{Headers: map[string]string{}, Cookies: map[string]string{}})
	sm.SetBearerToken("new-token")

	req := httptest.NewRequest("GET", "http://example.com", nil)
	sm.Apply(req)

	if req.Header.Get("Authorization") != "Bearer new-token" {
		t.Fatalf("expected bearer token, got '%s'", req.Header.Get("Authorization"))
	}
}

func TestSessionManager_Clone(t *testing.T) {
	sm := NewSessionManager(types.HTTPSettings{Headers: map[string]string{}, Cookies: map[string]string{}})
	sm.SetCookie("a", "1")
	sm.SetHeader("X-Test", "val")
	sm.SetBearerToken("tok")

	clone := sm.Clone()
	if clone.GetCookie("a") != "1" {
		t.Fatal("clone should have same cookie")
	}
	if clone.GetHeader("X-Test") != "val" {
		t.Fatal("clone should have same header")
	}

	// Modify original
	sm.SetCookie("a", "2")
	if clone.GetCookie("a") != "1" {
		t.Fatal("modifying original should not affect clone")
	}
}

func TestSessionManager_Clear(t *testing.T) {
	sm := NewSessionManager(types.HTTPSettings{Headers: map[string]string{}, Cookies: map[string]string{}})
	sm.SetCookie("a", "1")
	sm.SetHeader("X-H", "v")
	sm.SetBearerToken("tok")

	sm.Clear()

	if sm.GetCookie("a") != "" {
		t.Fatal("expected empty cookie after Clear()")
	}
	if sm.GetHeader("X-H") != "" {
		t.Fatal("expected empty header after Clear()")
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	sm.Apply(req)
	if req.Header.Get("Authorization") != "" {
		t.Fatal("expected no authorization after Clear()")
	}
}

// --- Helper function tests ---

func TestReplacePathParam(t *testing.T) {
	result := replacePathParam("/users/{user_id}/posts", "user_id", "42")
	if result != "/users/42/posts" {
		t.Fatalf("expected '/users/42/posts', got '%s'", result)
	}

	result = replacePathParam("/users/:user_id/posts", "user_id", "42")
	if result != "/users/42/posts" {
		t.Fatalf("expected '/users/42/posts', got '%s'", result)
	}
}

func TestIsValidHTTPMethod(t *testing.T) {
	valid := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
	for _, m := range valid {
		if !isValidHTTPMethod(m) {
			t.Fatalf("expected %s to be valid", m)
		}
	}
	if isValidHTTPMethod("INVALID") {
		t.Fatal("expected 'INVALID' to not be valid")
	}
	if isValidHTTPMethod("") {
		t.Fatal("expected empty string to not be valid")
	}
}

func TestIsAllowedOverrideHeader(t *testing.T) {
	allowed := []string{"X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"}
	for _, h := range allowed {
		if !isAllowedOverrideHeader(h) {
			t.Fatalf("expected %s to be allowed", h)
		}
	}
	if isAllowedOverrideHeader("Authorization") {
		t.Fatal("expected 'Authorization' to not be allowed")
	}
	if isAllowedOverrideHeader("X-Custom") {
		t.Fatal("expected 'X-Custom' to not be allowed")
	}
}

// --- buildBody tests ---

func TestBuildBody_NonBodyFuzz_WithFields(t *testing.T) {
	// Scenario: BOLA fuzzing a path parameter on a PUT endpoint.
	// The body should be populated from the endpoint's Body.Fields even though
	// the fuzz target is NOT a body parameter.
	engine := NewEngine(*types.DefaultConfig())

	body := &types.RequestBody{
		ContentType: "application/json",
		Fields: []types.BodyField{
			{Name: "password", Type: "string", Example: "pass4"},
		},
	}
	fuzzReq := payloads.FuzzRequest{
		Endpoint: types.Endpoint{
			Path:   "/users/v1/{username}/password",
			Method: "PUT",
		},
		Param:    &types.Parameter{Name: "username", In: "path"},
		Payload:  payloads.Payload{Type: "bola", Value: "admin", Metadata: map[string]string{}},
		Position: "path",
	}

	result := engine.buildBody(body, fuzzReq)
	if result == "" {
		t.Fatal("expected non-empty body when Fields have examples")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if parsed["password"] != "pass4" {
		t.Fatalf("expected password='pass4', got %v", parsed["password"])
	}
}

func TestBuildBody_BodyFuzz_WithFields(t *testing.T) {
	// When fuzzing a body parameter, the payload should be injected into
	// the targeted field while other fields keep their example values.
	engine := NewEngine(*types.DefaultConfig())

	body := &types.RequestBody{
		ContentType: "application/json",
		Fields: []types.BodyField{
			{Name: "username", Type: "string", Example: "testuser"},
			{Name: "password", Type: "string", Example: "pass4"},
		},
	}
	param := &types.Parameter{Name: "password", In: "body"}
	fuzzReq := payloads.FuzzRequest{
		Endpoint: types.Endpoint{
			Path:   "/users/v1/{username}/password",
			Method: "PUT",
		},
		Param:    param,
		Payload:  payloads.Payload{Type: "sqli", Value: "' OR 1=1--", Metadata: map[string]string{}},
		Position: "body",
	}

	result := engine.buildBody(body, fuzzReq)

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if parsed["password"] != "' OR 1=1--" {
		t.Fatalf("expected payload injected into password, got %v", parsed["password"])
	}
	if parsed["username"] != "testuser" {
		t.Fatalf("expected username='testuser', got %v", parsed["username"])
	}
}

func TestBuildBody_ExampleString_NonBodyFuzz(t *testing.T) {
	// When body.Example is set and fuzz target is NOT the body,
	// the example string should be returned as-is.
	engine := NewEngine(*types.DefaultConfig())

	body := &types.RequestBody{
		Example: `{"password":"pass4"}`,
	}
	fuzzReq := payloads.FuzzRequest{
		Position: "path",
		Param:    &types.Parameter{Name: "username", In: "path"},
		Payload:  payloads.Payload{Type: "bola", Value: "admin", Metadata: map[string]string{}},
	}

	result := engine.buildBody(body, fuzzReq)
	if result != `{"password":"pass4"}` {
		t.Fatalf("expected example string returned as-is, got %q", result)
	}
}

func TestBuildBody_ExampleString_BodyFuzz_Injection(t *testing.T) {
	// When body.Example is a JSON string and the fuzz target is a body param,
	// the payload should be injected into the target field.
	engine := NewEngine(*types.DefaultConfig())

	body := &types.RequestBody{
		Example: `{"username":"alice","password":"secret"}`,
	}
	param := &types.Parameter{Name: "password", In: "body"}
	fuzzReq := payloads.FuzzRequest{
		Param:    param,
		Payload:  payloads.Payload{Type: "sqli", Value: "injected", Metadata: map[string]string{}},
		Position: "body",
	}

	result := engine.buildBody(body, fuzzReq)

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if parsed["password"] != "injected" {
		t.Fatalf("expected password='injected', got %v", parsed["password"])
	}
	if parsed["username"] != "alice" {
		t.Fatalf("expected username to be preserved, got %v", parsed["username"])
	}
}

func TestBuildBody_Fields_TypeDefaults(t *testing.T) {
	// Fields without examples should get type-appropriate defaults.
	engine := NewEngine(*types.DefaultConfig())

	body := &types.RequestBody{
		Fields: []types.BodyField{
			{Name: "name", Type: "string"},
			{Name: "count", Type: "integer"},
			{Name: "active", Type: "boolean"},
		},
	}
	fuzzReq := payloads.FuzzRequest{
		Position: "query",
		Payload:  payloads.Payload{Metadata: map[string]string{}},
	}

	result := engine.buildBody(body, fuzzReq)

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if parsed["name"] != "" {
		t.Fatalf("expected name='', got %v", parsed["name"])
	}
	if parsed["count"] != float64(0) {
		t.Fatalf("expected count=0, got %v", parsed["count"])
	}
	if parsed["active"] != false {
		t.Fatalf("expected active=false, got %v", parsed["active"])
	}
}

func TestBuildBody_EmptyFields_NilExample(t *testing.T) {
	// No example and no fields -- should return empty string.
	engine := NewEngine(*types.DefaultConfig())

	body := &types.RequestBody{}
	fuzzReq := payloads.FuzzRequest{
		Position: "path",
		Payload:  payloads.Payload{Metadata: map[string]string{}},
	}

	result := engine.buildBody(body, fuzzReq)
	if result != "" {
		t.Fatalf("expected empty body, got %q", result)
	}
}

func TestInjectPayloadIntoJSON(t *testing.T) {
	original := `{"username":"alice","role":"user"}`
	result := injectPayloadIntoJSON(original, "role", "admin")

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if parsed["role"] != "admin" {
		t.Fatalf("expected role='admin', got %v", parsed["role"])
	}
	if parsed["username"] != "alice" {
		t.Fatalf("expected username preserved, got %v", parsed["username"])
	}
}

func TestInjectPayloadIntoJSON_InvalidJSON(t *testing.T) {
	// Non-JSON input should be returned as-is.
	result := injectPayloadIntoJSON("not json", "field", "value")
	if result != "not json" {
		t.Fatalf("expected original string returned for invalid JSON, got %q", result)
	}
}

func TestEngine_Fuzz_PUTWithBodyFields_PathFuzz(t *testing.T) {
	// End-to-end: PUT endpoint with path param fuzz should send body from Fields.
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		receivedBody = string(buf[:n])
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	cfg := *types.DefaultConfig()
	cfg.Scan.Concurrency = 1
	cfg.Scan.RateLimit = 0
	cfg.Scan.MaxRetries = 0
	cfg.Scan.Timeout = 5 * time.Second

	engine := NewEngine(cfg)

	usernameParam := types.Parameter{Name: "username", In: "path", Example: "normaluser"}
	requests := []payloads.FuzzRequest{
		{
			Endpoint: types.Endpoint{
				BaseURL:    server.URL,
				Path:       "/users/v1/{username}/password",
				Method:     "PUT",
				Parameters: []types.Parameter{usernameParam},
				Headers:    map[string]string{},
				Body: &types.RequestBody{
					ContentType: "application/json",
					Fields: []types.BodyField{
						{Name: "password", Type: "string", Example: "pass4"},
					},
				},
			},
			Param:    &usernameParam,
			Payload:  payloads.Payload{Type: "bola", Value: "admin", Metadata: map[string]string{}},
			Position: "path",
		},
	}

	ctx := context.Background()
	resultsCh := engine.Fuzz(ctx, requests)

	for r := range resultsCh {
		if r.Error != nil {
			t.Fatalf("request failed: %v", r.Error)
		}
		if r.Response.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", r.Response.StatusCode)
		}
	}

	// Verify the server received a body with the password field
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(receivedBody), &parsed); err != nil {
		t.Fatalf("server received invalid JSON body: %v (body was: %q)", err, receivedBody)
	}
	if parsed["password"] != "pass4" {
		t.Fatalf("expected server to receive password='pass4', got %v", parsed["password"])
	}
}
