package inference

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

// ---------------------------------------------------------------------------
// NewSchemaInferrer
// ---------------------------------------------------------------------------

func TestNewSchemaInferrer_Defaults(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})
	if si.minConfidence != 0.7 {
		t.Errorf("expected default minConfidence 0.7, got %f", si.minConfidence)
	}
	if si.threshold != 0.8 {
		t.Errorf("expected default threshold 0.8, got %f", si.threshold)
	}
	if len(si.requests) != 0 {
		t.Errorf("expected empty requests slice, got %d", len(si.requests))
	}
	if len(si.clusters) != 0 {
		t.Errorf("expected empty clusters map, got %d", len(si.clusters))
	}
}

func TestNewSchemaInferrer_CustomSettings(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{
		MinConfidence:    0.5,
		ClusterThreshold: 0.9,
		MaxExamples:      10,
	})
	if si.minConfidence != 0.5 {
		t.Errorf("expected minConfidence 0.5, got %f", si.minConfidence)
	}
	if si.threshold != 0.9 {
		t.Errorf("expected threshold 0.9, got %f", si.threshold)
	}
}

// ---------------------------------------------------------------------------
// AddRequest / AddRequests
// ---------------------------------------------------------------------------

func TestAddRequest(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})
	si.AddRequest(CapturedRequest{Method: "GET", Path: "/api/users"})
	if len(si.requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(si.requests))
	}
	si.AddRequest(CapturedRequest{Method: "POST", Path: "/api/users"})
	if len(si.requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(si.requests))
	}
}

func TestAddRequests(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})
	reqs := []CapturedRequest{
		{Method: "GET", Path: "/a"},
		{Method: "GET", Path: "/b"},
		{Method: "GET", Path: "/c"},
	}
	si.AddRequests(reqs)
	if len(si.requests) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(si.requests))
	}
}

// ---------------------------------------------------------------------------
// Path normalization
// ---------------------------------------------------------------------------

func TestNormalizePath_NumericID(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})
	result := si.normalizePath("/api/users/123")
	if result != "/api/users/{id}" {
		t.Errorf("expected /api/users/{id}, got %s", result)
	}
}

func TestNormalizePath_UUID(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})
	result := si.normalizePath("/api/orders/550e8400-e29b-41d4-a716-446655440000")
	if result != "/api/orders/{uuid}" {
		t.Errorf("expected /api/orders/{uuid}, got %s", result)
	}
}

func TestNormalizePath_ObjectId(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})
	result := si.normalizePath("/api/items/507f1f77bcf86cd799439011")
	if result != "/api/items/{objectId}" {
		t.Errorf("expected /api/items/{objectId}, got %s", result)
	}
}

func TestNormalizePath_Slug(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})
	result := si.normalizePath("/blog/posts/my-first-post")
	if result != "/blog/posts/{slug}" {
		t.Errorf("expected /blog/posts/{slug}, got %s", result)
	}
}

func TestNormalizePath_StaticSegments(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})
	result := si.normalizePath("/api/health")
	if result != "/api/health" {
		t.Errorf("expected /api/health, got %s", result)
	}
}

func TestNormalizePath_MultipleDynamic(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})
	result := si.normalizePath("/api/users/42/posts/99")
	if result != "/api/users/{id}/posts/{id}" {
		t.Errorf("expected /api/users/{id}/posts/{id}, got %s", result)
	}
}

// ---------------------------------------------------------------------------
// Infer — basic inference
// ---------------------------------------------------------------------------

func TestInfer_BasicEndpoints(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})

	si.AddRequests([]CapturedRequest{
		{Method: "GET", URL: "https://api.example.com/api/users/123", Path: "/api/users/123"},
		{Method: "GET", URL: "https://api.example.com/api/users/456", Path: "/api/users/456"},
		{Method: "GET", URL: "https://api.example.com/api/users/789", Path: "/api/users/789"},
	})

	endpoints, err := si.Infer()
	if err != nil {
		t.Fatalf("Infer failed: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}

	ep := endpoints[0]
	if ep.Method != "GET" {
		t.Errorf("expected method GET, got %s", ep.Method)
	}
	if ep.Path != "/api/users/{id}" {
		t.Errorf("expected path /api/users/{id}, got %s", ep.Path)
	}
	if ep.BaseURL != "https://api.example.com" {
		t.Errorf("expected baseURL https://api.example.com, got %s", ep.BaseURL)
	}
}

func TestInfer_MultipleEndpoints(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})

	si.AddRequests([]CapturedRequest{
		{Method: "GET", URL: "https://api.example.com/api/users/1", Path: "/api/users/1"},
		{Method: "POST", URL: "https://api.example.com/api/users", Path: "/api/users",
			Body: `{"name":"alice"}`, ContentType: "application/json"},
	})

	endpoints, err := si.Infer()
	if err != nil {
		t.Fatalf("Infer failed: %v", err)
	}
	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(endpoints))
	}
}

func TestInfer_QueryParameters(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})

	si.AddRequests([]CapturedRequest{
		{Method: "GET", URL: "https://api.example.com/api/users", Path: "/api/users",
			Query: map[string]string{"page": "1", "limit": "10"}},
		{Method: "GET", URL: "https://api.example.com/api/users", Path: "/api/users",
			Query: map[string]string{"page": "2", "limit": "10"}},
	})

	endpoints, err := si.Infer()
	if err != nil {
		t.Fatalf("Infer failed: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}

	ep := endpoints[0]
	// Should have query parameters inferred
	queryParams := 0
	for _, p := range ep.Parameters {
		if p.In == "query" {
			queryParams++
		}
	}
	if queryParams < 1 {
		t.Errorf("expected at least 1 query parameter, got %d", queryParams)
	}
}

func TestInfer_PathParameters(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})

	si.AddRequests([]CapturedRequest{
		{Method: "GET", URL: "https://api.example.com/api/users/100", Path: "/api/users/100"},
		{Method: "GET", URL: "https://api.example.com/api/users/200", Path: "/api/users/200"},
	})

	endpoints, err := si.Infer()
	if err != nil {
		t.Fatalf("Infer failed: %v", err)
	}

	ep := endpoints[0]
	foundPathParam := false
	for _, p := range ep.Parameters {
		if p.In == "path" && p.Name == "id" {
			foundPathParam = true
			if p.Type != "integer" {
				t.Errorf("expected path param type 'integer', got '%s'", p.Type)
			}
			if !p.Required {
				t.Error("expected path param to be required")
			}
		}
	}
	if !foundPathParam {
		t.Error("expected path parameter 'id' not found")
	}
}

func TestInfer_BodyParameters(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})

	si.AddRequests([]CapturedRequest{
		{Method: "POST", URL: "https://api.example.com/api/users", Path: "/api/users",
			Body: `{"name":"alice","email":"alice@example.com"}`, ContentType: "application/json"},
		{Method: "POST", URL: "https://api.example.com/api/users", Path: "/api/users",
			Body: `{"name":"bob","email":"bob@example.com"}`, ContentType: "application/json"},
	})

	endpoints, err := si.Infer()
	if err != nil {
		t.Fatalf("Infer failed: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}

	ep := endpoints[0]
	if ep.Body == nil {
		t.Fatal("expected request body, got nil")
	}
	if len(ep.Body.Fields) < 2 {
		t.Errorf("expected at least 2 body fields, got %d", len(ep.Body.Fields))
	}

	fieldNames := map[string]bool{}
	for _, f := range ep.Body.Fields {
		fieldNames[f.Name] = true
	}
	if !fieldNames["name"] {
		t.Error("expected body field 'name'")
	}
	if !fieldNames["email"] {
		t.Error("expected body field 'email'")
	}
}

func TestInfer_HeaderParameters(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})

	si.AddRequests([]CapturedRequest{
		{Method: "GET", URL: "https://api.example.com/api/data", Path: "/api/data",
			Headers: map[string]string{"Authorization": "Bearer token123"}},
		{Method: "GET", URL: "https://api.example.com/api/data", Path: "/api/data",
			Headers: map[string]string{"Authorization": "Bearer token456"}},
	})

	endpoints, err := si.Infer()
	if err != nil {
		t.Fatalf("Infer failed: %v", err)
	}

	ep := endpoints[0]
	foundHeader := false
	for _, p := range ep.Parameters {
		if p.In == "header" && p.Name == "Authorization" {
			foundHeader = true
		}
	}
	if !foundHeader {
		t.Error("expected header parameter 'Authorization' not found")
	}
}

func TestInfer_NoRequests(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})
	endpoints, err := si.Infer()
	if err != nil {
		t.Fatalf("Infer failed: %v", err)
	}
	if len(endpoints) != 0 {
		t.Errorf("expected 0 endpoints, got %d", len(endpoints))
	}
}

func TestInfer_EndpointTags(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})
	si.AddRequest(CapturedRequest{
		Method: "GET", URL: "https://api.example.com/api/test", Path: "/api/test",
	})
	endpoints, err := si.Infer()
	if err != nil {
		t.Fatalf("Infer failed: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
	if len(endpoints[0].Tags) == 0 || endpoints[0].Tags[0] != "inferred" {
		t.Errorf("expected tag 'inferred', got %v", endpoints[0].Tags)
	}
}

// ---------------------------------------------------------------------------
// GetClusters
// ---------------------------------------------------------------------------

func TestGetClusters_Empty(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})
	clusters := si.GetClusters()
	if len(clusters) != 0 {
		t.Errorf("expected 0 clusters, got %d", len(clusters))
	}
}

func TestGetClusters_AfterInfer(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})
	si.AddRequests([]CapturedRequest{
		{Method: "GET", URL: "https://api.example.com/api/users/1", Path: "/api/users/1"},
		{Method: "GET", URL: "https://api.example.com/api/users/2", Path: "/api/users/2"},
		{Method: "GET", URL: "https://api.example.com/api/users/3", Path: "/api/users/3"},
		{Method: "POST", URL: "https://api.example.com/api/users", Path: "/api/users",
			Body: `{"name":"test"}`, ContentType: "application/json"},
	})

	_, err := si.Infer()
	if err != nil {
		t.Fatalf("Infer failed: %v", err)
	}

	clusters := si.GetClusters()
	if len(clusters) != 2 {
		t.Errorf("expected 2 clusters, got %d", len(clusters))
	}

	// The GET /api/users/{id} cluster should have 3 requests
	getCluster, ok := clusters["GET:/api/users/{id}"]
	if !ok {
		t.Fatal("expected cluster 'GET:/api/users/{id}' not found")
	}
	if getCluster.Count != 3 {
		t.Errorf("expected count 3, got %d", getCluster.Count)
	}
	if getCluster.Method != "GET" {
		t.Errorf("expected method GET, got %s", getCluster.Method)
	}
	if getCluster.PathPattern != "/api/users/{id}" {
		t.Errorf("expected path /api/users/{id}, got %s", getCluster.PathPattern)
	}
}

func TestGetClusters_ExamplesLimit(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})
	for i := 0; i < 10; i++ {
		si.AddRequest(CapturedRequest{
			Method: "GET",
			URL:    "https://api.example.com/api/items",
			Path:   "/api/items",
		})
	}

	si.Infer()
	clusters := si.GetClusters()
	cluster := clusters["GET:/api/items"]
	if cluster == nil {
		t.Fatal("expected cluster not found")
	}
	// Examples should be capped at 5
	if len(cluster.Examples) > 5 {
		t.Errorf("expected at most 5 examples, got %d", len(cluster.Examples))
	}
}

// ---------------------------------------------------------------------------
// Parameter type inference
// ---------------------------------------------------------------------------

func TestInferTypeFromExamples_Integer(t *testing.T) {
	result := inferTypeFromExamples([]string{"1", "42", "100"})
	if result != "integer" {
		t.Errorf("expected 'integer', got '%s'", result)
	}
}

func TestInferTypeFromExamples_Number(t *testing.T) {
	result := inferTypeFromExamples([]string{"1.5", "3.14", "2.0"})
	if result != "number" {
		t.Errorf("expected 'number', got '%s'", result)
	}
}

func TestInferTypeFromExamples_Boolean(t *testing.T) {
	result := inferTypeFromExamples([]string{"true", "false"})
	if result != "boolean" {
		t.Errorf("expected 'boolean', got '%s'", result)
	}
}

func TestInferTypeFromExamples_String(t *testing.T) {
	result := inferTypeFromExamples([]string{"hello", "world"})
	if result != "string" {
		t.Errorf("expected 'string', got '%s'", result)
	}
}

func TestInferTypeFromExamples_Empty(t *testing.T) {
	result := inferTypeFromExamples([]string{})
	if result != "string" {
		t.Errorf("expected 'string' for empty, got '%s'", result)
	}
}

func TestInferTypeFromExamples_MixedNumericAndString(t *testing.T) {
	result := inferTypeFromExamples([]string{"1", "abc"})
	if result != "string" {
		t.Errorf("expected 'string' for mixed, got '%s'", result)
	}
}

func TestInferTypeFromExamples_NegativeNumbers(t *testing.T) {
	result := inferTypeFromExamples([]string{"-1", "-42"})
	if result != "integer" {
		t.Errorf("expected 'integer', got '%s'", result)
	}
}

// ---------------------------------------------------------------------------
// normalizeSegment
// ---------------------------------------------------------------------------

func TestNormalizeSegment_Email(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})
	result := si.normalizeSegment("user@example.com")
	if result != "{email}" {
		t.Errorf("expected {email}, got %s", result)
	}
}

func TestNormalizeSegment_Token(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})
	// 20+ alphanumeric chars should be a token
	result := si.normalizeSegment("abcdefghijklmnopqrstu")
	if result != "{token}" {
		t.Errorf("expected {token}, got %s", result)
	}
}

func TestNormalizeSegment_StaticWord(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})
	result := si.normalizeSegment("users")
	if result != "users" {
		t.Errorf("expected 'users', got '%s'", result)
	}
}

// ---------------------------------------------------------------------------
// NewOpenAPIGenerator
// ---------------------------------------------------------------------------

func TestNewOpenAPIGenerator_Defaults(t *testing.T) {
	gen := NewOpenAPIGenerator("", "", "")
	if gen.title != "Inferred API" {
		t.Errorf("expected default title 'Inferred API', got '%s'", gen.title)
	}
	if gen.version != "1.0.0" {
		t.Errorf("expected default version '1.0.0', got '%s'", gen.version)
	}
}

func TestNewOpenAPIGenerator_Custom(t *testing.T) {
	gen := NewOpenAPIGenerator("My API", "2.0.0", "A test API")
	if gen.title != "My API" {
		t.Errorf("expected title 'My API', got '%s'", gen.title)
	}
	if gen.version != "2.0.0" {
		t.Errorf("expected version '2.0.0', got '%s'", gen.version)
	}
	if gen.description != "A test API" {
		t.Errorf("expected description 'A test API', got '%s'", gen.description)
	}
}

// ---------------------------------------------------------------------------
// AddServer
// ---------------------------------------------------------------------------

func TestAddServer(t *testing.T) {
	gen := NewOpenAPIGenerator("Test", "1.0.0", "")
	gen.AddServer("https://api.example.com")
	gen.AddServer("https://staging.example.com")
	if len(gen.servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(gen.servers))
	}
	if gen.servers[0] != "https://api.example.com" {
		t.Errorf("expected first server 'https://api.example.com', got '%s'", gen.servers[0])
	}
}

// ---------------------------------------------------------------------------
// Generate
// ---------------------------------------------------------------------------

func TestGenerate_BasicSpec(t *testing.T) {
	gen := NewOpenAPIGenerator("Test API", "1.0.0", "A test")
	gen.AddServer("https://api.example.com")

	endpoints := []types.Endpoint{
		{
			Method:      "GET",
			Path:        "/api/users",
			Description: "List users",
			Tags:        []string{"users"},
			Parameters: []types.Parameter{
				{Name: "page", In: "query", Type: "integer", Required: false},
			},
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if spec.OpenAPI != "3.0.3" {
		t.Errorf("expected openapi '3.0.3', got '%s'", spec.OpenAPI)
	}
	if spec.Info.Title != "Test API" {
		t.Errorf("expected title 'Test API', got '%s'", spec.Info.Title)
	}
	if spec.Info.Version != "1.0.0" {
		t.Errorf("expected version '1.0.0', got '%s'", spec.Info.Version)
	}
	if len(spec.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(spec.Servers))
	}
	if spec.Servers[0].URL != "https://api.example.com" {
		t.Errorf("expected server URL, got '%s'", spec.Servers[0].URL)
	}

	pathItem, ok := spec.Paths["/api/users"]
	if !ok {
		t.Fatal("expected path /api/users not found")
	}
	if pathItem.Get == nil {
		t.Fatal("expected GET operation, got nil")
	}
	if pathItem.Get.Summary != "List users" {
		t.Errorf("expected summary 'List users', got '%s'", pathItem.Get.Summary)
	}
	if len(pathItem.Get.Parameters) != 1 {
		t.Fatalf("expected 1 parameter, got %d", len(pathItem.Get.Parameters))
	}
	if pathItem.Get.Parameters[0].Name != "page" {
		t.Errorf("expected param 'page', got '%s'", pathItem.Get.Parameters[0].Name)
	}
	if pathItem.Get.Parameters[0].Schema.Type != "integer" {
		t.Errorf("expected schema type 'integer', got '%s'", pathItem.Get.Parameters[0].Schema.Type)
	}
}

func TestGenerate_MultipleMethodsOnSamePath(t *testing.T) {
	gen := NewOpenAPIGenerator("Test", "1.0.0", "")

	endpoints := []types.Endpoint{
		{Method: "GET", Path: "/api/users", Description: "List users", Tags: []string{"users"}},
		{Method: "POST", Path: "/api/users", Description: "Create user", Tags: []string{"users"},
			Body: &types.RequestBody{
				ContentType: "application/json",
				Required:    true,
				Fields: []types.BodyField{
					{Name: "name", Type: "string", Required: true},
				},
			},
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	pathItem := spec.Paths["/api/users"]
	if pathItem.Get == nil {
		t.Error("expected GET operation")
	}
	if pathItem.Post == nil {
		t.Error("expected POST operation")
	}
	if pathItem.Post.RequestBody == nil {
		t.Error("expected POST to have request body")
	}
}

func TestGenerate_ServersFromEndpoints(t *testing.T) {
	gen := NewOpenAPIGenerator("Test", "1.0.0", "")
	// No explicit servers; should infer from endpoint BaseURL.
	endpoints := []types.Endpoint{
		{Method: "GET", Path: "/api/test", BaseURL: "https://inferred.example.com", Tags: []string{"test"}},
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if len(spec.Servers) == 0 {
		t.Error("expected at least 1 server inferred from endpoints")
	}
	if spec.Servers[0].URL != "https://inferred.example.com" {
		t.Errorf("expected inferred server URL, got '%s'", spec.Servers[0].URL)
	}
}

func TestGenerate_SecuritySchemes(t *testing.T) {
	gen := NewOpenAPIGenerator("Test", "1.0.0", "")
	endpoints := []types.Endpoint{
		{
			Method: "GET", Path: "/api/secure", Tags: []string{"secure"},
			Parameters: []types.Parameter{
				{Name: "Authorization", In: "header", Type: "string", Required: true},
			},
		},
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if spec.Components == nil || spec.Components.SecuritySchemes == nil {
		t.Fatal("expected security schemes")
	}
	bearer, ok := spec.Components.SecuritySchemes["bearerAuth"]
	if !ok {
		t.Fatal("expected bearerAuth security scheme")
	}
	if bearer.Type != "http" || bearer.Scheme != "bearer" {
		t.Errorf("expected http/bearer scheme, got %s/%s", bearer.Type, bearer.Scheme)
	}
}

func TestGenerate_ApiKeySecurity(t *testing.T) {
	gen := NewOpenAPIGenerator("Test", "1.0.0", "")
	endpoints := []types.Endpoint{
		{
			Method: "GET", Path: "/api/data", Tags: []string{"data"},
			Parameters: []types.Parameter{
				{Name: "X-API-Key", In: "header", Type: "string", Required: true},
			},
		},
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if spec.Components == nil || spec.Components.SecuritySchemes == nil {
		t.Fatal("expected security schemes")
	}
	apiKey, ok := spec.Components.SecuritySchemes["apiKey"]
	if !ok {
		t.Fatal("expected apiKey security scheme")
	}
	if apiKey.Type != "apiKey" {
		t.Errorf("expected type 'apiKey', got '%s'", apiKey.Type)
	}
}

func TestGenerate_NoSecurity(t *testing.T) {
	gen := NewOpenAPIGenerator("Test", "1.0.0", "")
	endpoints := []types.Endpoint{
		{Method: "GET", Path: "/api/public", Tags: []string{"public"}},
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if spec.Components != nil && spec.Components.SecuritySchemes != nil {
		t.Error("expected no security schemes for public endpoints")
	}
}

func TestGenerate_Tags(t *testing.T) {
	gen := NewOpenAPIGenerator("Test", "1.0.0", "")
	endpoints := []types.Endpoint{
		{Method: "GET", Path: "/api/users", Tags: []string{"users"}},
		{Method: "GET", Path: "/api/orders", Tags: []string{"orders"}},
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if len(spec.Tags) != 2 {
		t.Fatalf("expected 2 tags, got %d", len(spec.Tags))
	}
	// Tags should be sorted
	if spec.Tags[0].Name != "orders" || spec.Tags[1].Name != "users" {
		t.Errorf("expected sorted tags [orders, users], got [%s, %s]", spec.Tags[0].Name, spec.Tags[1].Name)
	}
}

func TestGenerate_AllHTTPMethods(t *testing.T) {
	gen := NewOpenAPIGenerator("Test", "1.0.0", "")
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
	var endpoints []types.Endpoint
	for _, m := range methods {
		endpoints = append(endpoints, types.Endpoint{
			Method: m, Path: "/api/resource", Tags: []string{"test"},
		})
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	pathItem := spec.Paths["/api/resource"]
	if pathItem.Get == nil {
		t.Error("expected GET operation")
	}
	if pathItem.Post == nil {
		t.Error("expected POST operation")
	}
	if pathItem.Put == nil {
		t.Error("expected PUT operation")
	}
	if pathItem.Patch == nil {
		t.Error("expected PATCH operation")
	}
	if pathItem.Delete == nil {
		t.Error("expected DELETE operation")
	}
	if pathItem.Options == nil {
		t.Error("expected OPTIONS operation")
	}
	if pathItem.Head == nil {
		t.Error("expected HEAD operation")
	}
}

func TestGenerate_Responses(t *testing.T) {
	gen := NewOpenAPIGenerator("Test", "1.0.0", "")
	endpoints := []types.Endpoint{
		{Method: "GET", Path: "/api/test", Tags: []string{"test"}},
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	op := spec.Paths["/api/test"].Get
	if op == nil {
		t.Fatal("expected GET operation")
	}
	expectedCodes := []string{"200", "400", "401", "404", "500"}
	for _, code := range expectedCodes {
		if _, ok := op.Responses[code]; !ok {
			t.Errorf("expected response code %s", code)
		}
	}
}

// ---------------------------------------------------------------------------
// ToJSON
// ---------------------------------------------------------------------------

func TestToJSON(t *testing.T) {
	gen := NewOpenAPIGenerator("JSON Test", "1.0.0", "")
	endpoints := []types.Endpoint{
		{Method: "GET", Path: "/api/items", Tags: []string{"items"},
			Parameters: []types.Parameter{
				{Name: "id", In: "path", Type: "integer", Required: true},
			}},
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	jsonBytes, err := spec.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Check key fields exist
	if parsed["openapi"] != "3.0.3" {
		t.Errorf("expected openapi '3.0.3' in JSON")
	}
	info, ok := parsed["info"].(map[string]interface{})
	if !ok {
		t.Fatal("expected 'info' object in JSON")
	}
	if info["title"] != "JSON Test" {
		t.Errorf("expected title 'JSON Test' in JSON, got '%v'", info["title"])
	}
	if _, ok := parsed["paths"]; !ok {
		t.Error("expected 'paths' in JSON")
	}
}

// ---------------------------------------------------------------------------
// ToYAML
// ---------------------------------------------------------------------------

func TestToYAML(t *testing.T) {
	gen := NewOpenAPIGenerator("YAML Test", "1.0.0", "")
	endpoints := []types.Endpoint{
		{Method: "GET", Path: "/api/items", Tags: []string{"items"}},
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	yamlStr, err := spec.ToYAML()
	if err != nil {
		t.Fatalf("ToYAML failed: %v", err)
	}

	if yamlStr == "" {
		t.Error("expected non-empty YAML output")
	}
	// The YAML output should contain key fields
	if !strings.Contains(yamlStr, "openapi") {
		t.Error("expected 'openapi' in YAML output")
	}
	if !strings.Contains(yamlStr, "YAML Test") {
		t.Error("expected title in YAML output")
	}
	if !strings.Contains(yamlStr, "/api/items") {
		t.Error("expected path in YAML output")
	}
}

// ---------------------------------------------------------------------------
// End-to-end: Infer + Generate
// ---------------------------------------------------------------------------

func TestEndToEnd_InferAndGenerate(t *testing.T) {
	// Infer endpoints from traffic
	si := NewSchemaInferrer(InferenceSettings{})
	si.AddRequests([]CapturedRequest{
		{Method: "GET", URL: "https://api.example.com/api/users/1", Path: "/api/users/1"},
		{Method: "GET", URL: "https://api.example.com/api/users/2", Path: "/api/users/2"},
		{Method: "POST", URL: "https://api.example.com/api/users", Path: "/api/users",
			Body: `{"name":"alice","age":30}`, ContentType: "application/json"},
		{Method: "POST", URL: "https://api.example.com/api/users", Path: "/api/users",
			Body: `{"name":"bob","age":25}`, ContentType: "application/json"},
	})

	endpoints, err := si.Infer()
	if err != nil {
		t.Fatalf("Infer failed: %v", err)
	}
	if len(endpoints) == 0 {
		t.Fatal("expected inferred endpoints")
	}

	// Generate OpenAPI spec
	gen := NewOpenAPIGenerator("E2E Test", "1.0.0", "End-to-end test")
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Verify spec is serializable
	jsonBytes, err := spec.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	if len(jsonBytes) == 0 {
		t.Error("expected non-empty JSON")
	}

	// Verify paths exist
	if len(spec.Paths) == 0 {
		t.Error("expected paths in spec")
	}

	// Verify servers were inferred
	if len(spec.Servers) == 0 {
		t.Error("expected servers inferred from endpoints")
	}
}

// ---------------------------------------------------------------------------
// Helper: contains
// ---------------------------------------------------------------------------

func TestContains(t *testing.T) {
	if !contains([]string{"a", "b", "c"}, "b") {
		t.Error("expected contains to return true for 'b'")
	}
	if contains([]string{"a", "b", "c"}, "d") {
		t.Error("expected contains to return false for 'd'")
	}
	if contains([]string{}, "a") {
		t.Error("expected contains to return false for empty slice")
	}
}

// ---------------------------------------------------------------------------
// Helper: getFirstExample
// ---------------------------------------------------------------------------

func TestGetFirstExample(t *testing.T) {
	if getFirstExample([]string{"x", "y"}) != "x" {
		t.Error("expected first example 'x'")
	}
	if getFirstExample([]string{}) != "" {
		t.Error("expected empty string for empty slice")
	}
}

// ---------------------------------------------------------------------------
// Type conversion helpers
// ---------------------------------------------------------------------------

func TestTypeToOpenAPI(t *testing.T) {
	gen := NewOpenAPIGenerator("", "", "")
	tests := map[string]string{
		"int":     "integer",
		"integer": "integer",
		"int32":   "integer",
		"int64":   "integer",
		"float":   "number",
		"double":  "number",
		"number":  "number",
		"bool":    "boolean",
		"boolean": "boolean",
		"array":   "array",
		"list":    "array",
		"object":  "object",
		"map":     "object",
		"string":  "string",
		"other":   "string",
	}
	for input, expected := range tests {
		result := gen.typeToOpenAPI(input)
		if result != expected {
			t.Errorf("typeToOpenAPI(%s): expected '%s', got '%s'", input, expected, result)
		}
	}
}

func TestFormatForType(t *testing.T) {
	gen := NewOpenAPIGenerator("", "", "")
	tests := map[string]string{
		"int32":     "int32",
		"int64":     "int64",
		"float":     "float",
		"double":    "double",
		"date":      "date",
		"datetime":  "date-time",
		"date-time": "date-time",
		"email":     "email",
		"uuid":      "uuid",
		"uri":       "uri",
		"url":       "uri",
		"string":    "",
		"integer":   "",
	}
	for input, expected := range tests {
		result := gen.formatForType(input)
		if result != expected {
			t.Errorf("formatForType(%s): expected '%s', got '%s'", input, expected, result)
		}
	}
}

// ---------------------------------------------------------------------------
// Body fields with no body (GET/DELETE skip body inference)
// ---------------------------------------------------------------------------

func TestInfer_GETSkipsBodyInference(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{})
	si.AddRequests([]CapturedRequest{
		{Method: "GET", URL: "https://api.example.com/api/test", Path: "/api/test",
			Body: `{"should":"be_ignored"}`},
	})

	endpoints, err := si.Infer()
	if err != nil {
		t.Fatalf("Infer failed: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
	if endpoints[0].Body != nil {
		t.Error("expected no body for GET endpoint")
	}
}

// ---------------------------------------------------------------------------
// MinConfidence filtering
// ---------------------------------------------------------------------------

func TestInfer_MinConfidenceFiltering(t *testing.T) {
	si := NewSchemaInferrer(InferenceSettings{MinConfidence: 0.9})

	// Add 10 requests: only 3 have the "rare" query param
	for i := 0; i < 10; i++ {
		q := map[string]string{"common": "yes"}
		if i < 3 {
			q["rare"] = "value"
		}
		si.AddRequest(CapturedRequest{
			Method: "GET",
			URL:    "https://api.example.com/api/test",
			Path:   "/api/test",
			Query:  q,
		})
	}

	endpoints, err := si.Infer()
	if err != nil {
		t.Fatalf("Infer failed: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}

	// "common" param is present in 100% of requests (confidence 1.0 >= 0.9), should be included
	// "rare" param is present in 30% of requests (confidence 0.3 < 0.9), may be included but with low confidence
	// The query parameter inference uses the cluster confidence, not minConfidence for filtering
	// But body param inference does filter by minConfidence
	foundCommon := false
	for _, p := range endpoints[0].Parameters {
		if p.In == "query" && p.Name == "common" {
			foundCommon = true
		}
	}
	if !foundCommon {
		t.Error("expected 'common' query parameter to be present")
	}
}
