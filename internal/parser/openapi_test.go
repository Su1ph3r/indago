package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestNewOpenAPIParser(t *testing.T) {
	p, err := NewOpenAPIParser("test.yaml", "https://api.example.com")
	if err != nil {
		t.Fatalf("NewOpenAPIParser failed: %v", err)
	}
	if p == nil {
		t.Fatal("NewOpenAPIParser returned nil")
	}
}

func TestOpenAPIParser_Type(t *testing.T) {
	p, _ := NewOpenAPIParser("test.yaml", "")
	if p.Type() != types.InputTypeOpenAPI {
		t.Errorf("Type() = %s, expected %s", p.Type(), types.InputTypeOpenAPI)
	}
}

func TestOpenAPIParser_Parse(t *testing.T) {
	// Find testdata directory
	testdataPath := findTestdata(t)
	specPath := filepath.Join(testdataPath, "petstore.yaml")

	// Skip if file doesn't exist
	if _, err := os.Stat(specPath); os.IsNotExist(err) {
		t.Skip("testdata/petstore.yaml not found")
	}

	p, err := NewOpenAPIParser(specPath, "")
	if err != nil {
		t.Fatalf("NewOpenAPIParser failed: %v", err)
	}

	endpoints, err := p.Parse()
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(endpoints) == 0 {
		t.Error("expected endpoints, got none")
	}

	// Verify endpoint structure
	for _, ep := range endpoints {
		if ep.Method == "" {
			t.Error("endpoint method should not be empty")
		}
		if ep.Path == "" {
			t.Error("endpoint path should not be empty")
		}
	}

	// Check for specific endpoints
	foundPets := false
	foundPetById := false
	foundUsers := false

	for _, ep := range endpoints {
		if ep.Path == "/pets" && ep.Method == "GET" {
			foundPets = true
			// Verify parameters
			hasLimit := false
			hasSearch := false
			for _, p := range ep.Parameters {
				if p.Name == "limit" {
					hasLimit = true
				}
				if p.Name == "search" {
					hasSearch = true
				}
			}
			if !hasLimit {
				t.Error("GET /pets should have limit parameter")
			}
			if !hasSearch {
				t.Error("GET /pets should have search parameter")
			}
		}
		if ep.Path == "/pets/{petId}" && ep.Method == "GET" {
			foundPetById = true
			// Verify path parameter
			hasPathParam := false
			for _, p := range ep.Parameters {
				if p.Name == "petId" && p.In == "path" {
					hasPathParam = true
				}
			}
			if !hasPathParam {
				t.Error("GET /pets/{petId} should have petId path parameter")
			}
		}
		if ep.Path == "/users/{userId}/profile" {
			foundUsers = true
		}
	}

	if !foundPets {
		t.Error("expected GET /pets endpoint")
	}
	if !foundPetById {
		t.Error("expected GET /pets/{petId} endpoint")
	}
	if !foundUsers {
		t.Error("expected /users/{userId}/profile endpoint")
	}
}

func TestOpenAPIParser_Parse_WithBaseURL(t *testing.T) {
	testdataPath := findTestdata(t)
	specPath := filepath.Join(testdataPath, "petstore.yaml")

	if _, err := os.Stat(specPath); os.IsNotExist(err) {
		t.Skip("testdata/petstore.yaml not found")
	}

	customBaseURL := "https://custom.api.com/v2"
	p, _ := NewOpenAPIParser(specPath, customBaseURL)

	endpoints, err := p.Parse()
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Verify base URL is set correctly
	for _, ep := range endpoints {
		if ep.BaseURL != customBaseURL {
			t.Errorf("BaseURL = %s, expected %s", ep.BaseURL, customBaseURL)
		}
	}
}

func TestOpenAPIParser_ParseRequestBody(t *testing.T) {
	testdataPath := findTestdata(t)
	specPath := filepath.Join(testdataPath, "petstore.yaml")

	if _, err := os.Stat(specPath); os.IsNotExist(err) {
		t.Skip("testdata/petstore.yaml not found")
	}

	p, _ := NewOpenAPIParser(specPath, "")
	endpoints, _ := p.Parse()

	// Find POST /pets endpoint
	var createPetEndpoint *types.Endpoint
	for i := range endpoints {
		if endpoints[i].Path == "/pets" && endpoints[i].Method == "POST" {
			createPetEndpoint = &endpoints[i]
			break
		}
	}

	if createPetEndpoint == nil {
		t.Fatal("POST /pets endpoint not found")
	}

	if createPetEndpoint.Body == nil {
		t.Fatal("POST /pets should have request body")
	}

	if createPetEndpoint.Body.ContentType != "application/json" {
		t.Errorf("ContentType = %s, expected application/json", createPetEndpoint.Body.ContentType)
	}

	// Check body fields
	if len(createPetEndpoint.Body.Fields) == 0 {
		t.Error("expected body fields")
	}

	// Check for specific fields
	fieldNames := make(map[string]bool)
	for _, f := range createPetEndpoint.Body.Fields {
		fieldNames[f.Name] = true
	}

	expectedFields := []string{"name", "tag", "owner_id"}
	for _, expected := range expectedFields {
		if !fieldNames[expected] {
			t.Errorf("expected body field %s not found", expected)
		}
	}
}

func TestOpenAPIParser_InvalidFile(t *testing.T) {
	p, _ := NewOpenAPIParser("/nonexistent/file.yaml", "")

	_, err := p.Parse()
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// Helper function to find testdata directory
func findTestdata(t *testing.T) string {
	// Try relative paths from common test locations
	paths := []string{
		"../../testdata",
		"../testdata",
		"testdata",
		"../../../testdata",
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// Try to find from working directory
	wd, _ := os.Getwd()
	t.Logf("Working directory: %s", wd)

	return "../../testdata"
}
