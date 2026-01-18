// Package parser provides parsers for various API specification formats
package parser

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// Parser defines the interface for API specification parsers
type Parser interface {
	// Parse parses the input and returns a slice of endpoints
	Parse() ([]types.Endpoint, error)

	// Type returns the input type
	Type() types.InputType
}

// Errors
var (
	ErrUnsupportedFormat = errors.New("unsupported file format")
	ErrInvalidInput      = errors.New("invalid input")
	ErrFileNotFound      = errors.New("file not found")
	ErrParseFailed       = errors.New("failed to parse input")
)

// NewParser creates a parser based on the input file
func NewParser(filePath string, baseURL string) (Parser, error) {
	if filePath == "" {
		return nil, fmt.Errorf("%w: empty file path", ErrInvalidInput)
	}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: %s", ErrFileNotFound, filePath)
	}

	inputType := DetectInputType(filePath)

	switch inputType {
	case types.InputTypeOpenAPI:
		return NewOpenAPIParser(filePath, baseURL)
	case types.InputTypePostman:
		return NewPostmanParser(filePath, baseURL)
	case types.InputTypeHAR:
		return NewHARParser(filePath, baseURL)
	case types.InputTypeBurp:
		return NewBurpParser(filePath, baseURL)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedFormat, filePath)
	}
}

// DetectInputType detects the input type from file extension and content
func DetectInputType(filePath string) types.InputType {
	ext := strings.ToLower(filepath.Ext(filePath))

	// First check extension
	switch ext {
	case ".har":
		return types.InputTypeHAR
	case ".xml":
		// Could be Burp export, check content
		if isBurpExport(filePath) {
			return types.InputTypeBurp
		}
		return types.InputTypeUnknown
	}

	// For JSON/YAML files, need to check content
	if ext == ".json" || ext == ".yaml" || ext == ".yml" {
		content, err := os.ReadFile(filePath)
		if err != nil {
			return types.InputTypeUnknown
		}

		// Check for OpenAPI markers
		contentStr := string(content)
		if strings.Contains(contentStr, "openapi") || strings.Contains(contentStr, "swagger") {
			return types.InputTypeOpenAPI
		}

		// Check for Postman collection markers
		if strings.Contains(contentStr, "\"info\"") && strings.Contains(contentStr, "\"item\"") {
			// Try to parse as Postman
			var pm struct {
				Info struct {
					Schema string `json:"schema"`
				} `json:"info"`
			}
			if err := json.Unmarshal(content, &pm); err == nil {
				if strings.Contains(pm.Info.Schema, "postman") {
					return types.InputTypePostman
				}
			}
		}

		// Check for HAR
		if strings.Contains(contentStr, "\"log\"") && strings.Contains(contentStr, "\"entries\"") {
			return types.InputTypeHAR
		}

		// Default to OpenAPI for yaml/yml
		if ext == ".yaml" || ext == ".yml" {
			return types.InputTypeOpenAPI
		}
	}

	return types.InputTypeUnknown
}

// isBurpExport checks if a file is a Burp Suite export
func isBurpExport(filePath string) bool {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}
	contentStr := string(content)
	return strings.Contains(contentStr, "<items") && strings.Contains(contentStr, "<item>")
}

// ParseMultiple parses multiple input files and combines endpoints
func ParseMultiple(files []string, baseURL string) ([]types.Endpoint, error) {
	var allEndpoints []types.Endpoint

	for _, file := range files {
		parser, err := NewParser(file, baseURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create parser for %s: %w", file, err)
		}

		endpoints, err := parser.Parse()
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", file, err)
		}

		allEndpoints = append(allEndpoints, endpoints...)
	}

	return deduplicateEndpoints(allEndpoints), nil
}

// deduplicateEndpoints removes duplicate endpoints
func deduplicateEndpoints(endpoints []types.Endpoint) []types.Endpoint {
	seen := make(map[string]bool)
	var unique []types.Endpoint

	for _, ep := range endpoints {
		key := ep.Method + ":" + ep.BaseURL + ep.Path
		if !seen[key] {
			seen[key] = true
			unique = append(unique, ep)
		}
	}

	return unique
}

// NormalizeMethod normalizes HTTP method to uppercase
func NormalizeMethod(method string) string {
	return strings.ToUpper(strings.TrimSpace(method))
}

// NormalizePath normalizes a URL path
func NormalizePath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimSuffix(path, "/")
}
