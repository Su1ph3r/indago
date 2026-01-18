package parser

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// RawParser parses raw URLs and endpoint definitions
type RawParser struct {
	urls    []string
	baseURL string
}

// NewRawParser creates a new raw URL parser
func NewRawParser(baseURL string, urls []string) *RawParser {
	return &RawParser{
		baseURL: baseURL,
		urls:    urls,
	}
}

// NewRawParserFromFile creates a parser from a file containing URLs
func NewRawParserFromFile(filePath, baseURL string) (*RawParser, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseFailed, err)
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseFailed, err)
	}

	return &RawParser{
		baseURL: baseURL,
		urls:    urls,
	}, nil
}

// Type returns the input type
func (p *RawParser) Type() types.InputType {
	return types.InputTypeRaw
}

// Parse parses the raw URLs
func (p *RawParser) Parse() ([]types.Endpoint, error) {
	var endpoints []types.Endpoint

	for _, rawURL := range p.urls {
		endpoint, err := p.parseURL(rawURL)
		if err != nil {
			continue // Skip invalid URLs
		}
		endpoints = append(endpoints, endpoint)
	}

	return endpoints, nil
}

// parseURL parses a single URL or endpoint definition
func (p *RawParser) parseURL(raw string) (types.Endpoint, error) {
	// Check for method prefix like "GET /users" or "POST https://api.example.com/users"
	method := "GET"
	urlPart := raw

	parts := strings.SplitN(raw, " ", 2)
	if len(parts) == 2 {
		maybeMethod := strings.ToUpper(parts[0])
		if isHTTPMethod(maybeMethod) {
			method = maybeMethod
			urlPart = parts[1]
		}
	}

	// If it doesn't start with http, prepend base URL
	if !strings.HasPrefix(urlPart, "http://") && !strings.HasPrefix(urlPart, "https://") {
		if p.baseURL != "" {
			urlPart = strings.TrimSuffix(p.baseURL, "/") + "/" + strings.TrimPrefix(urlPart, "/")
		} else {
			return types.Endpoint{}, fmt.Errorf("no base URL for relative path: %s", urlPart)
		}
	}

	// Parse the URL
	parsedURL, err := url.Parse(urlPart)
	if err != nil {
		return types.Endpoint{}, err
	}

	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}

	endpoint := types.Endpoint{
		Method:  method,
		Path:    NormalizePath(path),
		BaseURL: baseURL,
		Headers: make(map[string]string),
	}

	// Parse query parameters
	for key, values := range parsedURL.Query() {
		endpoint.Parameters = append(endpoint.Parameters, types.Parameter{
			Name:    key,
			In:      "query",
			Type:    inferType(values[0]),
			Example: values[0],
		})
	}

	// Detect path parameters (like {id} or :id)
	pathParts := strings.Split(path, "/")
	for _, part := range pathParts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			paramName := strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")
			endpoint.Parameters = append(endpoint.Parameters, types.Parameter{
				Name:     paramName,
				In:       "path",
				Type:     "string",
				Required: true,
			})
		} else if strings.HasPrefix(part, ":") {
			paramName := strings.TrimPrefix(part, ":")
			endpoint.Parameters = append(endpoint.Parameters, types.Parameter{
				Name:     paramName,
				In:       "path",
				Type:     "string",
				Required: true,
			})
		}
	}

	return endpoint, nil
}

// isHTTPMethod checks if a string is a valid HTTP method
func isHTTPMethod(s string) bool {
	methods := map[string]bool{
		"GET":     true,
		"POST":    true,
		"PUT":     true,
		"PATCH":   true,
		"DELETE":  true,
		"HEAD":    true,
		"OPTIONS": true,
		"TRACE":   true,
		"CONNECT": true,
	}
	return methods[s]
}

// ParseEndpointString parses a single endpoint string
func ParseEndpointString(s, baseURL string) (types.Endpoint, error) {
	parser := NewRawParser(baseURL, []string{s})
	endpoints, err := parser.Parse()
	if err != nil {
		return types.Endpoint{}, err
	}
	if len(endpoints) == 0 {
		return types.Endpoint{}, fmt.Errorf("failed to parse endpoint: %s", s)
	}
	return endpoints[0], nil
}

// ParseEndpointList parses a comma-separated list of endpoints
func ParseEndpointList(list, baseURL string) ([]types.Endpoint, error) {
	parts := strings.Split(list, ",")
	var urls []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			urls = append(urls, p)
		}
	}

	parser := NewRawParser(baseURL, urls)
	return parser.Parse()
}
