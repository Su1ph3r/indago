package parser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// HARParser parses HAR (HTTP Archive) files
type HARParser struct {
	filePath string
	baseURL  string
}

// HAR represents a HAR file structure
type HAR struct {
	Log HARLog `json:"log"`
}

// HARLog represents the log section
type HARLog struct {
	Version string     `json:"version"`
	Creator HARCreator `json:"creator"`
	Entries []HAREntry `json:"entries"`
}

// HARCreator represents the creator
type HARCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// HAREntry represents a single request/response pair
type HAREntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Request         HARRequest  `json:"request"`
	Response        HARResponse `json:"response"`
}

// HARRequest represents a request
type HARRequest struct {
	Method      string          `json:"method"`
	URL         string          `json:"url"`
	HTTPVersion string          `json:"httpVersion"`
	Headers     []HARNameValue  `json:"headers"`
	QueryString []HARNameValue  `json:"queryString"`
	Cookies     []HARCookie     `json:"cookies"`
	PostData    *HARPostData    `json:"postData,omitempty"`
}

// HARResponse represents a response
type HARResponse struct {
	Status      int            `json:"status"`
	StatusText  string         `json:"statusText"`
	HTTPVersion string         `json:"httpVersion"`
	Headers     []HARNameValue `json:"headers"`
	Content     HARContent     `json:"content"`
}

// HARNameValue represents a name-value pair
type HARNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HARCookie represents a cookie
type HARCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path"`
	Domain   string `json:"domain"`
	HTTPOnly bool   `json:"httpOnly"`
	Secure   bool   `json:"secure"`
}

// HARPostData represents POST data
type HARPostData struct {
	MimeType string         `json:"mimeType"`
	Text     string         `json:"text"`
	Params   []HARNameValue `json:"params,omitempty"`
}

// HARContent represents response content
type HARContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
}

// NewHARParser creates a new HAR parser
func NewHARParser(filePath, baseURL string) (*HARParser, error) {
	return &HARParser{
		filePath: filePath,
		baseURL:  baseURL,
	}, nil
}

// Type returns the input type
func (p *HARParser) Type() types.InputType {
	return types.InputTypeHAR
}

// Parse parses the HAR file
func (p *HARParser) Parse() ([]types.Endpoint, error) {
	data, err := os.ReadFile(p.filePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseFailed, err)
	}

	var har HAR
	if err := json.Unmarshal(data, &har); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseFailed, err)
	}

	seen := make(map[string]bool)
	var endpoints []types.Endpoint

	for _, entry := range har.Log.Entries {
		endpoint := p.parseEntry(entry)

		// Deduplicate by method+path
		key := endpoint.Method + ":" + endpoint.BaseURL + endpoint.Path
		if seen[key] {
			continue
		}
		seen[key] = true

		endpoints = append(endpoints, endpoint)
	}

	return endpoints, nil
}

// parseEntry converts a HAR entry to an Endpoint
func (p *HARParser) parseEntry(entry HAREntry) types.Endpoint {
	req := entry.Request

	// Parse URL
	parsedURL, _ := url.Parse(req.URL)
	baseURL := p.baseURL
	path := "/"

	if parsedURL != nil {
		if baseURL == "" {
			baseURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		}
		path = parsedURL.Path
	}

	endpoint := types.Endpoint{
		Method:  NormalizeMethod(req.Method),
		Path:    NormalizePath(path),
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		Headers: make(map[string]string),
	}

	// Parse headers (skip some internal ones)
	skipHeaders := map[string]bool{
		"host":              true,
		"content-length":    true,
		"accept-encoding":   true,
		"connection":        true,
		"sec-ch-ua":         true,
		"sec-ch-ua-mobile":  true,
		"sec-ch-ua-platform": true,
		"sec-fetch-site":    true,
		"sec-fetch-mode":    true,
		"sec-fetch-dest":    true,
	}

	for _, h := range req.Headers {
		name := strings.ToLower(h.Name)
		if skipHeaders[name] {
			continue
		}

		// Check for auth headers
		if name == "authorization" {
			endpoint.Auth = p.parseAuthHeader(h.Value)
		} else if name == "cookie" {
			// Skip cookies in headers, use cookies array
			continue
		} else {
			endpoint.Headers[h.Name] = h.Value
		}
	}

	// Parse query parameters
	for _, q := range req.QueryString {
		endpoint.Parameters = append(endpoint.Parameters, types.Parameter{
			Name:    q.Name,
			In:      "query",
			Type:    inferType(q.Value),
			Example: q.Value,
		})
	}

	// Parse POST data
	if req.PostData != nil {
		endpoint.Body = p.parsePostData(req.PostData)
	}

	return endpoint
}

// parsePostData converts HAR POST data
func (p *HARParser) parsePostData(postData *HARPostData) *types.RequestBody {
	rb := &types.RequestBody{
		ContentType: postData.MimeType,
	}

	// Handle URL-encoded params
	if len(postData.Params) > 0 {
		for _, param := range postData.Params {
			rb.Fields = append(rb.Fields, types.BodyField{
				Name:    param.Name,
				Type:    inferType(param.Value),
				Example: param.Value,
			})
		}
		return rb
	}

	// Handle raw text body
	if postData.Text != "" {
		rb.Example = postData.Text

		// Try to parse as JSON
		if strings.Contains(postData.MimeType, "json") {
			var jsonBody map[string]interface{}
			if err := json.Unmarshal([]byte(postData.Text), &jsonBody); err == nil {
				rb.Fields = extractFieldsFromJSON(jsonBody, "")
			}
		}
	}

	return rb
}

// parseAuthHeader parses an Authorization header
func (p *HARParser) parseAuthHeader(value string) *types.AuthConfig {
	auth := &types.AuthConfig{}

	parts := strings.SplitN(value, " ", 2)
	if len(parts) == 2 {
		authType := strings.ToLower(parts[0])
		switch authType {
		case "bearer":
			auth.Type = "bearer"
			auth.Value = parts[1]
		case "basic":
			auth.Type = "basic"
			auth.Value = parts[1]
		default:
			auth.Type = authType
			auth.Value = parts[1]
		}
	} else {
		auth.Type = "custom"
		auth.Value = value
	}

	return auth
}

// inferType attempts to infer the type of a string value
func inferType(value string) string {
	// Check if it looks like a number
	if _, err := json.Number(value).Int64(); err == nil {
		return "integer"
	}
	if _, err := json.Number(value).Float64(); err == nil {
		return "number"
	}

	// Check for boolean
	lower := strings.ToLower(value)
	if lower == "true" || lower == "false" {
		return "boolean"
	}

	// Check for UUID
	if len(value) == 36 && strings.Count(value, "-") == 4 {
		return "uuid"
	}

	return "string"
}
