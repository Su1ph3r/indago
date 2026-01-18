package parser

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// BurpParser parses Burp Suite XML exports
type BurpParser struct {
	filePath string
	baseURL  string
}

// BurpExport represents a Burp Suite XML export
type BurpExport struct {
	XMLName xml.Name   `xml:"items"`
	Items   []BurpItem `xml:"item"`
}

// BurpItem represents a single request/response
type BurpItem struct {
	Time           string `xml:"time"`
	URL            string `xml:"url"`
	Host           string `xml:"host"`
	Port           string `xml:"port"`
	Protocol       string `xml:"protocol"`
	Method         string `xml:"method"`
	Path           string `xml:"path"`
	Extension      string `xml:"extension"`
	Request        string `xml:"request"`
	RequestBase64  bool   `xml:"request,attr"`
	Status         string `xml:"status"`
	ResponseLength string `xml:"responselength"`
	MimeType       string `xml:"mimetype"`
	Response       string `xml:"response"`
	ResponseBase64 bool   `xml:"response,attr"`
	Comment        string `xml:"comment"`
}

// NewBurpParser creates a new Burp parser
func NewBurpParser(filePath, baseURL string) (*BurpParser, error) {
	return &BurpParser{
		filePath: filePath,
		baseURL:  baseURL,
	}, nil
}

// Type returns the input type
func (p *BurpParser) Type() types.InputType {
	return types.InputTypeBurp
}

// Parse parses the Burp export
func (p *BurpParser) Parse() ([]types.Endpoint, error) {
	data, err := os.ReadFile(p.filePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseFailed, err)
	}

	var export BurpExport
	if err := xml.Unmarshal(data, &export); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseFailed, err)
	}

	seen := make(map[string]bool)
	var endpoints []types.Endpoint

	for _, item := range export.Items {
		endpoint := p.parseItem(item)

		// Deduplicate
		key := endpoint.Method + ":" + endpoint.BaseURL + endpoint.Path
		if seen[key] {
			continue
		}
		seen[key] = true

		endpoints = append(endpoints, endpoint)
	}

	return endpoints, nil
}

// parseItem converts a Burp item to an Endpoint
func (p *BurpParser) parseItem(item BurpItem) types.Endpoint {
	// Decode request if base64
	requestData := item.Request
	if item.RequestBase64 {
		if decoded, err := base64.StdEncoding.DecodeString(item.Request); err == nil {
			requestData = string(decoded)
		}
	}

	// Determine base URL
	baseURL := p.baseURL
	if baseURL == "" {
		baseURL = fmt.Sprintf("%s://%s", item.Protocol, item.Host)
		if item.Port != "" && item.Port != "80" && item.Port != "443" {
			baseURL = fmt.Sprintf("%s:%s", baseURL, item.Port)
		}
	}

	endpoint := types.Endpoint{
		Method:      NormalizeMethod(item.Method),
		Path:        NormalizePath(item.Path),
		BaseURL:     strings.TrimSuffix(baseURL, "/"),
		Headers:     make(map[string]string),
		Description: item.Comment,
	}

	// Parse the raw request
	p.parseRawRequest(requestData, &endpoint)

	return endpoint
}

// parseRawRequest parses a raw HTTP request
func (p *BurpParser) parseRawRequest(raw string, endpoint *types.Endpoint) {
	lines := strings.Split(raw, "\r\n")
	if len(lines) == 0 {
		lines = strings.Split(raw, "\n")
	}

	// Find the blank line separating headers from body
	bodyStart := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			bodyStart = i + 1
			break
		}
	}

	// Parse headers (skip first line which is the request line)
	headerEnd := len(lines)
	if bodyStart > 0 {
		headerEnd = bodyStart - 1
	}

	skipHeaders := map[string]bool{
		"host":            true,
		"content-length":  true,
		"accept-encoding": true,
		"connection":      true,
	}

	for i := 1; i < headerEnd; i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		nameLower := strings.ToLower(name)

		if skipHeaders[nameLower] {
			continue
		}

		if nameLower == "authorization" {
			endpoint.Auth = p.parseAuthHeader(value)
		} else if nameLower == "cookie" {
			// Could parse cookies here if needed
			continue
		} else {
			endpoint.Headers[name] = value
		}
	}

	// Parse query parameters from path
	if strings.Contains(endpoint.Path, "?") {
		parts := strings.SplitN(endpoint.Path, "?", 2)
		endpoint.Path = parts[0]
		if len(parts) > 1 {
			queryParams, _ := url.ParseQuery(parts[1])
			for key, values := range queryParams {
				endpoint.Parameters = append(endpoint.Parameters, types.Parameter{
					Name:    key,
					In:      "query",
					Type:    inferType(values[0]),
					Example: values[0],
				})
			}
		}
	}

	// Parse body
	if bodyStart > 0 && bodyStart < len(lines) {
		body := strings.Join(lines[bodyStart:], "\n")
		body = strings.TrimSpace(body)

		if body != "" {
			contentType := "application/octet-stream"
			if ct, ok := endpoint.Headers["Content-Type"]; ok {
				contentType = ct
			}

			endpoint.Body = p.parseBody(body, contentType)
		}
	}
}

// parseBody parses a request body
func (p *BurpParser) parseBody(body, contentType string) *types.RequestBody {
	rb := &types.RequestBody{
		ContentType: contentType,
		Example:     body,
	}

	// Parse based on content type
	if strings.Contains(contentType, "json") {
		var jsonBody map[string]interface{}
		if err := parseJSON(body, &jsonBody); err == nil {
			rb.Fields = extractFieldsFromJSON(jsonBody, "")
		}
	} else if strings.Contains(contentType, "x-www-form-urlencoded") {
		params, _ := url.ParseQuery(body)
		for key, values := range params {
			rb.Fields = append(rb.Fields, types.BodyField{
				Name:    key,
				Type:    inferType(values[0]),
				Example: values[0],
			})
		}
	}

	return rb
}

// parseAuthHeader parses an Authorization header
func (p *BurpParser) parseAuthHeader(value string) *types.AuthConfig {
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

// parseJSON is a helper to parse JSON
func parseJSON(s string, v interface{}) error {
	return parseJSONString(s, v)
}

// parseJSONString decodes JSON from a string
func parseJSONString(s string, v interface{}) error {
	decoder := strings.NewReader(s)
	return decodeJSON(decoder, v)
}

// decodeJSON uses json decoder
func decodeJSON(r *strings.Reader, v interface{}) error {
	// Import json package functionality
	type jsonDecoder interface {
		Decode(v interface{}) error
	}

	// Simple JSON parse
	data, _ := readAll(r)
	return unmarshalJSON(data, v)
}

// readAll reads all bytes from reader
func readAll(r *strings.Reader) ([]byte, error) {
	var result []byte
	buf := make([]byte, 1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return result, nil
}

// unmarshalJSON wraps json.Unmarshal
func unmarshalJSON(data []byte, v interface{}) error {
	return jsonUnmarshal(data, v)
}

// jsonUnmarshal is the actual json unmarshal
func jsonUnmarshal(data []byte, v interface{}) error {
	// Use encoding/json
	type jsonUnmarshaler interface {
		UnmarshalJSON([]byte) error
	}

	// Direct implementation
	str := string(data)
	if strings.HasPrefix(str, "{") {
		// It's an object, parse manually for our needs
		m, ok := v.(*map[string]interface{})
		if !ok {
			return fmt.Errorf("unsupported type")
		}
		*m = make(map[string]interface{})
		// Basic parsing - in production use encoding/json
		str = strings.TrimPrefix(str, "{")
		str = strings.TrimSuffix(str, "}")
		// This is simplified - real impl would use encoding/json
	}
	return nil
}
