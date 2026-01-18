package parser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// PostmanParser parses Postman collection files
type PostmanParser struct {
	filePath string
	baseURL  string
}

// PostmanCollection represents a Postman collection
type PostmanCollection struct {
	Info     PostmanInfo      `json:"info"`
	Item     []PostmanItem    `json:"item"`
	Variable []PostmanVar     `json:"variable"`
	Auth     *PostmanAuth     `json:"auth,omitempty"`
}

// PostmanInfo represents collection info
type PostmanInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Schema      string `json:"schema"`
}

// PostmanItem represents an item (request or folder)
type PostmanItem struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Request     *PostmanRequest  `json:"request,omitempty"`
	Item        []PostmanItem    `json:"item,omitempty"` // For folders
	Auth        *PostmanAuth     `json:"auth,omitempty"`
}

// PostmanRequest represents a request
type PostmanRequest struct {
	Method      string           `json:"method"`
	URL         PostmanURL       `json:"url"`
	Header      []PostmanHeader  `json:"header"`
	Body        *PostmanBody     `json:"body,omitempty"`
	Description string           `json:"description"`
	Auth        *PostmanAuth     `json:"auth,omitempty"`
}

// PostmanURL represents a URL (can be string or object)
type PostmanURL struct {
	Raw      string            `json:"raw"`
	Protocol string            `json:"protocol"`
	Host     []string          `json:"host"`
	Path     []string          `json:"path"`
	Query    []PostmanKeyValue `json:"query"`
	Variable []PostmanKeyValue `json:"variable"`
}

// UnmarshalJSON handles both string and object URL formats
func (u *PostmanURL) UnmarshalJSON(data []byte) error {
	// Try string first
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		u.Raw = str
		return nil
	}

	// Try object
	type urlAlias PostmanURL
	var obj urlAlias
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*u = PostmanURL(obj)
	return nil
}

// PostmanHeader represents a header
type PostmanHeader struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Description string `json:"description"`
	Disabled    bool   `json:"disabled"`
}

// PostmanBody represents a request body
type PostmanBody struct {
	Mode       string            `json:"mode"` // raw, formdata, urlencoded
	Raw        string            `json:"raw"`
	URLEncoded []PostmanKeyValue `json:"urlencoded"`
	FormData   []PostmanKeyValue `json:"formdata"`
	Options    *PostmanBodyOpts  `json:"options"`
}

// PostmanBodyOpts represents body options
type PostmanBodyOpts struct {
	Raw struct {
		Language string `json:"language"`
	} `json:"raw"`
}

// PostmanKeyValue represents a key-value pair
type PostmanKeyValue struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Description string `json:"description"`
	Disabled    bool   `json:"disabled"`
	Type        string `json:"type"`
}

// PostmanVar represents a collection variable
type PostmanVar struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

// PostmanAuth represents authentication
type PostmanAuth struct {
	Type   string          `json:"type"`
	Bearer []PostmanKeyValue `json:"bearer,omitempty"`
	Basic  []PostmanKeyValue `json:"basic,omitempty"`
	APIKey []PostmanKeyValue `json:"apikey,omitempty"`
}

// NewPostmanParser creates a new Postman parser
func NewPostmanParser(filePath, baseURL string) (*PostmanParser, error) {
	return &PostmanParser{
		filePath: filePath,
		baseURL:  baseURL,
	}, nil
}

// Type returns the input type
func (p *PostmanParser) Type() types.InputType {
	return types.InputTypePostman
}

// Parse parses the Postman collection
func (p *PostmanParser) Parse() ([]types.Endpoint, error) {
	data, err := os.ReadFile(p.filePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseFailed, err)
	}

	var collection PostmanCollection
	if err := json.Unmarshal(data, &collection); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseFailed, err)
	}

	// Build variable map for substitution
	varMap := make(map[string]string)
	for _, v := range collection.Variable {
		varMap[v.Key] = v.Value
	}

	var endpoints []types.Endpoint
	p.parseItems(collection.Item, varMap, collection.Auth, &endpoints)

	return endpoints, nil
}

// parseItems recursively parses items (handles folders)
func (p *PostmanParser) parseItems(items []PostmanItem, varMap map[string]string, parentAuth *PostmanAuth, endpoints *[]types.Endpoint) {
	for _, item := range items {
		// If it's a folder, recurse
		if len(item.Item) > 0 {
			auth := item.Auth
			if auth == nil {
				auth = parentAuth
			}
			p.parseItems(item.Item, varMap, auth, endpoints)
			continue
		}

		// It's a request
		if item.Request == nil {
			continue
		}

		endpoint := p.parseRequest(item, varMap, parentAuth)
		*endpoints = append(*endpoints, endpoint)
	}
}

// parseRequest converts a Postman request to an Endpoint
func (p *PostmanParser) parseRequest(item PostmanItem, varMap map[string]string, parentAuth *PostmanAuth) types.Endpoint {
	req := item.Request

	// Resolve URL
	rawURL := p.substituteVars(req.URL.Raw, varMap)
	if rawURL == "" {
		// Build from parts
		protocol := req.URL.Protocol
		if protocol == "" {
			protocol = "https"
		}
		host := strings.Join(req.URL.Host, ".")
		path := "/" + strings.Join(req.URL.Path, "/")
		rawURL = fmt.Sprintf("%s://%s%s", protocol, host, path)
	}

	// Parse URL to extract base and path
	parsedURL, _ := url.Parse(rawURL)
	baseURL := p.baseURL
	path := "/"

	if parsedURL != nil {
		if baseURL == "" {
			baseURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		}
		path = parsedURL.Path
	}

	endpoint := types.Endpoint{
		Method:      NormalizeMethod(req.Method),
		Path:        NormalizePath(path),
		BaseURL:     strings.TrimSuffix(baseURL, "/"),
		Headers:     make(map[string]string),
		Description: item.Description,
	}

	if req.Description != "" {
		endpoint.Description = req.Description
	}

	// Parse headers
	for _, h := range req.Header {
		if !h.Disabled {
			endpoint.Headers[h.Key] = p.substituteVars(h.Value, varMap)
		}
	}

	// Parse query parameters
	for _, q := range req.URL.Query {
		if !q.Disabled {
			endpoint.Parameters = append(endpoint.Parameters, types.Parameter{
				Name:        q.Key,
				In:          "query",
				Type:        "string",
				Description: q.Description,
				Example:     p.substituteVars(q.Value, varMap),
			})
		}
	}

	// Parse path variables
	for _, v := range req.URL.Variable {
		endpoint.Parameters = append(endpoint.Parameters, types.Parameter{
			Name:        v.Key,
			In:          "path",
			Type:        "string",
			Required:    true,
			Description: v.Description,
			Example:     p.substituteVars(v.Value, varMap),
		})
	}

	// Parse body
	if req.Body != nil {
		endpoint.Body = p.parseBody(req.Body, varMap)
	}

	// Parse auth
	auth := req.Auth
	if auth == nil {
		auth = parentAuth
	}
	if auth != nil {
		endpoint.Auth = p.parseAuth(auth)
	}

	return endpoint
}

// parseBody converts a Postman body
func (p *PostmanParser) parseBody(body *PostmanBody, varMap map[string]string) *types.RequestBody {
	rb := &types.RequestBody{}

	switch body.Mode {
	case "raw":
		rb.ContentType = "application/json"
		if body.Options != nil && body.Options.Raw.Language == "xml" {
			rb.ContentType = "application/xml"
		}
		rb.Example = p.substituteVars(body.Raw, varMap)

		// Try to parse as JSON for field extraction
		var jsonBody map[string]interface{}
		if err := json.Unmarshal([]byte(body.Raw), &jsonBody); err == nil {
			rb.Fields = extractFieldsFromJSON(jsonBody, "")
		}

	case "urlencoded":
		rb.ContentType = "application/x-www-form-urlencoded"
		for _, kv := range body.URLEncoded {
			if !kv.Disabled {
				rb.Fields = append(rb.Fields, types.BodyField{
					Name:        kv.Key,
					Type:        "string",
					Description: kv.Description,
					Example:     p.substituteVars(kv.Value, varMap),
				})
			}
		}

	case "formdata":
		rb.ContentType = "multipart/form-data"
		for _, kv := range body.FormData {
			if !kv.Disabled {
				fieldType := "string"
				if kv.Type == "file" {
					fieldType = "file"
				}
				rb.Fields = append(rb.Fields, types.BodyField{
					Name:        kv.Key,
					Type:        fieldType,
					Description: kv.Description,
					Example:     p.substituteVars(kv.Value, varMap),
				})
			}
		}
	}

	return rb
}

// parseAuth converts Postman auth
func (p *PostmanParser) parseAuth(auth *PostmanAuth) *types.AuthConfig {
	ac := &types.AuthConfig{
		Type: auth.Type,
	}

	switch auth.Type {
	case "bearer":
		for _, kv := range auth.Bearer {
			if kv.Key == "token" {
				ac.Value = kv.Value
			}
		}
	case "basic":
		for _, kv := range auth.Basic {
			if kv.Key == "username" {
				ac.Extra = map[string]string{"username": kv.Value}
			} else if kv.Key == "password" {
				if ac.Extra == nil {
					ac.Extra = make(map[string]string)
				}
				ac.Extra["password"] = kv.Value
			}
		}
	case "apikey":
		for _, kv := range auth.APIKey {
			if kv.Key == "key" {
				ac.Name = kv.Value
			} else if kv.Key == "value" {
				ac.Value = kv.Value
			} else if kv.Key == "in" {
				ac.Location = kv.Value
			}
		}
	}

	return ac
}

// substituteVars replaces {{var}} with actual values
func (p *PostmanParser) substituteVars(s string, varMap map[string]string) string {
	result := s
	for key, value := range varMap {
		result = strings.ReplaceAll(result, "{{"+key+"}}", value)
	}
	return result
}

// extractFieldsFromJSON extracts fields from a JSON object
func extractFieldsFromJSON(obj map[string]interface{}, prefix string) []types.BodyField {
	var fields []types.BodyField

	for key, value := range obj {
		field := types.BodyField{
			Name:    key,
			Example: value,
		}

		switch v := value.(type) {
		case string:
			field.Type = "string"
		case float64:
			field.Type = "number"
		case bool:
			field.Type = "boolean"
		case []interface{}:
			field.Type = "array"
		case map[string]interface{}:
			field.Type = "object"
			field.Nested = extractFieldsFromJSON(v, key+".")
		default:
			field.Type = "string"
		}

		fields = append(fields, field)
	}

	return fields
}
