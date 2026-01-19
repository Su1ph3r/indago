// Package inference provides API schema inference from traffic
package inference

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// OpenAPIGenerator generates OpenAPI specs from inferred endpoints
type OpenAPIGenerator struct {
	title       string
	version     string
	description string
	servers     []string
}

// OpenAPISpec represents an OpenAPI 3.0 specification
type OpenAPISpec struct {
	OpenAPI    string                `json:"openapi"`
	Info       OpenAPIInfo           `json:"info"`
	Servers    []OpenAPIServer       `json:"servers,omitempty"`
	Paths      map[string]PathItem   `json:"paths"`
	Components *OpenAPIComponents    `json:"components,omitempty"`
	Tags       []OpenAPITag          `json:"tags,omitempty"`
}

// OpenAPIInfo represents the info section
type OpenAPIInfo struct {
	Title       string `json:"title"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
}

// OpenAPIServer represents a server
type OpenAPIServer struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}

// PathItem represents a path item
type PathItem struct {
	Get     *Operation `json:"get,omitempty"`
	Post    *Operation `json:"post,omitempty"`
	Put     *Operation `json:"put,omitempty"`
	Patch   *Operation `json:"patch,omitempty"`
	Delete  *Operation `json:"delete,omitempty"`
	Options *Operation `json:"options,omitempty"`
	Head    *Operation `json:"head,omitempty"`
}

// Operation represents an operation
type Operation struct {
	Tags        []string              `json:"tags,omitempty"`
	Summary     string                `json:"summary,omitempty"`
	Description string                `json:"description,omitempty"`
	OperationID string                `json:"operationId,omitempty"`
	Parameters  []OpenAPIParameter    `json:"parameters,omitempty"`
	RequestBody *OpenAPIRequestBody   `json:"requestBody,omitempty"`
	Responses   map[string]Response   `json:"responses"`
	Security    []map[string][]string `json:"security,omitempty"`
}

// OpenAPIParameter represents a parameter
type OpenAPIParameter struct {
	Name        string       `json:"name"`
	In          string       `json:"in"`
	Description string       `json:"description,omitempty"`
	Required    bool         `json:"required"`
	Schema      SchemaObject `json:"schema"`
	Example     interface{}  `json:"example,omitempty"`
}

// OpenAPIRequestBody represents a request body
type OpenAPIRequestBody struct {
	Description string                    `json:"description,omitempty"`
	Required    bool                      `json:"required"`
	Content     map[string]MediaTypeObject `json:"content"`
}

// MediaTypeObject represents a media type
type MediaTypeObject struct {
	Schema  SchemaObject `json:"schema"`
	Example interface{}  `json:"example,omitempty"`
}

// SchemaObject represents a schema
type SchemaObject struct {
	Type       string                  `json:"type,omitempty"`
	Format     string                  `json:"format,omitempty"`
	Properties map[string]SchemaObject `json:"properties,omitempty"`
	Items      *SchemaObject           `json:"items,omitempty"`
	Required   []string                `json:"required,omitempty"`
	Example    interface{}             `json:"example,omitempty"`
	Enum       []string                `json:"enum,omitempty"`
}

// Response represents a response
type Response struct {
	Description string                    `json:"description"`
	Content     map[string]MediaTypeObject `json:"content,omitempty"`
}

// OpenAPIComponents represents components
type OpenAPIComponents struct {
	Schemas         map[string]SchemaObject      `json:"schemas,omitempty"`
	SecuritySchemes map[string]SecurityScheme    `json:"securitySchemes,omitempty"`
}

// SecurityScheme represents a security scheme
type SecurityScheme struct {
	Type         string `json:"type"`
	Scheme       string `json:"scheme,omitempty"`
	BearerFormat string `json:"bearerFormat,omitempty"`
	Name         string `json:"name,omitempty"`
	In           string `json:"in,omitempty"`
}

// OpenAPITag represents a tag
type OpenAPITag struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// NewOpenAPIGenerator creates a new OpenAPI generator
func NewOpenAPIGenerator(title, version, description string) *OpenAPIGenerator {
	if title == "" {
		title = "Inferred API"
	}
	if version == "" {
		version = "1.0.0"
	}

	return &OpenAPIGenerator{
		title:       title,
		version:     version,
		description: description,
		servers:     make([]string, 0),
	}
}

// AddServer adds a server URL
func (g *OpenAPIGenerator) AddServer(url string) {
	g.servers = append(g.servers, url)
}

// Generate generates an OpenAPI spec from endpoints
func (g *OpenAPIGenerator) Generate(endpoints []types.Endpoint) (*OpenAPISpec, error) {
	spec := &OpenAPISpec{
		OpenAPI: "3.0.3",
		Info: OpenAPIInfo{
			Title:       g.title,
			Version:     g.version,
			Description: g.description,
		},
		Paths: make(map[string]PathItem),
		Components: &OpenAPIComponents{
			Schemas:         make(map[string]SchemaObject),
			SecuritySchemes: make(map[string]SecurityScheme),
		},
	}

	// Add servers
	for _, server := range g.servers {
		spec.Servers = append(spec.Servers, OpenAPIServer{
			URL:         server,
			Description: "Inferred server",
		})
	}

	// Extract servers from endpoints if not provided
	if len(spec.Servers) == 0 {
		serverSet := make(map[string]bool)
		for _, ep := range endpoints {
			if ep.BaseURL != "" && !serverSet[ep.BaseURL] {
				serverSet[ep.BaseURL] = true
				spec.Servers = append(spec.Servers, OpenAPIServer{
					URL: ep.BaseURL,
				})
			}
		}
	}

	// Collect tags
	tagSet := make(map[string]bool)

	// Convert endpoints to paths
	for _, ep := range endpoints {
		pathItem := g.getOrCreatePathItem(spec, ep.Path)
		operation := g.endpointToOperation(ep)

		// Add to path item
		switch ep.Method {
		case "GET":
			pathItem.Get = operation
		case "POST":
			pathItem.Post = operation
		case "PUT":
			pathItem.Put = operation
		case "PATCH":
			pathItem.Patch = operation
		case "DELETE":
			pathItem.Delete = operation
		case "OPTIONS":
			pathItem.Options = operation
		case "HEAD":
			pathItem.Head = operation
		}

		spec.Paths[ep.Path] = *pathItem

		// Collect tags
		for _, tag := range ep.Tags {
			tagSet[tag] = true
		}
	}

	// Add tags
	for tag := range tagSet {
		spec.Tags = append(spec.Tags, OpenAPITag{Name: tag})
	}

	// Sort tags
	sort.Slice(spec.Tags, func(i, j int) bool {
		return spec.Tags[i].Name < spec.Tags[j].Name
	})

	// Add security schemes
	g.inferSecuritySchemes(endpoints, spec)

	return spec, nil
}

// getOrCreatePathItem gets or creates a path item
func (g *OpenAPIGenerator) getOrCreatePathItem(spec *OpenAPISpec, path string) *PathItem {
	if item, exists := spec.Paths[path]; exists {
		return &item
	}
	return &PathItem{}
}

// endpointToOperation converts an endpoint to an operation
func (g *OpenAPIGenerator) endpointToOperation(ep types.Endpoint) *Operation {
	operation := &Operation{
		Tags:        ep.Tags,
		Summary:     ep.Description,
		Description: ep.BusinessContext,
		OperationID: g.generateOperationID(ep),
		Responses: map[string]Response{
			"200": {
				Description: "Successful response",
				Content: map[string]MediaTypeObject{
					"application/json": {
						Schema: SchemaObject{Type: "object"},
					},
				},
			},
			"400": {Description: "Bad request"},
			"401": {Description: "Unauthorized"},
			"404": {Description: "Not found"},
			"500": {Description: "Internal server error"},
		},
	}

	// Convert parameters
	for _, param := range ep.Parameters {
		if param.In == "body" {
			continue // Body params handled separately
		}

		openAPIParam := OpenAPIParameter{
			Name:        param.Name,
			In:          param.In,
			Description: param.Description,
			Required:    param.Required,
			Schema: SchemaObject{
				Type:   g.typeToOpenAPI(param.Type),
				Format: g.formatForType(param.Type),
			},
		}

		if param.Example != nil {
			openAPIParam.Example = param.Example
		}

		operation.Parameters = append(operation.Parameters, openAPIParam)
	}

	// Convert request body
	if ep.Body != nil && len(ep.Body.Fields) > 0 {
		operation.RequestBody = g.bodyToRequestBody(ep.Body)
	}

	return operation
}

// bodyToRequestBody converts a RequestBody to OpenAPI format
func (g *OpenAPIGenerator) bodyToRequestBody(body *types.RequestBody) *OpenAPIRequestBody {
	properties := make(map[string]SchemaObject)
	var required []string

	for _, field := range body.Fields {
		schema := SchemaObject{
			Type:   g.typeToOpenAPI(field.Type),
			Format: g.formatForType(field.Type),
		}

		if field.Example != nil {
			schema.Example = field.Example
		}

		properties[field.Name] = schema

		if field.Required {
			required = append(required, field.Name)
		}
	}

	contentType := body.ContentType
	if contentType == "" {
		contentType = "application/json"
	}

	return &OpenAPIRequestBody{
		Required: body.Required,
		Content: map[string]MediaTypeObject{
			contentType: {
				Schema: SchemaObject{
					Type:       "object",
					Properties: properties,
					Required:   required,
				},
			},
		},
	}
}

// generateOperationID generates a unique operation ID
func (g *OpenAPIGenerator) generateOperationID(ep types.Endpoint) string {
	// Convert path to camelCase operation ID
	path := ep.Path
	path = strings.ReplaceAll(path, "{", "By")
	path = strings.ReplaceAll(path, "}", "")

	segments := strings.Split(path, "/")
	var parts []string
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		parts = append(parts, strings.Title(seg))
	}

	method := strings.ToLower(ep.Method)
	return method + strings.Join(parts, "")
}

// typeToOpenAPI converts internal type to OpenAPI type
func (g *OpenAPIGenerator) typeToOpenAPI(t string) string {
	switch strings.ToLower(t) {
	case "int", "integer", "int32", "int64":
		return "integer"
	case "float", "double", "number":
		return "number"
	case "bool", "boolean":
		return "boolean"
	case "array", "list":
		return "array"
	case "object", "map":
		return "object"
	default:
		return "string"
	}
}

// formatForType returns the format for a type
func (g *OpenAPIGenerator) formatForType(t string) string {
	switch strings.ToLower(t) {
	case "int32":
		return "int32"
	case "int64":
		return "int64"
	case "float":
		return "float"
	case "double":
		return "double"
	case "date":
		return "date"
	case "datetime", "date-time":
		return "date-time"
	case "email":
		return "email"
	case "uuid":
		return "uuid"
	case "uri", "url":
		return "uri"
	default:
		return ""
	}
}

// inferSecuritySchemes infers security schemes from endpoints
func (g *OpenAPIGenerator) inferSecuritySchemes(endpoints []types.Endpoint, spec *OpenAPISpec) {
	hasAuth := false

	for _, ep := range endpoints {
		for _, param := range ep.Parameters {
			if param.In == "header" {
				nameLower := strings.ToLower(param.Name)
				if nameLower == "authorization" {
					spec.Components.SecuritySchemes["bearerAuth"] = SecurityScheme{
						Type:         "http",
						Scheme:       "bearer",
						BearerFormat: "JWT",
					}
					hasAuth = true
				} else if strings.Contains(nameLower, "api-key") || strings.Contains(nameLower, "apikey") {
					spec.Components.SecuritySchemes["apiKey"] = SecurityScheme{
						Type: "apiKey",
						In:   "header",
						Name: param.Name,
					}
					hasAuth = true
				}
			}
		}
	}

	// If no auth detected, don't add security
	if !hasAuth {
		spec.Components.SecuritySchemes = nil
	}
}

// ToJSON serializes the spec to JSON
func (spec *OpenAPISpec) ToJSON() ([]byte, error) {
	return json.MarshalIndent(spec, "", "  ")
}

// ToYAML serializes the spec to YAML format
func (spec *OpenAPISpec) ToYAML() (string, error) {
	jsonBytes, err := spec.ToJSON()
	if err != nil {
		return "", err
	}

	// Simple JSON to YAML conversion
	// In production, use a proper YAML library
	var data interface{}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		return "", err
	}

	return toYAML(data, 0), nil
}

// toYAML converts a value to YAML format (simplified)
func toYAML(v interface{}, indent int) string {
	indentStr := strings.Repeat("  ", indent)

	switch val := v.(type) {
	case map[string]interface{}:
		if len(val) == 0 {
			return "{}"
		}
		var sb strings.Builder
		for k, v := range val {
			sb.WriteString(fmt.Sprintf("%s%s:", indentStr, k))
			child := toYAML(v, indent+1)
			if strings.HasPrefix(child, "\n") {
				sb.WriteString(child)
			} else {
				sb.WriteString(" " + child)
			}
			sb.WriteString("\n")
		}
		return "\n" + sb.String()
	case []interface{}:
		if len(val) == 0 {
			return "[]"
		}
		var sb strings.Builder
		sb.WriteString("\n")
		for _, item := range val {
			sb.WriteString(fmt.Sprintf("%s- %s\n", indentStr, toYAML(item, indent+1)))
		}
		return sb.String()
	case string:
		if strings.ContainsAny(val, ":\n#") {
			return fmt.Sprintf("\"%s\"", val)
		}
		return val
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%v", val)
	}
}
