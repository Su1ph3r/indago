package parser

import (
	"fmt"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/su1ph3r/indago/pkg/types"
)

// OpenAPIParser parses OpenAPI/Swagger specifications
type OpenAPIParser struct {
	filePath string
	baseURL  string
}

// NewOpenAPIParser creates a new OpenAPI parser
func NewOpenAPIParser(filePath, baseURL string) (*OpenAPIParser, error) {
	return &OpenAPIParser{
		filePath: filePath,
		baseURL:  baseURL,
	}, nil
}

// Type returns the input type
func (p *OpenAPIParser) Type() types.InputType {
	return types.InputTypeOpenAPI
}

// Parse parses the OpenAPI specification
func (p *OpenAPIParser) Parse() ([]types.Endpoint, error) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(p.filePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseFailed, err)
	}

	// Determine base URL
	baseURL := p.baseURL
	if baseURL == "" && len(doc.Servers) > 0 {
		baseURL = doc.Servers[0].URL
	}

	var endpoints []types.Endpoint

	for path, pathItem := range doc.Paths.Map() {
		operations := map[string]*openapi3.Operation{
			"GET":     pathItem.Get,
			"POST":    pathItem.Post,
			"PUT":     pathItem.Put,
			"PATCH":   pathItem.Patch,
			"DELETE":  pathItem.Delete,
			"HEAD":    pathItem.Head,
			"OPTIONS": pathItem.Options,
		}

		for method, op := range operations {
			if op == nil {
				continue
			}

			endpoint := p.parseOperation(method, path, baseURL, op, pathItem.Parameters)
			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints, nil
}

// parseOperation converts an OpenAPI operation to an Endpoint
func (p *OpenAPIParser) parseOperation(method, path, baseURL string, op *openapi3.Operation, pathParams openapi3.Parameters) types.Endpoint {
	endpoint := types.Endpoint{
		Method:      method,
		Path:        NormalizePath(path),
		BaseURL:     strings.TrimSuffix(baseURL, "/"),
		Headers:     make(map[string]string),
		Description: op.Description,
		Tags:        op.Tags,
		OperationID: op.OperationID,
	}

	if op.Summary != "" && endpoint.Description == "" {
		endpoint.Description = op.Summary
	}

	// Parse path-level parameters first
	for _, paramRef := range pathParams {
		if param := paramRef.Value; param != nil {
			endpoint.Parameters = append(endpoint.Parameters, p.parseParameter(param))
		}
	}

	// Parse operation-level parameters
	for _, paramRef := range op.Parameters {
		if param := paramRef.Value; param != nil {
			endpoint.Parameters = append(endpoint.Parameters, p.parseParameter(param))
		}
	}

	// Parse request body
	if op.RequestBody != nil && op.RequestBody.Value != nil {
		endpoint.Body = p.parseRequestBody(op.RequestBody.Value)
	}

	// Parse security requirements
	if op.Security != nil && len(*op.Security) > 0 {
		endpoint.Auth = p.parseSecurityRequirements(*op.Security)
	}

	return endpoint
}

// parseParameter converts an OpenAPI parameter
func (p *OpenAPIParser) parseParameter(param *openapi3.Parameter) types.Parameter {
	tp := types.Parameter{
		Name:        param.Name,
		In:          param.In,
		Required:    param.Required,
		Description: param.Description,
	}

	if param.Schema != nil && param.Schema.Value != nil {
		schema := param.Schema.Value
		tp.Type = schema.Type.Slice()[0]
		tp.Format = schema.Format
		tp.Pattern = schema.Pattern

		if schema.Enum != nil {
			for _, e := range schema.Enum {
				if str, ok := e.(string); ok {
					tp.Enum = append(tp.Enum, str)
				}
			}
		}

		if schema.Example != nil {
			tp.Example = schema.Example
		}

		if schema.Default != nil {
			tp.Default = schema.Default
		}

		if schema.Min != nil {
			tp.Minimum = schema.Min
		}

		if schema.Max != nil {
			tp.Maximum = schema.Max
		}
	}

	if param.Example != nil {
		tp.Example = param.Example
	}

	return tp
}

// parseRequestBody converts an OpenAPI request body
func (p *OpenAPIParser) parseRequestBody(body *openapi3.RequestBody) *types.RequestBody {
	rb := &types.RequestBody{
		Required: body.Required,
	}

	// Prefer JSON content type
	contentTypes := []string{"application/json", "application/x-www-form-urlencoded", "multipart/form-data"}

	for _, ct := range contentTypes {
		if content, ok := body.Content[ct]; ok {
			rb.ContentType = ct

			if content.Schema != nil && content.Schema.Value != nil {
				rb.Schema = schemaToMap(content.Schema.Value)
				rb.Fields = p.extractBodyFields(content.Schema.Value, "")
			}

			if content.Example != nil {
				rb.Example = content.Example
			}

			break
		}
	}

	// If no preferred content type found, take the first one
	if rb.ContentType == "" {
		for ct, content := range body.Content {
			rb.ContentType = ct
			if content.Schema != nil && content.Schema.Value != nil {
				rb.Schema = schemaToMap(content.Schema.Value)
				rb.Fields = p.extractBodyFields(content.Schema.Value, "")
			}
			break
		}
	}

	return rb
}

// extractBodyFields extracts fields from a schema
func (p *OpenAPIParser) extractBodyFields(schema *openapi3.Schema, prefix string) []types.BodyField {
	var fields []types.BodyField

	if schema.Properties == nil {
		return fields
	}

	required := make(map[string]bool)
	for _, r := range schema.Required {
		required[r] = true
	}

	for name, propRef := range schema.Properties {
		prop := propRef.Value
		if prop == nil {
			continue
		}

		field := types.BodyField{
			Name:        name,
			Type:        prop.Type.Slice()[0],
			Required:    required[name],
			Description: prop.Description,
			Example:     prop.Example,
		}

		// Handle nested objects
		if prop.Type.Slice()[0] == "object" && prop.Properties != nil {
			field.Nested = p.extractBodyFields(prop, name+".")
		}

		fields = append(fields, field)
	}

	return fields
}

// parseSecurityRequirements parses security requirements
func (p *OpenAPIParser) parseSecurityRequirements(security openapi3.SecurityRequirements) *types.AuthConfig {
	if len(security) == 0 {
		return nil
	}

	// Just note that auth is required, the specific type will be determined later
	return &types.AuthConfig{
		Type: "required",
	}
}

// schemaToMap converts a schema to a generic map
func schemaToMap(schema *openapi3.Schema) map[string]interface{} {
	result := make(map[string]interface{})

	result["type"] = schema.Type
	if schema.Format != "" {
		result["format"] = schema.Format
	}
	if schema.Description != "" {
		result["description"] = schema.Description
	}

	if schema.Properties != nil {
		props := make(map[string]interface{})
		for name, propRef := range schema.Properties {
			if propRef.Value != nil {
				props[name] = schemaToMap(propRef.Value)
			}
		}
		result["properties"] = props
	}

	if len(schema.Required) > 0 {
		result["required"] = schema.Required
	}

	return result
}
