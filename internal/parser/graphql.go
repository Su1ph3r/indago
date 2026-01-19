// Package parser provides parsers for various API specification formats
package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/su1ph3r/indago/pkg/types"
)

// GraphQLParser parses GraphQL schemas via introspection
type GraphQLParser struct {
	endpoint    string
	baseURL     string
	headers     map[string]string
	client      *http.Client
	schema      *GraphQLSchema
}

// GraphQLSchema represents a GraphQL schema
type GraphQLSchema struct {
	Types        []GraphQLType       `json:"types"`
	QueryType    *GraphQLTypeRef     `json:"queryType"`
	MutationType *GraphQLTypeRef     `json:"mutationType"`
	Subscriptions *GraphQLTypeRef    `json:"subscriptionType"`
	Directives   []GraphQLDirective  `json:"directives"`
}

// GraphQLType represents a GraphQL type
type GraphQLType struct {
	Kind          string             `json:"kind"`
	Name          string             `json:"name"`
	Description   string             `json:"description"`
	Fields        []GraphQLField     `json:"fields"`
	InputFields   []GraphQLInputField `json:"inputFields"`
	Interfaces    []GraphQLTypeRef   `json:"interfaces"`
	EnumValues    []GraphQLEnumValue `json:"enumValues"`
	PossibleTypes []GraphQLTypeRef   `json:"possibleTypes"`
}

// GraphQLField represents a field in a GraphQL type
type GraphQLField struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Args        []GraphQLArg     `json:"args"`
	Type        GraphQLTypeRef   `json:"type"`
	IsDeprecated bool            `json:"isDeprecated"`
}

// GraphQLInputField represents an input field
type GraphQLInputField struct {
	Name         string         `json:"name"`
	Description  string         `json:"description"`
	Type         GraphQLTypeRef `json:"type"`
	DefaultValue string         `json:"defaultValue"`
}

// GraphQLArg represents a field argument
type GraphQLArg struct {
	Name         string         `json:"name"`
	Description  string         `json:"description"`
	Type         GraphQLTypeRef `json:"type"`
	DefaultValue string         `json:"defaultValue"`
}

// GraphQLTypeRef represents a reference to a type
type GraphQLTypeRef struct {
	Kind   string         `json:"kind"`
	Name   string         `json:"name"`
	OfType *GraphQLTypeRef `json:"ofType"`
}

// GraphQLEnumValue represents an enum value
type GraphQLEnumValue struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	IsDeprecated bool   `json:"isDeprecated"`
}

// GraphQLDirective represents a directive
type GraphQLDirective struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Locations   []string     `json:"locations"`
	Args        []GraphQLArg `json:"args"`
}

// GraphQLOperation represents a GraphQL operation
type GraphQLOperation struct {
	Name        string
	Type        string // query, mutation, subscription
	Arguments   []GraphQLArg
	ReturnType  string
	Description string
	Depth       int
}

// IntrospectionResponse represents the introspection query response
type IntrospectionResponse struct {
	Data struct {
		Schema GraphQLSchema `json:"__schema"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// NewGraphQLParser creates a new GraphQL parser
func NewGraphQLParser(endpoint string, baseURL string) (*GraphQLParser, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("GraphQL endpoint URL is required")
	}

	return &GraphQLParser{
		endpoint: endpoint,
		baseURL:  baseURL,
		headers:  make(map[string]string),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// SetHeaders sets custom headers for requests
func (p *GraphQLParser) SetHeaders(headers map[string]string) {
	p.headers = headers
}

// Type returns the input type
func (p *GraphQLParser) Type() types.InputType {
	return types.InputTypeGraphQL
}

// Parse performs introspection and returns endpoints
func (p *GraphQLParser) Parse() ([]types.Endpoint, error) {
	// Run introspection query
	schema, err := p.introspect()
	if err != nil {
		return nil, fmt.Errorf("introspection failed: %w", err)
	}

	p.schema = schema

	// Convert to endpoints
	endpoints := p.schemaToEndpoints(schema)

	return endpoints, nil
}

// introspect runs the introspection query
func (p *GraphQLParser) introspect() (*GraphQLSchema, error) {
	query := getIntrospectionQuery()

	body, err := json.Marshal(map[string]string{
		"query": query,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", p.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range p.headers {
		req.Header.Set(k, v)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var introspection IntrospectionResponse
	if err := json.Unmarshal(respBody, &introspection); err != nil {
		return nil, fmt.Errorf("failed to parse introspection response: %w", err)
	}

	if len(introspection.Errors) > 0 {
		return nil, fmt.Errorf("introspection errors: %s", introspection.Errors[0].Message)
	}

	return &introspection.Data.Schema, nil
}

// schemaToEndpoints converts a GraphQL schema to endpoints
func (p *GraphQLParser) schemaToEndpoints(schema *GraphQLSchema) []types.Endpoint {
	var endpoints []types.Endpoint

	// Find query and mutation types
	var queryType, mutationType *GraphQLType
	for i := range schema.Types {
		if schema.QueryType != nil && schema.Types[i].Name == schema.QueryType.Name {
			queryType = &schema.Types[i]
		}
		if schema.MutationType != nil && schema.Types[i].Name == schema.MutationType.Name {
			mutationType = &schema.Types[i]
		}
	}

	// Convert queries to endpoints
	if queryType != nil {
		for _, field := range queryType.Fields {
			ep := p.fieldToEndpoint(field, "query")
			endpoints = append(endpoints, ep)
		}
	}

	// Convert mutations to endpoints
	if mutationType != nil {
		for _, field := range mutationType.Fields {
			ep := p.fieldToEndpoint(field, "mutation")
			endpoints = append(endpoints, ep)
		}
	}

	return endpoints
}

// fieldToEndpoint converts a GraphQL field to an endpoint
func (p *GraphQLParser) fieldToEndpoint(field GraphQLField, opType string) types.Endpoint {
	method := "POST" // GraphQL always uses POST

	// Build parameters from arguments
	var params []types.Parameter
	for _, arg := range field.Args {
		param := types.Parameter{
			Name:        arg.Name,
			In:          "body",
			Type:        resolveTypeName(arg.Type),
			Required:    isNonNull(arg.Type),
			Description: arg.Description,
		}
		if arg.DefaultValue != "" {
			param.Default = arg.DefaultValue
		}
		params = append(params, param)
	}

	return types.Endpoint{
		Method:      method,
		Path:        p.endpoint,
		BaseURL:     p.baseURL,
		Parameters:  params,
		Description: field.Description,
		OperationID: opType + "_" + field.Name,
		Tags:        []string{"graphql", opType},
		Body: &types.RequestBody{
			ContentType: "application/json",
			Required:    true,
			Fields:      p.argsToBodyFields(field.Args),
		},
		BusinessContext: fmt.Sprintf("GraphQL %s: %s", opType, field.Name),
		SuggestedAttacks: p.getSuggestedAttacks(field, opType),
	}
}

// argsToBodyFields converts GraphQL args to body fields
func (p *GraphQLParser) argsToBodyFields(args []GraphQLArg) []types.BodyField {
	var fields []types.BodyField

	for _, arg := range args {
		field := types.BodyField{
			Name:        arg.Name,
			Type:        resolveTypeName(arg.Type),
			Required:    isNonNull(arg.Type),
			Description: arg.Description,
		}
		fields = append(fields, field)
	}

	return fields
}

// getSuggestedAttacks generates suggested attacks for a GraphQL field
func (p *GraphQLParser) getSuggestedAttacks(field GraphQLField, opType string) []types.AttackVector {
	var attacks []types.AttackVector

	// Check for IDOR indicators
	for _, arg := range field.Args {
		nameLower := strings.ToLower(arg.Name)
		if strings.Contains(nameLower, "id") || strings.Contains(nameLower, "uuid") {
			attacks = append(attacks, types.AttackVector{
				Type:        types.AttackIDOR,
				Category:    "authorization",
				Priority:    "high",
				Rationale:   "GraphQL field accepts ID parameter",
				TargetParam: types.FlexibleString(arg.Name),
			})
		}
	}

	// Mutations are good targets for injection
	if opType == "mutation" {
		attacks = append(attacks, types.AttackVector{
			Type:     types.AttackSQLi,
			Category: "injection",
			Priority: "medium",
			Rationale: "Mutations may write to database",
		})
	}

	// GraphQL-specific attacks
	attacks = append(attacks, types.AttackVector{
		Type:     types.AttackGraphQLDepth,
		Category: "dos",
		Priority: "medium",
		Rationale: "Test for query depth limits",
	})

	attacks = append(attacks, types.AttackVector{
		Type:     types.AttackGraphQLBatch,
		Category: "dos",
		Priority: "medium",
		Rationale: "Test for batching limits",
	})

	return attacks
}

// GetOperations returns all GraphQL operations
func (p *GraphQLParser) GetOperations() []GraphQLOperation {
	if p.schema == nil {
		return nil
	}

	var ops []GraphQLOperation

	// Find query type
	for _, t := range p.schema.Types {
		if p.schema.QueryType != nil && t.Name == p.schema.QueryType.Name {
			for _, field := range t.Fields {
				ops = append(ops, GraphQLOperation{
					Name:        field.Name,
					Type:        "query",
					Arguments:   field.Args,
					ReturnType:  resolveTypeName(field.Type),
					Description: field.Description,
				})
			}
		}
		if p.schema.MutationType != nil && t.Name == p.schema.MutationType.Name {
			for _, field := range t.Fields {
				ops = append(ops, GraphQLOperation{
					Name:        field.Name,
					Type:        "mutation",
					Arguments:   field.Args,
					ReturnType:  resolveTypeName(field.Type),
					Description: field.Description,
				})
			}
		}
	}

	return ops
}

// GetSchema returns the parsed schema
func (p *GraphQLParser) GetSchema() *GraphQLSchema {
	return p.schema
}

// Helper functions

func resolveTypeName(ref GraphQLTypeRef) string {
	if ref.Name != "" {
		return ref.Name
	}
	if ref.OfType != nil {
		inner := resolveTypeName(*ref.OfType)
		switch ref.Kind {
		case "NON_NULL":
			return inner + "!"
		case "LIST":
			return "[" + inner + "]"
		}
		return inner
	}
	return ref.Kind
}

func isNonNull(ref GraphQLTypeRef) bool {
	return ref.Kind == "NON_NULL"
}

func getIntrospectionQuery() string {
	return `
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}`
}
