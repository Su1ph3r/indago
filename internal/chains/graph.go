// Package chains provides multi-step attack chain functionality
package chains

import (
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// EndpointGraph represents relationships between endpoints
type EndpointGraph struct {
	nodes map[string]*EndpointNode
	edges []EndpointEdge
}

// EndpointNode represents an endpoint in the graph
type EndpointNode struct {
	Endpoint       types.Endpoint
	Key            string
	ResourceType   string   // user, order, product, etc.
	Operations     []string // create, read, update, delete
	Parameters     []string
	DependsOn      []string // endpoints this depends on
	Provides       []string // what this endpoint provides (IDs, tokens)
}

// EndpointEdge represents a relationship between endpoints
type EndpointEdge struct {
	From         string // source endpoint key
	To           string // target endpoint key
	Type         string // data_flow, auth_dependency, resource_lifecycle
	SharedData   []string
	Strength     float64 // 0.0 - 1.0
}

// EdgeType constants
const (
	EdgeTypeDataFlow         = "data_flow"
	EdgeTypeAuthDependency   = "auth_dependency"
	EdgeTypeResourceLifecycle = "resource_lifecycle"
	EdgeTypeIDOR             = "idor_potential"
	EdgeTypePrivilegeEsc     = "privilege_escalation"
)

// NewEndpointGraph creates a new endpoint graph
func NewEndpointGraph() *EndpointGraph {
	return &EndpointGraph{
		nodes: make(map[string]*EndpointNode),
		edges: make([]EndpointEdge, 0),
	}
}

// AddEndpoint adds an endpoint to the graph
func (g *EndpointGraph) AddEndpoint(endpoint types.Endpoint) {
	key := endpoint.Method + ":" + endpoint.Path

	node := &EndpointNode{
		Endpoint:     endpoint,
		Key:          key,
		ResourceType: inferResourceType(endpoint),
		Operations:   inferOperations(endpoint),
		Parameters:   extractParameterNames(endpoint),
		DependsOn:    make([]string, 0),
		Provides:     inferProvides(endpoint),
	}

	g.nodes[key] = node
}

// BuildRelationships analyzes endpoints and builds relationship edges
func (g *EndpointGraph) BuildRelationships() {
	for _, nodeA := range g.nodes {
		for _, nodeB := range g.nodes {
			if nodeA.Key == nodeB.Key {
				continue
			}

			// Check for data flow relationships
			if edge := g.checkDataFlow(nodeA, nodeB); edge != nil {
				g.edges = append(g.edges, *edge)
			}

			// Check for resource lifecycle relationships
			if edge := g.checkResourceLifecycle(nodeA, nodeB); edge != nil {
				g.edges = append(g.edges, *edge)
			}

			// Check for auth dependencies
			if edge := g.checkAuthDependency(nodeA, nodeB); edge != nil {
				g.edges = append(g.edges, *edge)
			}

			// Check for IDOR potential
			if edge := g.checkIDORPotential(nodeA, nodeB); edge != nil {
				g.edges = append(g.edges, *edge)
			}
		}
	}
}

// checkDataFlow checks if nodeA provides data that nodeB needs
func (g *EndpointGraph) checkDataFlow(nodeA, nodeB *EndpointNode) *EndpointEdge {
	sharedData := make([]string, 0)

	for _, provided := range nodeA.Provides {
		for _, needed := range nodeB.Parameters {
			if strings.EqualFold(provided, needed) {
				sharedData = append(sharedData, provided)
			}
		}
	}

	if len(sharedData) > 0 {
		return &EndpointEdge{
			From:       nodeA.Key,
			To:         nodeB.Key,
			Type:       EdgeTypeDataFlow,
			SharedData: sharedData,
			Strength:   float64(len(sharedData)) / float64(len(nodeB.Parameters)+1),
		}
	}

	return nil
}

// checkResourceLifecycle checks for CRUD relationships on same resource
func (g *EndpointGraph) checkResourceLifecycle(nodeA, nodeB *EndpointNode) *EndpointEdge {
	if nodeA.ResourceType != nodeB.ResourceType || nodeA.ResourceType == "" {
		return nil
	}

	// POST creates, others operate on created resource
	if containsOperation(nodeA.Operations, "create") && !containsOperation(nodeB.Operations, "create") {
		return &EndpointEdge{
			From:       nodeA.Key,
			To:         nodeB.Key,
			Type:       EdgeTypeResourceLifecycle,
			SharedData: []string{nodeA.ResourceType + "_id"},
			Strength:   0.8,
		}
	}

	return nil
}

// checkAuthDependency checks for authentication dependencies
func (g *EndpointGraph) checkAuthDependency(nodeA, nodeB *EndpointNode) *EndpointEdge {
	// Login/auth endpoints provide tokens
	authKeywords := []string{"login", "auth", "token", "session", "signin"}

	isAuthEndpoint := false
	pathLower := strings.ToLower(nodeA.Endpoint.Path)
	for _, kw := range authKeywords {
		if strings.Contains(pathLower, kw) {
			isAuthEndpoint = true
			break
		}
	}

	if isAuthEndpoint && nodeA.Endpoint.Method == "POST" {
		// Check if nodeB requires auth
		if requiresAuth(nodeB.Endpoint) {
			return &EndpointEdge{
				From:       nodeA.Key,
				To:         nodeB.Key,
				Type:       EdgeTypeAuthDependency,
				SharedData: []string{"token", "session"},
				Strength:   0.9,
			}
		}
	}

	return nil
}

// checkIDORPotential checks for IDOR vulnerability potential
func (g *EndpointGraph) checkIDORPotential(nodeA, nodeB *EndpointNode) *EndpointEdge {
	// Same resource type with different access patterns
	if nodeA.ResourceType != nodeB.ResourceType || nodeA.ResourceType == "" {
		return nil
	}

	// Different users accessing same resource type
	hasIDParam := func(ep types.Endpoint) bool {
		for _, p := range ep.Parameters {
			nameLower := strings.ToLower(p.Name)
			if strings.Contains(nameLower, "id") || strings.Contains(nameLower, "uuid") {
				return true
			}
		}
		return false
	}

	if hasIDParam(nodeA.Endpoint) && hasIDParam(nodeB.Endpoint) {
		return &EndpointEdge{
			From:       nodeA.Key,
			To:         nodeB.Key,
			Type:       EdgeTypeIDOR,
			SharedData: []string{nodeA.ResourceType + "_id"},
			Strength:   0.7,
		}
	}

	return nil
}

// GetNode returns a node by key
func (g *EndpointGraph) GetNode(key string) *EndpointNode {
	return g.nodes[key]
}

// GetEdges returns all edges
func (g *EndpointGraph) GetEdges() []EndpointEdge {
	return g.edges
}

// GetEdgesFrom returns edges starting from a node
func (g *EndpointGraph) GetEdgesFrom(key string) []EndpointEdge {
	var edges []EndpointEdge
	for _, e := range g.edges {
		if e.From == key {
			edges = append(edges, e)
		}
	}
	return edges
}

// GetEdgesTo returns edges ending at a node
func (g *EndpointGraph) GetEdgesTo(key string) []EndpointEdge {
	var edges []EndpointEdge
	for _, e := range g.edges {
		if e.To == key {
			edges = append(edges, e)
		}
	}
	return edges
}

// FindChainCandidates finds potential attack chain paths
func (g *EndpointGraph) FindChainCandidates(maxDepth int) [][]string {
	var chains [][]string

	// Start from each node
	for key := range g.nodes {
		paths := g.findPaths(key, maxDepth, make(map[string]bool))
		chains = append(chains, paths...)
	}

	return chains
}

// findPaths finds all paths from a starting node
func (g *EndpointGraph) findPaths(start string, maxDepth int, visited map[string]bool) [][]string {
	if maxDepth <= 0 || visited[start] {
		return nil
	}

	visited[start] = true
	defer func() { visited[start] = false }()

	var paths [][]string
	paths = append(paths, []string{start})

	edges := g.GetEdgesFrom(start)
	for _, edge := range edges {
		subPaths := g.findPaths(edge.To, maxDepth-1, visited)
		for _, subPath := range subPaths {
			path := append([]string{start}, subPath...)
			paths = append(paths, path)
		}
	}

	return paths
}

// Helper functions

func inferResourceType(endpoint types.Endpoint) string {
	path := strings.ToLower(endpoint.Path)

	// Common resource patterns
	resources := []string{
		"user", "account", "profile",
		"order", "cart", "checkout",
		"product", "item", "inventory",
		"payment", "transaction",
		"comment", "post", "article",
		"file", "document", "attachment",
		"message", "notification",
		"setting", "config", "preference",
		"admin", "role", "permission",
	}

	for _, resource := range resources {
		if strings.Contains(path, "/"+resource) || strings.Contains(path, resource+"s") {
			return resource
		}
	}

	// Extract from path segments
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) > 0 {
		// First segment is often the resource
		return strings.TrimSuffix(segments[0], "s")
	}

	return ""
}

func inferOperations(endpoint types.Endpoint) []string {
	switch endpoint.Method {
	case "GET":
		return []string{"read"}
	case "POST":
		return []string{"create"}
	case "PUT":
		return []string{"update", "replace"}
	case "PATCH":
		return []string{"update"}
	case "DELETE":
		return []string{"delete"}
	default:
		return []string{}
	}
}

func extractParameterNames(endpoint types.Endpoint) []string {
	names := make([]string, 0)

	for _, p := range endpoint.Parameters {
		names = append(names, p.Name)
	}

	if endpoint.Body != nil {
		for _, f := range endpoint.Body.Fields {
			names = append(names, f.Name)
		}
	}

	return names
}

func inferProvides(endpoint types.Endpoint) []string {
	provides := make([]string, 0)

	// POST typically creates and returns IDs
	if endpoint.Method == "POST" {
		resourceType := inferResourceType(endpoint)
		if resourceType != "" {
			provides = append(provides, resourceType+"_id", "id")
		}

		// Auth endpoints provide tokens
		pathLower := strings.ToLower(endpoint.Path)
		if strings.Contains(pathLower, "login") || strings.Contains(pathLower, "auth") {
			provides = append(provides, "token", "access_token", "refresh_token", "session")
		}
	}

	// GET typically returns data including IDs
	if endpoint.Method == "GET" {
		resourceType := inferResourceType(endpoint)
		if resourceType != "" {
			provides = append(provides, resourceType+"_id", "id")
		}
	}

	return provides
}

func requiresAuth(endpoint types.Endpoint) bool {
	// Check if endpoint has auth configuration
	if endpoint.Auth != nil {
		return true
	}

	// Check for protected paths
	protectedPatterns := []string{
		"/admin", "/user", "/account", "/profile",
		"/order", "/payment", "/settings",
	}

	pathLower := strings.ToLower(endpoint.Path)
	for _, pattern := range protectedPatterns {
		if strings.Contains(pathLower, pattern) {
			return true
		}
	}

	// Public paths
	publicPatterns := []string{
		"/public", "/login", "/register", "/signup",
		"/health", "/status", "/docs", "/swagger",
	}

	for _, pattern := range publicPatterns {
		if strings.Contains(pathLower, pattern) {
			return false
		}
	}

	// Default: assume authenticated
	return true
}

func containsOperation(ops []string, target string) bool {
	for _, op := range ops {
		if op == target {
			return true
		}
	}
	return false
}
