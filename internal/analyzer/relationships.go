package analyzer

import (
	"regexp"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// RelationshipMapper maps relationships between endpoints
type RelationshipMapper struct{}

// NewRelationshipMapper creates a new relationship mapper
func NewRelationshipMapper() *RelationshipMapper {
	return &RelationshipMapper{}
}

// Relationship types
const (
	RelationCreates    = "creates"
	RelationReads      = "reads"
	RelationUpdates    = "updates"
	RelationDeletes    = "deletes"
	RelationReferences = "references"
	RelationBelongsTo  = "belongs_to"
)

// EndpointRelationship describes a relationship between endpoints
type EndpointRelationship struct {
	Source      types.Endpoint
	Target      types.Endpoint
	Type        string
	Description string
}

// MapRelationships identifies relationships between endpoints
func (m *RelationshipMapper) MapRelationships(endpoints []types.Endpoint) []EndpointRelationship {
	var relationships []EndpointRelationship

	// Group endpoints by resource
	resourceMap := m.groupByResource(endpoints)

	// Find CRUD relationships within each resource
	for resource, eps := range resourceMap {
		crudRels := m.findCRUDRelationships(resource, eps)
		relationships = append(relationships, crudRels...)
	}

	// Find cross-resource relationships
	crossRels := m.findCrossResourceRelationships(endpoints, resourceMap)
	relationships = append(relationships, crossRels...)

	return relationships
}

// groupByResource groups endpoints by their resource
func (m *RelationshipMapper) groupByResource(endpoints []types.Endpoint) map[string][]types.Endpoint {
	groups := make(map[string][]types.Endpoint)

	for _, ep := range endpoints {
		resource := m.extractResource(ep.Path)
		if resource != "" {
			groups[resource] = append(groups[resource], ep)
		}
	}

	return groups
}

// extractResource extracts the primary resource from a path
func (m *RelationshipMapper) extractResource(path string) string {
	// Remove leading slash and split
	path = strings.TrimPrefix(path, "/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 {
		return ""
	}

	// Skip version prefixes (v1, v2, api, etc.)
	start := 0
	for i, part := range parts {
		if regexp.MustCompile(`^v\d+$`).MatchString(part) || part == "api" {
			start = i + 1
		} else {
			break
		}
	}

	if start >= len(parts) {
		return ""
	}

	return parts[start]
}

// findCRUDRelationships finds CRUD relationships for a resource
func (m *RelationshipMapper) findCRUDRelationships(resource string, endpoints []types.Endpoint) []EndpointRelationship {
	var relationships []EndpointRelationship

	var listEndpoint, createEndpoint, readEndpoint, updateEndpoint, deleteEndpoint *types.Endpoint

	for i := range endpoints {
		ep := &endpoints[i]

		// Classify by method and path pattern
		hasID := m.hasIDInPath(ep.Path)

		switch ep.Method {
		case "GET":
			if hasID {
				readEndpoint = ep
			} else {
				listEndpoint = ep
			}
		case "POST":
			if !hasID {
				createEndpoint = ep
			}
		case "PUT", "PATCH":
			if hasID {
				updateEndpoint = ep
			}
		case "DELETE":
			if hasID {
				deleteEndpoint = ep
			}
		}
	}

	// Create relationships
	if createEndpoint != nil {
		if readEndpoint != nil {
			relationships = append(relationships, EndpointRelationship{
				Source:      *createEndpoint,
				Target:      *readEndpoint,
				Type:        RelationCreates,
				Description: "Creates a resource that can be read",
			})
		}
		if listEndpoint != nil {
			relationships = append(relationships, EndpointRelationship{
				Source:      *createEndpoint,
				Target:      *listEndpoint,
				Type:        RelationCreates,
				Description: "Creates a resource that appears in list",
			})
		}
	}

	if updateEndpoint != nil && readEndpoint != nil {
		relationships = append(relationships, EndpointRelationship{
			Source:      *updateEndpoint,
			Target:      *readEndpoint,
			Type:        RelationUpdates,
			Description: "Updates a resource",
		})
	}

	if deleteEndpoint != nil {
		if readEndpoint != nil {
			relationships = append(relationships, EndpointRelationship{
				Source:      *deleteEndpoint,
				Target:      *readEndpoint,
				Type:        RelationDeletes,
				Description: "Deletes a resource",
			})
		}
		if listEndpoint != nil {
			relationships = append(relationships, EndpointRelationship{
				Source:      *deleteEndpoint,
				Target:      *listEndpoint,
				Type:        RelationDeletes,
				Description: "Deletes a resource from list",
			})
		}
	}

	return relationships
}

// findCrossResourceRelationships finds relationships between different resources
func (m *RelationshipMapper) findCrossResourceRelationships(endpoints []types.Endpoint, resourceMap map[string][]types.Endpoint) []EndpointRelationship {
	var relationships []EndpointRelationship

	// Look for nested resources (e.g., /users/{id}/orders)
	nestedPattern := regexp.MustCompile(`/([^/]+)/\{[^}]+\}/([^/]+)`)

	for _, ep := range endpoints {
		matches := nestedPattern.FindStringSubmatch(ep.Path)
		if len(matches) >= 3 {
			parentResource := matches[1]
			childResource := matches[2]

			// Find parent endpoints
			if parentEps, ok := resourceMap[parentResource]; ok {
				for _, parentEp := range parentEps {
					if parentEp.Method == "GET" && m.hasIDInPath(parentEp.Path) {
						relationships = append(relationships, EndpointRelationship{
							Source:      ep,
							Target:      parentEp,
							Type:        RelationBelongsTo,
							Description: childResource + " belongs to " + parentResource,
						})
					}
				}
			}
		}
	}

	// Look for reference parameters (e.g., user_id in body)
	for _, ep := range endpoints {
		if ep.Body == nil {
			continue
		}

		for _, field := range ep.Body.Fields {
			refResource := m.extractResourceFromFieldName(field.Name)
			if refResource != "" && refResource != m.extractResource(ep.Path) {
				if refEps, ok := resourceMap[refResource]; ok {
					for _, refEp := range refEps {
						if refEp.Method == "GET" && m.hasIDInPath(refEp.Path) {
							relationships = append(relationships, EndpointRelationship{
								Source:      ep,
								Target:      refEp,
								Type:        RelationReferences,
								Description: "References " + refResource + " via " + field.Name,
							})
							break
						}
					}
				}
			}
		}
	}

	return relationships
}

// hasIDInPath checks if a path contains an ID placeholder
func (m *RelationshipMapper) hasIDInPath(path string) bool {
	return regexp.MustCompile(`\{[^}]+\}|:[^/]+`).MatchString(path)
}

// extractResourceFromFieldName extracts resource name from field names like user_id
func (m *RelationshipMapper) extractResourceFromFieldName(fieldName string) string {
	// Common patterns: user_id, userId, user-id
	patterns := []struct {
		regex   *regexp.Regexp
		capture int
	}{
		{regexp.MustCompile(`^([a-z]+)_id$`), 1},
		{regexp.MustCompile(`^([a-z]+)Id$`), 1},
		{regexp.MustCompile(`^([a-z]+)-id$`), 1},
	}

	for _, p := range patterns {
		matches := p.regex.FindStringSubmatch(strings.ToLower(fieldName))
		if len(matches) > p.capture {
			// Convert to plural if needed
			resource := matches[p.capture]
			if !strings.HasSuffix(resource, "s") {
				resource += "s"
			}
			return resource
		}
	}

	return ""
}

// GetSecurityImplications returns security implications of relationships
func (m *RelationshipMapper) GetSecurityImplications(relationships []EndpointRelationship) []string {
	var implications []string

	for _, rel := range relationships {
		switch rel.Type {
		case RelationCreates:
			implications = append(implications,
				"Create operation ("+rel.Source.Method+" "+rel.Source.Path+") should validate authorization before creating resources visible at "+rel.Target.Path)

		case RelationDeletes:
			implications = append(implications,
				"Delete operation ("+rel.Source.Method+" "+rel.Source.Path+") is destructive - verify proper authorization and consider soft-delete")

		case RelationReferences:
			implications = append(implications,
				"Reference relationship detected - "+rel.Source.Path+" references resources at "+rel.Target.Path+". Test for IDOR by manipulating the reference ID")

		case RelationBelongsTo:
			implications = append(implications,
				"Nested resource "+rel.Source.Path+" belongs to parent. Verify that accessing child resources requires authorization on parent")
		}
	}

	return implications
}
