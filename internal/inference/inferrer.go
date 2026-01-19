// Package inference provides API schema inference from traffic
package inference

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// SchemaInferrer infers API schema from captured requests
type SchemaInferrer struct {
	requests      []CapturedRequest
	clusters      map[string]*RequestCluster
	minConfidence float64
	threshold     float64 // Similarity threshold for clustering
}

// CapturedRequest represents a captured HTTP request
type CapturedRequest struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Path        string            `json:"path"`
	Query       map[string]string `json:"query"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	ContentType string            `json:"content_type"`
	Timestamp   int64             `json:"timestamp"`
}

// RequestCluster represents a group of similar requests
type RequestCluster struct {
	PathPattern    string              `json:"path_pattern"`
	Method         string              `json:"method"`
	Requests       []CapturedRequest   `json:"requests"`
	InferredParams []InferredParameter `json:"inferred_params"`
	Examples       []string            `json:"examples"`
	Count          int                 `json:"count"`
}

// InferredParameter represents an inferred API parameter
type InferredParameter struct {
	Name         string   `json:"name"`
	Location     string   `json:"location"` // path, query, header, body
	InferredType string   `json:"inferred_type"`
	Required     bool     `json:"required"`
	Examples     []string `json:"examples"`
	Confidence   float64  `json:"confidence"`
	Pattern      string   `json:"pattern,omitempty"`
}

// InferenceSettings holds inference configuration
type InferenceSettings struct {
	MinConfidence      float64 `yaml:"min_confidence" json:"min_confidence"`
	ClusterThreshold   float64 `yaml:"cluster_threshold" json:"cluster_threshold"`
	MaxExamples        int     `yaml:"max_examples" json:"max_examples"`
}

// NewSchemaInferrer creates a new schema inferrer
func NewSchemaInferrer(settings InferenceSettings) *SchemaInferrer {
	if settings.MinConfidence <= 0 {
		settings.MinConfidence = 0.7
	}
	if settings.ClusterThreshold <= 0 {
		settings.ClusterThreshold = 0.8
	}

	return &SchemaInferrer{
		requests:      make([]CapturedRequest, 0),
		clusters:      make(map[string]*RequestCluster),
		minConfidence: settings.MinConfidence,
		threshold:     settings.ClusterThreshold,
	}
}

// AddRequest adds a captured request for inference
func (si *SchemaInferrer) AddRequest(req CapturedRequest) {
	si.requests = append(si.requests, req)
}

// AddRequests adds multiple captured requests
func (si *SchemaInferrer) AddRequests(reqs []CapturedRequest) {
	si.requests = append(si.requests, reqs...)
}

// Infer performs schema inference and returns endpoints
func (si *SchemaInferrer) Infer() ([]types.Endpoint, error) {
	// Step 1: Normalize and cluster requests
	si.clusterRequests()

	// Step 2: Infer parameters for each cluster
	si.inferParameters()

	// Step 3: Convert clusters to endpoints
	endpoints := si.clustersToEndpoints()

	return endpoints, nil
}

// clusterRequests clusters similar requests together
func (si *SchemaInferrer) clusterRequests() {
	for _, req := range si.requests {
		// Normalize the path
		normalizedPath := si.normalizePath(req.Path)
		key := req.Method + ":" + normalizedPath

		if cluster, exists := si.clusters[key]; exists {
			cluster.Requests = append(cluster.Requests, req)
			cluster.Count++
			if len(cluster.Examples) < 5 {
				cluster.Examples = append(cluster.Examples, req.URL)
			}
		} else {
			si.clusters[key] = &RequestCluster{
				PathPattern: normalizedPath,
				Method:      req.Method,
				Requests:    []CapturedRequest{req},
				Examples:    []string{req.URL},
				Count:       1,
			}
		}
	}
}

// normalizePath normalizes a path by replacing dynamic segments
func (si *SchemaInferrer) normalizePath(path string) string {
	segments := strings.Split(path, "/")
	normalized := make([]string, 0, len(segments))

	for _, seg := range segments {
		if seg == "" {
			continue
		}

		// Check for various dynamic patterns
		normalizedSeg := si.normalizeSegment(seg)
		normalized = append(normalized, normalizedSeg)
	}

	return "/" + strings.Join(normalized, "/")
}

// normalizeSegment normalizes a single path segment
func (si *SchemaInferrer) normalizeSegment(seg string) string {
	// UUID pattern
	uuidPattern := regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	if uuidPattern.MatchString(seg) {
		return "{uuid}"
	}

	// Numeric ID pattern
	numericPattern := regexp.MustCompile(`^\d+$`)
	if numericPattern.MatchString(seg) {
		return "{id}"
	}

	// MongoDB ObjectId pattern
	objectIdPattern := regexp.MustCompile(`^[a-f0-9]{24}$`)
	if objectIdPattern.MatchString(seg) {
		return "{objectId}"
	}

	// Slug pattern (could be dynamic)
	slugPattern := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)+$`)
	if slugPattern.MatchString(seg) {
		return "{slug}"
	}

	// Base64-like pattern (tokens)
	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9_-]{20,}$`)
	if base64Pattern.MatchString(seg) {
		return "{token}"
	}

	// Email pattern
	emailPattern := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if emailPattern.MatchString(seg) {
		return "{email}"
	}

	return seg
}

// inferParameters infers parameters for each cluster
func (si *SchemaInferrer) inferParameters() {
	for _, cluster := range si.clusters {
		params := make([]InferredParameter, 0)

		// Infer path parameters
		pathParams := si.inferPathParameters(cluster)
		params = append(params, pathParams...)

		// Infer query parameters
		queryParams := si.inferQueryParameters(cluster)
		params = append(params, queryParams...)

		// Infer body parameters
		bodyParams := si.inferBodyParameters(cluster)
		params = append(params, bodyParams...)

		// Infer header parameters
		headerParams := si.inferHeaderParameters(cluster)
		params = append(params, headerParams...)

		cluster.InferredParams = params
	}
}

// inferPathParameters infers parameters from path patterns
func (si *SchemaInferrer) inferPathParameters(cluster *RequestCluster) []InferredParameter {
	var params []InferredParameter

	segments := strings.Split(cluster.PathPattern, "/")
	for _, seg := range segments {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			paramName := seg[1 : len(seg)-1]
			paramType := "string"

			switch paramName {
			case "id":
				paramType = "integer"
			case "uuid", "objectId":
				paramType = "string"
			}

			// Collect examples
			examples := si.collectPathParamExamples(cluster.Requests, seg)

			params = append(params, InferredParameter{
				Name:         paramName,
				Location:     "path",
				InferredType: paramType,
				Required:     true,
				Examples:     examples,
				Confidence:   1.0, // Path params are always high confidence
			})
		}
	}

	return params
}

// collectPathParamExamples collects example values for a path parameter
func (si *SchemaInferrer) collectPathParamExamples(requests []CapturedRequest, placeholder string) []string {
	examples := make([]string, 0)
	seen := make(map[string]bool)

	// Get the position of the placeholder
	// This is simplified - in practice you'd need to match positions

	for _, req := range requests {
		segments := strings.Split(req.Path, "/")
		for _, seg := range segments {
			// Try to find dynamic segments
			if si.normalizeSegment(seg) == placeholder && !seen[seg] {
				seen[seg] = true
				examples = append(examples, seg)
				if len(examples) >= 5 {
					return examples
				}
			}
		}
	}

	return examples
}

// inferQueryParameters infers parameters from query strings
func (si *SchemaInferrer) inferQueryParameters(cluster *RequestCluster) []InferredParameter {
	paramStats := make(map[string]*paramStat)

	for _, req := range cluster.Requests {
		for name, value := range req.Query {
			if stat, exists := paramStats[name]; exists {
				stat.count++
				if len(stat.examples) < 5 && !contains(stat.examples, value) {
					stat.examples = append(stat.examples, value)
				}
			} else {
				paramStats[name] = &paramStat{
					name:     name,
					count:    1,
					examples: []string{value},
				}
			}
		}
	}

	var params []InferredParameter
	totalRequests := len(cluster.Requests)

	for _, stat := range paramStats {
		confidence := float64(stat.count) / float64(totalRequests)
		required := confidence > 0.9 // Present in >90% of requests

		params = append(params, InferredParameter{
			Name:         stat.name,
			Location:     "query",
			InferredType: inferTypeFromExamples(stat.examples),
			Required:     required,
			Examples:     stat.examples,
			Confidence:   confidence,
		})
	}

	return params
}

// inferBodyParameters infers parameters from request bodies
func (si *SchemaInferrer) inferBodyParameters(cluster *RequestCluster) []InferredParameter {
	if cluster.Method == "GET" || cluster.Method == "DELETE" {
		return nil
	}

	fieldStats := make(map[string]*paramStat)

	for _, req := range cluster.Requests {
		if req.Body == "" {
			continue
		}

		// Try to parse as JSON
		var body map[string]interface{}
		if err := json.Unmarshal([]byte(req.Body), &body); err != nil {
			continue
		}

		si.collectJSONFields(body, "", fieldStats)
	}

	var params []InferredParameter
	requestsWithBody := 0
	for _, req := range cluster.Requests {
		if req.Body != "" {
			requestsWithBody++
		}
	}

	if requestsWithBody == 0 {
		return params
	}

	for _, stat := range fieldStats {
		confidence := float64(stat.count) / float64(requestsWithBody)
		if confidence < si.minConfidence {
			continue
		}

		params = append(params, InferredParameter{
			Name:         stat.name,
			Location:     "body",
			InferredType: inferTypeFromExamples(stat.examples),
			Required:     confidence > 0.9,
			Examples:     stat.examples,
			Confidence:   confidence,
		})
	}

	return params
}

// collectJSONFields recursively collects JSON field names and values
func (si *SchemaInferrer) collectJSONFields(data map[string]interface{}, prefix string, stats map[string]*paramStat) {
	for key, value := range data {
		fieldName := key
		if prefix != "" {
			fieldName = prefix + "." + key
		}

		var example string
		switch v := value.(type) {
		case string:
			example = v
		case float64:
			example = json.Number(string(rune(int(v)))).String()
		case bool:
			if v {
				example = "true"
			} else {
				example = "false"
			}
		case map[string]interface{}:
			si.collectJSONFields(v, fieldName, stats)
			continue
		case []interface{}:
			if len(v) > 0 {
				if nested, ok := v[0].(map[string]interface{}); ok {
					si.collectJSONFields(nested, fieldName+"[]", stats)
				}
			}
			continue
		default:
			example = ""
		}

		if stat, exists := stats[fieldName]; exists {
			stat.count++
			if len(stat.examples) < 5 && example != "" && !contains(stat.examples, example) {
				stat.examples = append(stat.examples, example)
			}
		} else {
			examples := []string{}
			if example != "" {
				examples = append(examples, example)
			}
			stats[fieldName] = &paramStat{
				name:     fieldName,
				count:    1,
				examples: examples,
			}
		}
	}
}

// inferHeaderParameters infers parameters from headers
func (si *SchemaInferrer) inferHeaderParameters(cluster *RequestCluster) []InferredParameter {
	// Focus on custom/interesting headers
	interestingHeaders := map[string]bool{
		"authorization":  true,
		"x-api-key":      true,
		"x-auth-token":   true,
		"x-request-id":   true,
		"x-correlation-id": true,
		"x-session-id":   true,
	}

	headerStats := make(map[string]*paramStat)

	for _, req := range cluster.Requests {
		for name, value := range req.Headers {
			nameLower := strings.ToLower(name)
			if !interestingHeaders[nameLower] && !strings.HasPrefix(nameLower, "x-") {
				continue
			}

			if stat, exists := headerStats[name]; exists {
				stat.count++
				if len(stat.examples) < 3 && !contains(stat.examples, "[REDACTED]") {
					stat.examples = append(stat.examples, "[REDACTED]")
				}
			} else {
				headerStats[name] = &paramStat{
					name:     name,
					count:    1,
					examples: []string{"[REDACTED]"}, // Don't leak auth tokens
				}
				_ = value // We don't store actual header values
			}
		}
	}

	var params []InferredParameter
	totalRequests := len(cluster.Requests)

	for _, stat := range headerStats {
		confidence := float64(stat.count) / float64(totalRequests)

		params = append(params, InferredParameter{
			Name:         stat.name,
			Location:     "header",
			InferredType: "string",
			Required:     confidence > 0.9,
			Examples:     stat.examples,
			Confidence:   confidence,
		})
	}

	return params
}

// clustersToEndpoints converts clusters to endpoints
func (si *SchemaInferrer) clustersToEndpoints() []types.Endpoint {
	var endpoints []types.Endpoint

	for _, cluster := range si.clusters {
		// Determine base URL from examples
		baseURL := ""
		if len(cluster.Requests) > 0 {
			parsed, err := url.Parse(cluster.Requests[0].URL)
			if err == nil {
				baseURL = parsed.Scheme + "://" + parsed.Host
			}
		}

		// Convert parameters
		var params []types.Parameter
		var bodyFields []types.BodyField

		for _, ip := range cluster.InferredParams {
			if ip.Confidence < si.minConfidence {
				continue
			}

			if ip.Location == "body" {
				bodyFields = append(bodyFields, types.BodyField{
					Name:        ip.Name,
					Type:        ip.InferredType,
					Required:    ip.Required,
					Example:     getFirstExample(ip.Examples),
					Description: "Inferred from traffic",
				})
			} else {
				var example interface{} = getFirstExample(ip.Examples)
				params = append(params, types.Parameter{
					Name:        ip.Name,
					In:          ip.Location,
					Type:        ip.InferredType,
					Required:    ip.Required,
					Example:     example,
					Description: "Inferred from traffic",
				})
			}
		}

		endpoint := types.Endpoint{
			Method:      cluster.Method,
			Path:        cluster.PathPattern,
			BaseURL:     baseURL,
			Parameters:  params,
			Description: "Inferred endpoint",
			Tags:        []string{"inferred"},
		}

		if len(bodyFields) > 0 {
			contentType := "application/json"
			if len(cluster.Requests) > 0 {
				contentType = cluster.Requests[0].ContentType
				if contentType == "" {
					contentType = "application/json"
				}
			}

			endpoint.Body = &types.RequestBody{
				ContentType: contentType,
				Required:    true,
				Fields:      bodyFields,
			}
		}

		endpoints = append(endpoints, endpoint)
	}

	// Sort by path for consistency
	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].Path < endpoints[j].Path
	})

	return endpoints
}

// GetClusters returns the request clusters
func (si *SchemaInferrer) GetClusters() map[string]*RequestCluster {
	return si.clusters
}

// Helper types and functions

type paramStat struct {
	name     string
	count    int
	examples []string
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func getFirstExample(examples []string) string {
	if len(examples) > 0 {
		return examples[0]
	}
	return ""
}

func inferTypeFromExamples(examples []string) string {
	if len(examples) == 0 {
		return "string"
	}

	// Check if all examples are numeric
	allNumeric := true
	allInteger := true
	allBoolean := true

	for _, ex := range examples {
		// Check boolean
		if ex != "true" && ex != "false" {
			allBoolean = false
		}

		// Check numeric
		if !regexp.MustCompile(`^-?\d+\.?\d*$`).MatchString(ex) {
			allNumeric = false
			allInteger = false
		} else if strings.Contains(ex, ".") {
			allInteger = false
		}
	}

	if allBoolean {
		return "boolean"
	}
	if allInteger {
		return "integer"
	}
	if allNumeric {
		return "number"
	}

	return "string"
}
