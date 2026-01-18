package fuzzer

import (
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/su1ph3r/indago/pkg/types"
)

// readResponse reads an HTTP response into our response type
func readResponse(resp *http.Response) (*types.HTTPResponse, error) {
	defer resp.Body.Close()

	// Read body with limit
	body, err := readBody(resp.Body, 10*1024*1024) // 10MB limit
	if err != nil {
		return nil, err
	}

	// Convert headers
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}

	return &types.HTTPResponse{
		StatusCode:    resp.StatusCode,
		Status:        resp.Status,
		Headers:       headers,
		Body:          string(body),
		ContentLength: resp.ContentLength,
	}, nil
}

// readBody reads response body with a size limit
func readBody(reader io.Reader, limit int64) ([]byte, error) {
	limitedReader := io.LimitReader(reader, limit)
	return io.ReadAll(limitedReader)
}

// stringReader creates an io.Reader from a string
func stringReader(s string) io.Reader {
	return strings.NewReader(s)
}

// ResponseComparator compares responses to detect anomalies
type ResponseComparator struct {
	threshold float64
}

// NewResponseComparator creates a new response comparator
func NewResponseComparator(threshold float64) *ResponseComparator {
	if threshold <= 0 {
		threshold = 0.1 // 10% difference threshold
	}
	return &ResponseComparator{threshold: threshold}
}

// Compare compares two responses and returns a similarity score
func (c *ResponseComparator) Compare(baseline, fuzzed *types.HTTPResponse) *ComparisonResult {
	if baseline == nil || fuzzed == nil {
		return &ComparisonResult{IsAnomaly: true}
	}

	result := &ComparisonResult{
		StatusCodeMatch: baseline.StatusCode == fuzzed.StatusCode,
		StatusCodeDiff:  fuzzed.StatusCode - baseline.StatusCode,
		ContentLengthDiff: fuzzed.ContentLength - baseline.ContentLength,
	}

	// Calculate body similarity
	result.BodySimilarity = c.calculateSimilarity(baseline.Body, fuzzed.Body)

	// Calculate header changes
	result.HeaderChanges = c.compareHeaders(baseline.Headers, fuzzed.Headers)

	// Determine if it's an anomaly
	result.IsAnomaly = c.isAnomaly(result)

	return result
}

// ComparisonResult holds the comparison between baseline and fuzzed response
type ComparisonResult struct {
	StatusCodeMatch   bool
	StatusCodeDiff    int
	ContentLengthDiff int64
	BodySimilarity    float64
	HeaderChanges     []string
	IsAnomaly         bool
	TimeDiff          time.Duration
}

// calculateSimilarity calculates the similarity between two strings
func (c *ResponseComparator) calculateSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}

	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}

	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	// Simple length-based similarity for performance
	// In production, you might use more sophisticated algorithms
	lenA := float64(len(a))
	lenB := float64(len(b))

	lengthSimilarity := 1.0 - (abs(lenA-lenB) / max(lenA, lenB))

	// Quick content comparison using sampling
	contentSimilarity := c.sampleComparison(a, b)

	return (lengthSimilarity + contentSimilarity) / 2
}

// sampleComparison does a quick content comparison by sampling
func (c *ResponseComparator) sampleComparison(a, b string) float64 {
	samples := 10
	matches := 0

	shorter := a
	longer := b
	if len(a) > len(b) {
		shorter = b
		longer = a
	}

	if len(shorter) < samples {
		samples = len(shorter)
	}

	if samples == 0 {
		return 0.0
	}

	step := len(shorter) / samples
	if step == 0 {
		step = 1
	}

	for i := 0; i < samples; i++ {
		pos := i * step
		if pos < len(shorter) && pos < len(longer) {
			if shorter[pos] == longer[pos] {
				matches++
			}
		}
	}

	return float64(matches) / float64(samples)
}

// compareHeaders compares two header sets
func (c *ResponseComparator) compareHeaders(baseline, fuzzed map[string]string) []string {
	var changes []string

	// Check for missing or changed headers
	for key, baseValue := range baseline {
		if fuzzValue, ok := fuzzed[key]; !ok {
			changes = append(changes, "removed: "+key)
		} else if fuzzValue != baseValue {
			changes = append(changes, "changed: "+key)
		}
	}

	// Check for new headers
	for key := range fuzzed {
		if _, ok := baseline[key]; !ok {
			changes = append(changes, "added: "+key)
		}
	}

	return changes
}

// isAnomaly determines if a result is anomalous
func (c *ResponseComparator) isAnomaly(result *ComparisonResult) bool {
	// Different status code is suspicious
	if !result.StatusCodeMatch {
		// Error to success or vice versa is very suspicious
		if result.StatusCodeDiff > 100 || result.StatusCodeDiff < -100 {
			return true
		}
	}

	// Large content length difference
	if result.ContentLengthDiff > 1000 || result.ContentLengthDiff < -1000 {
		return true
	}

	// Low body similarity
	if result.BodySimilarity < (1.0 - c.threshold) {
		return true
	}

	// Sensitive headers changed
	sensitiveHeaders := []string{"Set-Cookie", "Authorization", "X-Auth-Token"}
	for _, change := range result.HeaderChanges {
		for _, sensitive := range sensitiveHeaders {
			if strings.Contains(change, sensitive) {
				return true
			}
		}
	}

	return false
}

// Helper functions
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
