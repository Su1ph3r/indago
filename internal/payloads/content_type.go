// Package payloads provides attack payload generation
package payloads

import (
	"github.com/su1ph3r/indago/pkg/types"
)

// ContentTypeConfusionGenerator tests how APIs handle mismatched Content-Type
// headers. Only targets POST/PUT/PATCH endpoints.
type ContentTypeConfusionGenerator struct{}

// NewContentTypeConfusionGenerator creates a new content-type confusion generator.
func NewContentTypeConfusionGenerator() *ContentTypeConfusionGenerator {
	return &ContentTypeConfusionGenerator{}
}

// Type returns the attack type.
func (g *ContentTypeConfusionGenerator) Type() string {
	return types.AttackContentTypeConfusion
}

// Generate produces content-type confusion payloads. Sentinel: only runs
// for the first parameter to avoid duplication.
func (g *ContentTypeConfusionGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	// Only for methods with request bodies
	if endpoint.Method != "POST" && endpoint.Method != "PUT" && endpoint.Method != "PATCH" {
		return nil
	}

	// Sentinel: only first parameter
	if len(endpoint.Parameters) > 0 && param.Name != endpoint.Parameters[0].Name {
		return nil
	}
	if endpoint.Body != nil && len(endpoint.Parameters) == 0 &&
		len(endpoint.Body.Fields) > 0 && param.Name != endpoint.Body.Fields[0].Name {
		return nil
	}

	confusionPayloads := []struct {
		desc        string
		contentType string
		remove      bool
	}{
		{"JSON body with form-urlencoded Content-Type", "application/x-www-form-urlencoded", false},
		{"JSON body with text/plain Content-Type", "text/plain", false},
		{"JSON body with XML Content-Type", "application/xml", false},
		{"JSON body with no Content-Type", "", true},
	}

	var payloads []Payload
	for _, cp := range confusionPayloads {
		meta := map[string]string{}
		if cp.remove {
			meta["remove_content_type"] = "true"
		} else {
			meta["override_content_type"] = cp.contentType
		}

		payloads = append(payloads, Payload{
			Value:       param.Name, // keep original value
			Type:        types.AttackContentTypeConfusion,
			Category:    "parser_confusion",
			Description: cp.desc,
			Metadata:    meta,
		})
	}

	return payloads
}
