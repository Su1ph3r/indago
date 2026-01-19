package types

import (
	"time"
)

// Config represents the application configuration
type Config struct {
	// LLM Provider settings
	Provider ProviderConfig `yaml:"provider" mapstructure:"provider"`

	// Scan settings
	Scan ScanSettings `yaml:"scan" mapstructure:"scan"`

	// HTTP settings
	HTTP HTTPSettings `yaml:"http" mapstructure:"http"`

	// Output settings
	Output OutputSettings `yaml:"output" mapstructure:"output"`

	// Attack settings
	Attacks AttackSettings `yaml:"attacks" mapstructure:"attacks"`

	// Attack Chain settings
	Chains ChainSettings `yaml:"chains" mapstructure:"chains"`

	// Stateful session tracking
	State StateSettings `yaml:"state" mapstructure:"state"`

	// Differential response analysis
	Differential DifferentialSettings `yaml:"differential" mapstructure:"differential"`

	// GraphQL settings
	GraphQL GraphQLSettings `yaml:"graphql" mapstructure:"graphql"`

	// Business rules settings
	Rules RulesSettings `yaml:"rules" mapstructure:"rules"`

	// Schema inference settings
	Inference InferenceSettings `yaml:"inference" mapstructure:"inference"`

	// Callback/OOB detection settings
	Callback CallbackSettings `yaml:"callback" mapstructure:"callback"`

	// WAF detection settings
	WAF WAFSettings `yaml:"waf" mapstructure:"waf"`
}

// ProviderConfig holds LLM provider configuration
type ProviderConfig struct {
	Name        string  `yaml:"name" mapstructure:"name"` // openai, anthropic, ollama, lmstudio
	APIKey      string  `yaml:"api_key" mapstructure:"api_key"`
	BaseURL     string  `yaml:"base_url" mapstructure:"base_url"` // For ollama/lmstudio
	Model       string  `yaml:"model" mapstructure:"model"`
	MaxTokens   int     `yaml:"max_tokens" mapstructure:"max_tokens"`
	Temperature float64 `yaml:"temperature" mapstructure:"temperature"`
}

// ScanSettings holds scan configuration
type ScanSettings struct {
	Concurrency     int           `yaml:"concurrency" mapstructure:"concurrency"`
	RateLimit       float64       `yaml:"rate_limit" mapstructure:"rate_limit"` // requests per second
	Timeout         time.Duration `yaml:"timeout" mapstructure:"timeout"`
	MaxRetries      int           `yaml:"max_retries" mapstructure:"max_retries"`
	RetryDelay      time.Duration `yaml:"retry_delay" mapstructure:"retry_delay"`
	FollowRedirects bool          `yaml:"follow_redirects" mapstructure:"follow_redirects"`
	MaxRedirects    int           `yaml:"max_redirects" mapstructure:"max_redirects"`
	VerifySSL       bool          `yaml:"verify_ssl" mapstructure:"verify_ssl"`
}

// HTTPSettings holds HTTP client configuration
type HTTPSettings struct {
	ProxyURL   string            `yaml:"proxy_url" mapstructure:"proxy_url"`
	Headers    map[string]string `yaml:"headers" mapstructure:"headers"`
	UserAgent  string            `yaml:"user_agent" mapstructure:"user_agent"`
	AuthHeader string            `yaml:"auth_header" mapstructure:"auth_header"`
	AuthToken  string            `yaml:"auth_token" mapstructure:"auth_token"`
	Cookies    map[string]string `yaml:"cookies" mapstructure:"cookies"`
}

// OutputSettings holds output configuration
type OutputSettings struct {
	Format     string `yaml:"format" mapstructure:"format"` // json, html, markdown, sarif
	File       string `yaml:"file" mapstructure:"file"`
	Verbose    bool   `yaml:"verbose" mapstructure:"verbose"`
	Color      bool   `yaml:"color" mapstructure:"color"`
	IncludeRaw bool   `yaml:"include_raw" mapstructure:"include_raw"` // Include raw request/response
}

// AttackSettings holds attack configuration
type AttackSettings struct {
	Enabled            []string `yaml:"enabled" mapstructure:"enabled"` // Empty = all
	Disabled           []string `yaml:"disabled" mapstructure:"disabled"`
	MaxPayloadsPerType int      `yaml:"max_payloads_per_type" mapstructure:"max_payloads_per_type"`
	CustomPayloads     string   `yaml:"custom_payloads" mapstructure:"custom_payloads"`   // Path to custom payloads file
	UseLLMPayloads     bool     `yaml:"use_llm_payloads" mapstructure:"use_llm_payloads"` // Generate additional context-aware payloads using LLM
	LLMConcurrency     int      `yaml:"llm_concurrency" mapstructure:"llm_concurrency"`   // Concurrent LLM calls for payload generation

	// Category-specific settings
	IDOR      IDORSettings      `yaml:"idor" mapstructure:"idor"`
	Injection InjectionSettings `yaml:"injection" mapstructure:"injection"`
}

// IDORSettings holds IDOR-specific configuration
type IDORSettings struct {
	IDRange   int  `yaml:"id_range" mapstructure:"id_range"` // How far to increment/decrement
	TestUUIDs bool `yaml:"test_uuids" mapstructure:"test_uuids"`
	SwapUsers bool `yaml:"swap_users" mapstructure:"swap_users"`
}

// InjectionSettings holds injection attack configuration
type InjectionSettings struct {
	SQLi       bool `yaml:"sqli" mapstructure:"sqli"`
	NoSQLi     bool `yaml:"nosqli" mapstructure:"nosqli"`
	Command    bool `yaml:"command" mapstructure:"command"`
	LDAP       bool `yaml:"ldap" mapstructure:"ldap"`
	XPath      bool `yaml:"xpath" mapstructure:"xpath"`
	SSTI       bool `yaml:"ssti" mapstructure:"ssti"`
	BlindDelay int  `yaml:"blind_delay" mapstructure:"blind_delay"` // Seconds for time-based detection
}

// ChainSettings holds attack chain configuration
type ChainSettings struct {
	Enabled   bool   `yaml:"enabled" mapstructure:"enabled"`
	MaxDepth  int    `yaml:"max_depth" mapstructure:"max_depth"`
	ChainFile string `yaml:"chain_file" mapstructure:"chain_file"` // Custom chain definitions YAML
}

// StateSettings holds stateful session tracking configuration
type StateSettings struct {
	Enabled     bool   `yaml:"enabled" mapstructure:"enabled"`
	ExtractFile string `yaml:"extract_file" mapstructure:"extract_file"` // Custom extraction rules YAML
	Inject      bool   `yaml:"inject" mapstructure:"inject"`             // Enable variable injection into payloads
}

// DifferentialSettings holds differential response analysis configuration
type DifferentialSettings struct {
	Enabled      bool          `yaml:"enabled" mapstructure:"enabled"`
	AuthContexts []AuthContext `yaml:"auth_contexts" mapstructure:"auth_contexts"`
	AuthFile     string        `yaml:"auth_file" mapstructure:"auth_file"` // Auth contexts YAML file
}

// AuthContext represents an authentication context for differential analysis
type AuthContext struct {
	Name     string            `yaml:"name" mapstructure:"name"`           // "user_a", "admin", "anonymous"
	AuthType string            `yaml:"auth_type" mapstructure:"auth_type"` // "bearer", "cookie", "api_key", "basic"
	Token    string            `yaml:"token" mapstructure:"token" json:"-"` // Excluded from JSON to prevent credential leakage
	Headers  map[string]string `yaml:"headers" mapstructure:"headers"`
	Cookies  map[string]string `yaml:"cookies" mapstructure:"cookies" json:"-"` // Excluded from JSON to prevent credential leakage
	Priority int               `yaml:"priority" mapstructure:"priority"` // Lower = higher privilege (0=admin, 1=user, etc.)
	UserID   string            `yaml:"user_id" mapstructure:"user_id"`   // User identifier for horizontal access checks
}

// GraphQLSettings holds GraphQL scanning configuration
type GraphQLSettings struct {
	Endpoint     string `yaml:"endpoint" mapstructure:"endpoint"`             // GraphQL endpoint URL
	Introspect   bool   `yaml:"introspect" mapstructure:"introspect"`         // Enable introspection query
	MaxDepth     int    `yaml:"max_depth" mapstructure:"max_depth"`           // Max query depth to test
	MaxBatchSize int    `yaml:"max_batch_size" mapstructure:"max_batch_size"` // Max batch size to test
	MaxAliases   int    `yaml:"max_aliases" mapstructure:"max_aliases"`       // Max aliases to test
}

// RulesSettings holds business rules configuration
type RulesSettings struct {
	File   string `yaml:"file" mapstructure:"file"`     // Business rules YAML file
	Strict bool   `yaml:"strict" mapstructure:"strict"` // Fail scan if rules violated
}

// InferenceSettings holds schema inference configuration
type InferenceSettings struct {
	Enabled          bool    `yaml:"enabled" mapstructure:"enabled"`
	OutputFile       string  `yaml:"output_file" mapstructure:"output_file"`             // Save generated OpenAPI spec
	MinConfidence    float64 `yaml:"min_confidence" mapstructure:"min_confidence"`       // Min confidence threshold
	ClusterThreshold float64 `yaml:"cluster_threshold" mapstructure:"cluster_threshold"` // Similarity threshold for clustering
}

// CallbackSettings holds callback/OOB detection configuration
type CallbackSettings struct {
	Enabled     bool          `yaml:"enabled" mapstructure:"enabled"`
	ExternalURL string        `yaml:"external_url" mapstructure:"external_url"` // External URL (if behind NAT)
	HTTPPort    int           `yaml:"http_port" mapstructure:"http_port"`       // HTTP callback port
	DNSPort     int           `yaml:"dns_port" mapstructure:"dns_port"`         // DNS callback port
	Timeout     time.Duration `yaml:"timeout" mapstructure:"timeout"`           // Wait timeout for callbacks
}

// WAFSettings holds WAF detection and bypass configuration
type WAFSettings struct {
	Detect     bool `yaml:"detect" mapstructure:"detect"`           // Enable WAF detection
	Bypass     bool `yaml:"bypass" mapstructure:"bypass"`           // Enable WAF bypass attempts
	Threshold  int  `yaml:"threshold" mapstructure:"threshold"`     // Consecutive blocks to trigger detection
	MaxRetries int  `yaml:"max_retries" mapstructure:"max_retries"` // Max bypass attempts per payload
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Provider: ProviderConfig{
			Name:        "openai",
			Model:       "gpt-4o",
			MaxTokens:   4096,
			Temperature: 0.1,
		},
		Scan: ScanSettings{
			Concurrency:     10,
			RateLimit:       10.0,
			Timeout:         30 * time.Second,
			MaxRetries:      3,
			RetryDelay:      1 * time.Second,
			FollowRedirects: true,
			MaxRedirects:    5,
			VerifySSL:       true,
		},
		HTTP: HTTPSettings{
			UserAgent: "Indago/1.0 (Security Scanner)",
			Headers:   make(map[string]string),
			Cookies:   make(map[string]string),
		},
		Output: OutputSettings{
			Format:     "json",
			Verbose:    false,
			Color:      true,
			IncludeRaw: true,
		},
		Attacks: AttackSettings{
			Enabled:            []string{},
			Disabled:           []string{},
			MaxPayloadsPerType: 50,
			UseLLMPayloads:     false,
			LLMConcurrency:     8,
			IDOR: IDORSettings{
				IDRange:   10,
				TestUUIDs: true,
				SwapUsers: true,
			},
			Injection: InjectionSettings{
				SQLi:       true,
				NoSQLi:     true,
				Command:    true,
				LDAP:       false,
				XPath:      false,
				SSTI:       true,
				BlindDelay: 5,
			},
		},
		Chains: ChainSettings{
			Enabled:  false,
			MaxDepth: 5,
		},
		State: StateSettings{
			Enabled: false,
			Inject:  true,
		},
		Differential: DifferentialSettings{
			Enabled:      false,
			AuthContexts: []AuthContext{},
		},
		GraphQL: GraphQLSettings{
			Introspect:   true,
			MaxDepth:     10,
			MaxBatchSize: 100,
			MaxAliases:   50,
		},
		Rules: RulesSettings{
			Strict: false,
		},
		Inference: InferenceSettings{
			Enabled:          false,
			MinConfidence:    0.7,
			ClusterThreshold: 0.8,
		},
		Callback: CallbackSettings{
			Enabled:  false,
			HTTPPort: 8888,
			DNSPort:  5353,
			Timeout:  30 * time.Second,
		},
		WAF: WAFSettings{
			Detect:     false,
			Bypass:     false,
			Threshold:  5,
			MaxRetries: 3,
		},
	}
}

// InputType represents the type of input specification
type InputType string

const (
	InputTypeOpenAPI  InputType = "openapi"
	InputTypePostman  InputType = "postman"
	InputTypeHAR      InputType = "har"
	InputTypeBurp     InputType = "burp"
	InputTypeRaw      InputType = "raw"
	InputTypeGraphQL  InputType = "graphql"
	InputTypeUnknown  InputType = "unknown"
)
