// Package plugin provides extension capabilities for Indago
package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// Loader loads plugins from external files
type Loader struct {
	registry *PluginRegistry
}

// NewLoader creates a new plugin loader
func NewLoader(registry *PluginRegistry) *Loader {
	return &Loader{
		registry: registry,
	}
}

// LoadPayloadFile loads payloads from a file
func (l *Loader) LoadPayloadFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open payload file: %w", err)
	}
	defer file.Close()

	// Detect file format
	ext := getExtension(filePath)

	switch ext {
	case "json":
		return l.loadJSONPayloads(file, filePath)
	case "txt":
		return l.loadTextPayloads(file, filePath)
	case "yaml", "yml":
		return l.loadYAMLPayloads(file, filePath)
	default:
		// Default to text format
		return l.loadTextPayloads(file, filePath)
	}
}

// loadJSONPayloads loads payloads from a JSON file
func (l *Loader) loadJSONPayloads(file *os.File, filePath string) error {
	var payloadFile struct {
		Name        string    `json:"name"`
		Description string    `json:"description"`
		AttackTypes []string  `json:"attack_types"`
		Payloads    []Payload `json:"payloads"`
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&payloadFile); err != nil {
		return fmt.Errorf("failed to parse JSON payload file: %w", err)
	}

	plugin := &FilePayloadPlugin{
		name:        payloadFile.Name,
		description: payloadFile.Description,
		attackTypes: payloadFile.AttackTypes,
		payloads:    payloadFile.Payloads,
		filePath:    filePath,
	}

	l.registry.RegisterAttackPlugin(plugin)
	return nil
}

// loadTextPayloads loads payloads from a plain text file (one per line)
func (l *Loader) loadTextPayloads(file *os.File, filePath string) error {
	var payloads []Payload
	scanner := bufio.NewScanner(file)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		payloads = append(payloads, Payload{
			Value:       line,
			Type:        "custom",
			Category:    "custom",
			Description: fmt.Sprintf("Custom payload from %s line %d", filePath, lineNum),
		})
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading payload file: %w", err)
	}

	// Extract name from filename
	name := getBaseName(filePath)

	plugin := &FilePayloadPlugin{
		name:        name,
		description: fmt.Sprintf("Payloads loaded from %s", filePath),
		attackTypes: []string{"custom"},
		payloads:    payloads,
		filePath:    filePath,
	}

	l.registry.RegisterAttackPlugin(plugin)
	return nil
}

// loadYAMLPayloads loads payloads from a YAML file
func (l *Loader) loadYAMLPayloads(file *os.File, filePath string) error {
	// For simplicity, we'll use JSON-compatible YAML or treat as text
	// In production, you'd use a proper YAML library
	return l.loadTextPayloads(file, filePath)
}

// LoadMatcherFile loads matchers from a file
func (l *Loader) LoadMatcherFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open matcher file: %w", err)
	}
	defer file.Close()

	var matcherFile struct {
		Name        string        `json:"name"`
		Description string        `json:"description"`
		Matchers    []MatcherDef  `json:"matchers"`
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&matcherFile); err != nil {
		return fmt.Errorf("failed to parse matcher file: %w", err)
	}

	for _, def := range matcherFile.Matchers {
		matcher := &FileResponseMatcher{
			name:        def.Name,
			description: def.Description,
			patterns:    def.Patterns,
			severity:    def.Severity,
			confidence:  def.Confidence,
			cwe:         def.CWE,
		}
		l.registry.RegisterResponseMatcher(matcher)
	}

	return nil
}

// MatcherDef defines a matcher in a file
type MatcherDef struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Patterns    []string `json:"patterns"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	CWE         string   `json:"cwe,omitempty"`
}

// FilePayloadPlugin is a plugin loaded from a file
type FilePayloadPlugin struct {
	name        string
	description string
	attackTypes []string
	payloads    []Payload
	filePath    string
}

// Name returns the plugin name
func (p *FilePayloadPlugin) Name() string {
	return p.name
}

// Description returns the plugin description
func (p *FilePayloadPlugin) Description() string {
	return p.description
}

// AttackTypes returns the attack types this plugin handles
func (p *FilePayloadPlugin) AttackTypes() []string {
	return p.attackTypes
}

// Generate generates payloads
func (p *FilePayloadPlugin) Generate(ctx context.Context, endpoint types.Endpoint, param *types.Parameter) ([]Payload, error) {
	// Return all payloads (filtering can be done by the caller)
	return p.payloads, nil
}

// Priority returns the plugin priority
func (p *FilePayloadPlugin) Priority() int {
	return 0 // Default priority
}

// FileResponseMatcher is a matcher loaded from a file
type FileResponseMatcher struct {
	name        string
	description string
	patterns    []string
	severity    string
	confidence  string
	cwe         string
}

// Name returns the matcher name
func (m *FileResponseMatcher) Name() string {
	return m.name
}

// Description returns the matcher description
func (m *FileResponseMatcher) Description() string {
	return m.description
}

// Match checks if a response matches
func (m *FileResponseMatcher) Match(ctx context.Context, response *types.HTTPResponse, request *types.HTTPRequest) (*MatchResult, error) {
	if response == nil {
		return &MatchResult{Matched: false}, nil
	}

	for _, pattern := range m.patterns {
		if strings.Contains(response.Body, pattern) {
			return &MatchResult{
				Matched:     true,
				Severity:    m.severity,
				Confidence:  m.confidence,
				Title:       m.name,
				Description: m.description,
				Evidence:    []string{pattern},
				CWE:         m.cwe,
			}, nil
		}
	}

	return &MatchResult{Matched: false}, nil
}

// Priority returns the matcher priority
func (m *FileResponseMatcher) Priority() int {
	return 0
}

// Helper functions

func getExtension(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			return strings.ToLower(path[i+1:])
		}
		if path[i] == '/' || path[i] == '\\' {
			break
		}
	}
	return ""
}

func getBaseName(path string) string {
	// Get filename
	start := 0
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			start = i + 1
			break
		}
	}
	filename := path[start:]

	// Remove extension
	for i := len(filename) - 1; i >= 0; i-- {
		if filename[i] == '.' {
			return filename[:i]
		}
	}
	return filename
}

// LoadPlugins loads all plugins from config
func LoadPlugins(config PluginConfig) (*PluginRegistry, error) {
	registry := NewRegistry()

	if !config.Enabled {
		return registry, nil
	}

	loader := NewLoader(registry)

	// Load payload files
	for _, file := range config.PayloadFiles {
		if err := loader.LoadPayloadFile(file); err != nil {
			return nil, fmt.Errorf("failed to load payload file %s: %w", file, err)
		}
	}

	// Load matcher files
	for _, file := range config.MatcherFiles {
		if err := loader.LoadMatcherFile(file); err != nil {
			return nil, fmt.Errorf("failed to load matcher file %s: %w", file, err)
		}
	}

	return registry, nil
}
