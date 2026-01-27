// Package types provides core data structures for Indago
package types

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Value   interface{}
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("config validation error: %s: %s (value: %v)", e.Field, e.Message, e.Value)
}

// ValidationErrors is a collection of validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("configuration validation failed:\n")
	for _, err := range e {
		sb.WriteString(fmt.Sprintf("  - %s: %s\n", err.Field, err.Message))
	}
	return sb.String()
}

// HasErrors returns true if there are any validation errors
func (e ValidationErrors) HasErrors() bool {
	return len(e) > 0
}

// ConfigValidator validates configuration settings
type ConfigValidator struct {
	errors ValidationErrors
}

// NewConfigValidator creates a new config validator
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{}
}

// Validate performs comprehensive validation of the config
func (v *ConfigValidator) Validate(config *Config) ValidationErrors {
	v.errors = nil

	v.validateScanSettings(config.Scan)
	v.validateHTTPSettings(config.HTTP)
	v.validateAttackSettings(config.Attacks)
	v.validateProviderSettings(config.Provider)
	v.validateOutputSettings(config.Output)
	v.validateChainSettings(config.Chains)
	v.validateDifferentialSettings(config.Differential)
	v.validateCallbackSettings(config.Callback)

	return v.errors
}

func (v *ConfigValidator) addError(field, message string, value interface{}) {
	v.errors = append(v.errors, ValidationError{
		Field:   field,
		Value:   value,
		Message: message,
	})
}

func (v *ConfigValidator) validateScanSettings(s ScanSettings) {
	if s.Concurrency < 1 {
		v.addError("scan.concurrency", "must be at least 1", s.Concurrency)
	}
	if s.Concurrency > 100 {
		v.addError("scan.concurrency", "should not exceed 100 to avoid overwhelming targets", s.Concurrency)
	}

	if s.RateLimit < 0 {
		v.addError("scan.rate_limit", "cannot be negative", s.RateLimit)
	}
	if s.RateLimit > 1000 {
		v.addError("scan.rate_limit", "extremely high rate limits may cause issues", s.RateLimit)
	}

	if s.Timeout < 1*time.Second {
		v.addError("scan.timeout", "should be at least 1 second", s.Timeout)
	}
	if s.Timeout > 5*time.Minute {
		v.addError("scan.timeout", "timeout exceeds 5 minutes which may cause issues", s.Timeout)
	}

	if s.MaxRetries < 0 {
		v.addError("scan.max_retries", "cannot be negative", s.MaxRetries)
	}
	if s.MaxRetries > 10 {
		v.addError("scan.max_retries", "excessive retries may slow down scans", s.MaxRetries)
	}

	if s.MaxRedirects < 0 {
		v.addError("scan.max_redirects", "cannot be negative", s.MaxRedirects)
	}
}

func (v *ConfigValidator) validateHTTPSettings(h HTTPSettings) {
	if h.ProxyURL != "" {
		if _, err := url.Parse(h.ProxyURL); err != nil {
			v.addError("http.proxy_url", "invalid URL format", h.ProxyURL)
		}
	}

	if h.UserAgent == "" {
		v.addError("http.user_agent", "should not be empty", h.UserAgent)
	}
}

func (v *ConfigValidator) validateAttackSettings(a AttackSettings) {
	if a.MaxPayloadsPerType < 0 {
		v.addError("attacks.max_payloads_per_type", "cannot be negative", a.MaxPayloadsPerType)
	}

	if a.LLMConcurrency < 1 && a.UseLLMPayloads {
		v.addError("attacks.llm_concurrency", "must be at least 1 when LLM payloads are enabled", a.LLMConcurrency)
	}

	if a.CustomPayloads != "" {
		if _, err := os.Stat(a.CustomPayloads); os.IsNotExist(err) {
			v.addError("attacks.custom_payloads", "file does not exist", a.CustomPayloads)
		}
	}

	// Validate attack type names
	validAttacks := map[string]bool{
		AttackIDOR: true, AttackSQLi: true, AttackNoSQLi: true,
		AttackCommandInject: true, AttackXSS: true, AttackAuthBypass: true,
		AttackMassAssignment: true, AttackBOLA: true, AttackBFLA: true,
		AttackRateLimit: true, AttackDataExposure: true, AttackSSRF: true,
		AttackPathTraversal: true, AttackLDAP: true, AttackXPath: true,
		AttackSSTI: true, AttackJWT: true,
	}

	for _, attack := range a.Enabled {
		if !validAttacks[attack] {
			v.addError("attacks.enabled", "unknown attack type", attack)
		}
	}

	for _, attack := range a.Disabled {
		if !validAttacks[attack] {
			v.addError("attacks.disabled", "unknown attack type", attack)
		}
	}
}

func (v *ConfigValidator) validateProviderSettings(p ProviderConfig) {
	if p.Name != "" {
		validProviders := map[string]bool{
			"openai": true, "anthropic": true, "ollama": true, "lmstudio": true,
		}
		if !validProviders[p.Name] {
			v.addError("provider.name", "unknown provider", p.Name)
		}

		// Check for required settings per provider
		switch p.Name {
		case "openai", "anthropic":
			if p.APIKey == "" {
				v.addError("provider.api_key", "required for "+p.Name, "")
			}
		case "ollama", "lmstudio":
			if p.BaseURL == "" {
				v.addError("provider.base_url", "required for local providers", "")
			}
		}
	}

	if p.MaxTokens < 0 {
		v.addError("provider.max_tokens", "cannot be negative", p.MaxTokens)
	}

	if p.Temperature < 0 || p.Temperature > 2 {
		v.addError("provider.temperature", "should be between 0 and 2", p.Temperature)
	}
}

func (v *ConfigValidator) validateOutputSettings(o OutputSettings) {
	validFormats := map[string]bool{
		"json": true, "html": true, "markdown": true,
		"sarif": true, "text": true, "burp": true,
	}

	if o.Format != "" && !validFormats[o.Format] {
		v.addError("output.format", "unknown format", o.Format)
	}
}

func (v *ConfigValidator) validateChainSettings(c ChainSettings) {
	if c.Enabled {
		if c.MaxDepth < 1 {
			v.addError("chains.max_depth", "must be at least 1 when chains are enabled", c.MaxDepth)
		}
		if c.MaxDepth > 20 {
			v.addError("chains.max_depth", "excessive depth may cause performance issues", c.MaxDepth)
		}

		if c.ChainFile != "" {
			if _, err := os.Stat(c.ChainFile); os.IsNotExist(err) {
				v.addError("chains.chain_file", "file does not exist", c.ChainFile)
			}
		}
	}
}

func (v *ConfigValidator) validateDifferentialSettings(d DifferentialSettings) {
	if d.Enabled && len(d.AuthContexts) == 0 && d.AuthFile == "" {
		v.addError("differential", "requires auth_contexts or auth_file when enabled", "")
	}

	if d.AuthFile != "" {
		if _, err := os.Stat(d.AuthFile); os.IsNotExist(err) {
			v.addError("differential.auth_file", "file does not exist", d.AuthFile)
		}
	}

	for i, ctx := range d.AuthContexts {
		if ctx.Name == "" {
			v.addError(fmt.Sprintf("differential.auth_contexts[%d].name", i), "name is required", "")
		}
		validAuthTypes := map[string]bool{
			"bearer": true, "cookie": true, "api_key": true, "basic": true, "": true,
		}
		if !validAuthTypes[ctx.AuthType] {
			v.addError(fmt.Sprintf("differential.auth_contexts[%d].auth_type", i), "unknown auth type", ctx.AuthType)
		}
	}
}

func (v *ConfigValidator) validateCallbackSettings(c CallbackSettings) {
	if c.Enabled {
		if c.HTTPPort < 1 || c.HTTPPort > 65535 {
			v.addError("callback.http_port", "must be a valid port (1-65535)", c.HTTPPort)
		}
		if c.DNSPort < 1 || c.DNSPort > 65535 {
			v.addError("callback.dns_port", "must be a valid port (1-65535)", c.DNSPort)
		}
		if c.ExternalURL != "" {
			if _, err := url.Parse(c.ExternalURL); err != nil {
				v.addError("callback.external_url", "invalid URL format", c.ExternalURL)
			}
		}
	}
}

// ValidateConfig is a convenience function to validate a config
func ValidateConfig(config *Config) error {
	validator := NewConfigValidator()
	errors := validator.Validate(config)
	if errors.HasErrors() {
		return errors
	}
	return nil
}

// ValidateInputFile validates an input file exists and is readable
func ValidateInputFile(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("input file does not exist: %s", path)
	}
	if err != nil {
		return fmt.Errorf("cannot access input file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("input path is a directory, not a file: %s", path)
	}
	return nil
}

// ValidateURL validates a URL string
func ValidateURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("URL cannot be empty")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if parsed.Scheme == "" {
		return fmt.Errorf("URL must have a scheme (http or https)")
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https, got: %s", parsed.Scheme)
	}

	if parsed.Host == "" {
		return fmt.Errorf("URL must have a host")
	}

	return nil
}
