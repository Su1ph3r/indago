// Package llm provides LLM provider implementations for AI-powered analysis
package llm

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/su1ph3r/indago/pkg/types"
)

// MockProvider is a mock LLM provider for testing
type MockProvider struct {
	BaseProvider
	mu            sync.Mutex
	responses     map[string]string // prompt -> response mapping
	defaultResp   string
	callCount     int
	lastPrompt    string
	errorOnCall   error
	structuredRes interface{}
}

// MockProviderOption is a function that configures a MockProvider
type MockProviderOption func(*MockProvider)

// NewMockProvider creates a new mock provider for testing
func NewMockProvider(opts ...MockProviderOption) *MockProvider {
	m := &MockProvider{
		BaseProvider: BaseProvider{
			config: types.ProviderConfig{
				Name:  "mock",
				Model: "mock-model",
			},
		},
		responses:   make(map[string]string),
		defaultResp: `{"result": "mock response"}`,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// WithResponse adds a specific response for a prompt
func WithResponse(prompt, response string) MockProviderOption {
	return func(m *MockProvider) {
		m.responses[prompt] = response
	}
}

// WithDefaultResponse sets the default response
func WithDefaultResponse(response string) MockProviderOption {
	return func(m *MockProvider) {
		m.defaultResp = response
	}
}

// WithError sets an error to return on calls
func WithError(err error) MockProviderOption {
	return func(m *MockProvider) {
		m.errorOnCall = err
	}
}

// WithStructuredResponse sets a pre-defined structured response
func WithStructuredResponse(resp interface{}) MockProviderOption {
	return func(m *MockProvider) {
		m.structuredRes = resp
	}
}

// Analyze sends a prompt and returns a mock response
func (m *MockProvider) Analyze(ctx context.Context, prompt string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callCount++
	m.lastPrompt = prompt

	if m.errorOnCall != nil {
		return "", m.errorOnCall
	}

	if resp, ok := m.responses[prompt]; ok {
		return resp, nil
	}

	return m.defaultResp, nil
}

// AnalyzeStructured sends a prompt and parses response into a struct
func (m *MockProvider) AnalyzeStructured(ctx context.Context, prompt string, result interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callCount++
	m.lastPrompt = prompt

	if m.errorOnCall != nil {
		return m.errorOnCall
	}

	// If we have a pre-set structured response, copy it
	if m.structuredRes != nil {
		data, err := json.Marshal(m.structuredRes)
		if err != nil {
			return err
		}
		return json.Unmarshal(data, result)
	}

	// Otherwise parse from response string
	resp := m.defaultResp
	if r, ok := m.responses[prompt]; ok {
		resp = r
	}

	return ParseJSONResponse(resp, result)
}

// AnalyzeWithSystem sends a prompt with a system message
func (m *MockProvider) AnalyzeWithSystem(ctx context.Context, system, prompt string) (string, error) {
	return m.Analyze(ctx, prompt)
}

// Name returns the provider name
func (m *MockProvider) Name() string {
	return "mock"
}

// Model returns the model name
func (m *MockProvider) Model() string {
	return "mock-model"
}

// CallCount returns the number of times the provider was called
func (m *MockProvider) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

// LastPrompt returns the last prompt received
func (m *MockProvider) LastPrompt() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastPrompt
}

// Reset resets the mock provider state
func (m *MockProvider) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount = 0
	m.lastPrompt = ""
	m.errorOnCall = nil
}

// SetResponse sets a response for a specific prompt
func (m *MockProvider) SetResponse(prompt, response string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses[prompt] = response
}

// SetDefaultResponse sets the default response
func (m *MockProvider) SetDefaultResponse(response string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.defaultResp = response
}

// SetError sets an error to return
func (m *MockProvider) SetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorOnCall = err
}
