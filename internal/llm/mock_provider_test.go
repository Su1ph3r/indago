package llm

import (
	"context"
	"errors"
	"testing"
)

func TestNewMockProvider(t *testing.T) {
	m := NewMockProvider()

	if m == nil {
		t.Fatal("NewMockProvider returned nil")
	}
	if m.Name() != "mock" {
		t.Errorf("Name() = %s, expected mock", m.Name())
	}
	if m.Model() != "mock-model" {
		t.Errorf("Model() = %s, expected mock-model", m.Model())
	}
}

func TestMockProvider_Analyze(t *testing.T) {
	m := NewMockProvider(
		WithDefaultResponse("default response"),
		WithResponse("specific prompt", "specific response"),
	)

	ctx := context.Background()

	// Test default response
	resp, err := m.Analyze(ctx, "some prompt")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if resp != "default response" {
		t.Errorf("response = %s, expected default response", resp)
	}

	// Test specific response
	resp, err = m.Analyze(ctx, "specific prompt")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if resp != "specific response" {
		t.Errorf("response = %s, expected specific response", resp)
	}

	// Verify call count
	if m.CallCount() != 2 {
		t.Errorf("CallCount() = %d, expected 2", m.CallCount())
	}
}

func TestMockProvider_AnalyzeWithError(t *testing.T) {
	expectedErr := errors.New("test error")
	m := NewMockProvider(WithError(expectedErr))

	ctx := context.Background()
	_, err := m.Analyze(ctx, "prompt")

	if err != expectedErr {
		t.Errorf("error = %v, expected %v", err, expectedErr)
	}
}

func TestMockProvider_AnalyzeStructured(t *testing.T) {
	type TestResponse struct {
		Value string `json:"value"`
		Count int    `json:"count"`
	}

	m := NewMockProvider(
		WithDefaultResponse(`{"value": "test", "count": 42}`),
	)

	ctx := context.Background()
	var result TestResponse

	err := m.AnalyzeStructured(ctx, "prompt", &result)
	if err != nil {
		t.Fatalf("AnalyzeStructured failed: %v", err)
	}

	if result.Value != "test" {
		t.Errorf("Value = %s, expected test", result.Value)
	}
	if result.Count != 42 {
		t.Errorf("Count = %d, expected 42", result.Count)
	}
}

func TestMockProvider_AnalyzeStructured_WithPresetResponse(t *testing.T) {
	type Payload struct {
		Value string `json:"value"`
		Type  string `json:"type"`
	}

	preset := []Payload{
		{Value: "payload1", Type: "sqli"},
		{Value: "payload2", Type: "xss"},
	}

	m := NewMockProvider(
		WithStructuredResponse(preset),
	)

	ctx := context.Background()
	var result []Payload

	err := m.AnalyzeStructured(ctx, "prompt", &result)
	if err != nil {
		t.Fatalf("AnalyzeStructured failed: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 payloads, got %d", len(result))
	}
	if result[0].Value != "payload1" {
		t.Errorf("result[0].Value = %s, expected payload1", result[0].Value)
	}
}

func TestMockProvider_AnalyzeWithSystem(t *testing.T) {
	m := NewMockProvider(
		WithDefaultResponse("system response"),
	)

	ctx := context.Background()
	resp, err := m.AnalyzeWithSystem(ctx, "system prompt", "user prompt")

	if err != nil {
		t.Fatalf("AnalyzeWithSystem failed: %v", err)
	}
	if resp != "system response" {
		t.Errorf("response = %s, expected system response", resp)
	}
}

func TestMockProvider_LastPrompt(t *testing.T) {
	m := NewMockProvider()

	ctx := context.Background()
	m.Analyze(ctx, "first prompt")
	m.Analyze(ctx, "second prompt")

	if m.LastPrompt() != "second prompt" {
		t.Errorf("LastPrompt() = %s, expected second prompt", m.LastPrompt())
	}
}

func TestMockProvider_Reset(t *testing.T) {
	m := NewMockProvider(WithError(errors.New("error")))

	ctx := context.Background()
	m.Analyze(ctx, "prompt")

	m.Reset()

	if m.CallCount() != 0 {
		t.Errorf("CallCount() after reset = %d, expected 0", m.CallCount())
	}
	if m.LastPrompt() != "" {
		t.Errorf("LastPrompt() after reset = %s, expected empty", m.LastPrompt())
	}

	// Error should be cleared
	resp, err := m.Analyze(ctx, "prompt")
	if err != nil {
		t.Errorf("should not have error after reset: %v", err)
	}
	if resp == "" {
		t.Error("should have response after reset")
	}
}

func TestMockProvider_SetMethods(t *testing.T) {
	m := NewMockProvider()

	m.SetResponse("prompt1", "response1")
	m.SetDefaultResponse("new default")
	m.SetError(errors.New("set error"))

	ctx := context.Background()

	// Test set error
	_, err := m.Analyze(ctx, "any")
	if err == nil {
		t.Error("expected error after SetError")
	}

	// Clear error and test responses
	m.SetError(nil)

	resp, _ := m.Analyze(ctx, "prompt1")
	if resp != "response1" {
		t.Errorf("response = %s, expected response1", resp)
	}

	resp, _ = m.Analyze(ctx, "unknown")
	if resp != "new default" {
		t.Errorf("response = %s, expected new default", resp)
	}
}

func TestMockProvider_ConcurrentAccess(t *testing.T) {
	m := NewMockProvider()

	ctx := context.Background()
	done := make(chan bool)

	// Run concurrent calls
	for i := 0; i < 10; i++ {
		go func() {
			m.Analyze(ctx, "prompt")
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	if m.CallCount() != 10 {
		t.Errorf("CallCount() = %d, expected 10", m.CallCount())
	}
}
