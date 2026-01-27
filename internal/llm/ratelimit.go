// Package llm provides LLM provider implementations for AI-powered analysis
package llm

import (
	"context"
	"sync"
	"time"
)

// RateLimiter provides rate limiting for LLM API calls
type RateLimiter struct {
	mu           sync.Mutex
	tokens       float64
	maxTokens    float64
	refillRate   float64 // tokens per second
	lastRefill   time.Time
	minInterval  time.Duration
	lastCall     time.Time
	backoffUntil time.Time
	backoffCount int
}

// RateLimitConfig holds rate limiter configuration
type RateLimitConfig struct {
	RequestsPerMinute int           // Max requests per minute
	MinInterval       time.Duration // Minimum time between requests
	BurstSize         int           // Maximum burst size
}

// DefaultRateLimitConfigs returns default rate limits per provider
func DefaultRateLimitConfigs() map[string]*RateLimitConfig {
	return map[string]*RateLimitConfig{
		"openai": {
			RequestsPerMinute: 60,  // GPT-4 tier 1 limit
			MinInterval:       100 * time.Millisecond,
			BurstSize:         10,
		},
		"anthropic": {
			RequestsPerMinute: 60,  // Claude API limit
			MinInterval:       100 * time.Millisecond,
			BurstSize:         10,
		},
		"ollama": {
			RequestsPerMinute: 300, // Local, higher limit
			MinInterval:       10 * time.Millisecond,
			BurstSize:         50,
		},
		"lmstudio": {
			RequestsPerMinute: 300, // Local, higher limit
			MinInterval:       10 * time.Millisecond,
			BurstSize:         50,
		},
	}
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config *RateLimitConfig) *RateLimiter {
	if config == nil {
		config = &RateLimitConfig{
			RequestsPerMinute: 60,
			MinInterval:       100 * time.Millisecond,
			BurstSize:         10,
		}
	}

	return &RateLimiter{
		tokens:      float64(config.BurstSize),
		maxTokens:   float64(config.BurstSize),
		refillRate:  float64(config.RequestsPerMinute) / 60.0, // per second
		lastRefill:  time.Now(),
		minInterval: config.MinInterval,
	}
}

// Wait blocks until a request can be made
func (r *RateLimiter) Wait(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if we're in backoff
	if time.Now().Before(r.backoffUntil) {
		waitTime := time.Until(r.backoffUntil)
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			r.mu.Lock()
			return ctx.Err()
		case <-time.After(waitTime):
			r.mu.Lock()
		}
	}

	// Refill tokens
	r.refill()

	// Wait for token
	for r.tokens < 1 {
		// Calculate wait time for one token
		waitTime := time.Duration(float64(time.Second) / r.refillRate)

		r.mu.Unlock()
		select {
		case <-ctx.Done():
			r.mu.Lock()
			return ctx.Err()
		case <-time.After(waitTime):
			r.mu.Lock()
			r.refill()
		}
	}

	// Enforce minimum interval
	if elapsed := time.Since(r.lastCall); elapsed < r.minInterval {
		waitTime := r.minInterval - elapsed
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			r.mu.Lock()
			return ctx.Err()
		case <-time.After(waitTime):
			r.mu.Lock()
		}
	}

	// Consume token
	r.tokens--
	r.lastCall = time.Now()

	return nil
}

// refill adds tokens based on elapsed time
func (r *RateLimiter) refill() {
	now := time.Now()
	elapsed := now.Sub(r.lastRefill).Seconds()
	r.lastRefill = now

	r.tokens += elapsed * r.refillRate
	if r.tokens > r.maxTokens {
		r.tokens = r.maxTokens
	}
}

// OnRateLimitError handles a rate limit error from the API
func (r *RateLimiter) OnRateLimitError(retryAfter time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.backoffCount++

	// Calculate backoff time
	backoff := retryAfter
	if backoff == 0 {
		// Exponential backoff
		backoff = time.Duration(1<<r.backoffCount) * time.Second
		if backoff > 5*time.Minute {
			backoff = 5 * time.Minute
		}
	}

	r.backoffUntil = time.Now().Add(backoff)
	r.tokens = 0 // Drain tokens
}

// OnSuccess resets backoff count on successful request
func (r *RateLimiter) OnSuccess() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.backoffCount = 0
}

// RateLimitedProvider wraps a provider with rate limiting
type RateLimitedProvider struct {
	provider    Provider
	rateLimiter *RateLimiter
	usage       *UsageTracker
}

// NewRateLimitedProvider creates a rate-limited provider wrapper
func NewRateLimitedProvider(provider Provider, config *RateLimitConfig) *RateLimitedProvider {
	return &RateLimitedProvider{
		provider:    provider,
		rateLimiter: NewRateLimiter(config),
		usage:       NewUsageTracker(),
	}
}

// Analyze sends a prompt with rate limiting
func (p *RateLimitedProvider) Analyze(ctx context.Context, prompt string) (string, error) {
	if err := p.rateLimiter.Wait(ctx); err != nil {
		return "", err
	}

	response, err := p.provider.Analyze(ctx, prompt)
	if err != nil {
		if isRateLimitError(err) {
			p.rateLimiter.OnRateLimitError(0)
		}
		return "", err
	}

	p.rateLimiter.OnSuccess()
	p.usage.RecordRequest(len(prompt), len(response))

	return response, nil
}

// AnalyzeStructured sends a prompt with rate limiting
func (p *RateLimitedProvider) AnalyzeStructured(ctx context.Context, prompt string, result interface{}) error {
	if err := p.rateLimiter.Wait(ctx); err != nil {
		return err
	}

	err := p.provider.AnalyzeStructured(ctx, prompt, result)
	if err != nil {
		if isRateLimitError(err) {
			p.rateLimiter.OnRateLimitError(0)
		}
		return err
	}

	p.rateLimiter.OnSuccess()
	p.usage.RecordRequest(len(prompt), 0) // Unknown response size for structured

	return nil
}

// AnalyzeWithSystem sends a prompt with system message and rate limiting
func (p *RateLimitedProvider) AnalyzeWithSystem(ctx context.Context, system, prompt string) (string, error) {
	if err := p.rateLimiter.Wait(ctx); err != nil {
		return "", err
	}

	response, err := p.provider.AnalyzeWithSystem(ctx, system, prompt)
	if err != nil {
		if isRateLimitError(err) {
			p.rateLimiter.OnRateLimitError(0)
		}
		return "", err
	}

	p.rateLimiter.OnSuccess()
	p.usage.RecordRequest(len(system)+len(prompt), len(response))

	return response, nil
}

// Name returns the provider name
func (p *RateLimitedProvider) Name() string {
	return p.provider.Name()
}

// Model returns the model name
func (p *RateLimitedProvider) Model() string {
	return p.provider.Model()
}

// GetUsage returns usage statistics
func (p *RateLimitedProvider) GetUsage() *UsageStats {
	return p.usage.GetStats()
}

// isRateLimitError checks if an error is a rate limit error
func isRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	return err == ErrRateLimited ||
		containsString(err.Error(), "rate limit") ||
		containsString(err.Error(), "429") ||
		containsString(err.Error(), "too many requests")
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && findString(s, substr) >= 0
}

func findString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
