// Package llm provides LLM provider implementations for AI-powered analysis
package llm

import (
	"sync"
	"time"
)

// UsageTracker tracks LLM API usage
type UsageTracker struct {
	mu    sync.Mutex
	stats UsageStats
}

// UsageStats holds usage statistics
type UsageStats struct {
	TotalRequests       int           `json:"total_requests"`
	SuccessfulRequests  int           `json:"successful_requests"`
	FailedRequests      int           `json:"failed_requests"`
	TotalPromptChars    int64         `json:"total_prompt_chars"`
	TotalResponseChars  int64         `json:"total_response_chars"`
	EstimatedTokens     int64         `json:"estimated_tokens"`
	AverageLatency      time.Duration `json:"average_latency"`
	TotalLatency        time.Duration `json:"total_latency"`
	RateLimitHits       int           `json:"rate_limit_hits"`
	StartTime           time.Time     `json:"start_time"`
	LastRequestTime     time.Time     `json:"last_request_time"`
}

// NewUsageTracker creates a new usage tracker
func NewUsageTracker() *UsageTracker {
	return &UsageTracker{
		stats: UsageStats{
			StartTime: time.Now(),
		},
	}
}

// RecordRequest records a successful request
func (u *UsageTracker) RecordRequest(promptSize, responseSize int) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.stats.TotalRequests++
	u.stats.SuccessfulRequests++
	u.stats.TotalPromptChars += int64(promptSize)
	u.stats.TotalResponseChars += int64(responseSize)
	u.stats.LastRequestTime = time.Now()

	// Estimate tokens (rough approximation: 4 chars per token)
	u.stats.EstimatedTokens += int64((promptSize + responseSize) / 4)
}

// RecordRequestWithLatency records a request with latency
func (u *UsageTracker) RecordRequestWithLatency(promptSize, responseSize int, latency time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.stats.TotalRequests++
	u.stats.SuccessfulRequests++
	u.stats.TotalPromptChars += int64(promptSize)
	u.stats.TotalResponseChars += int64(responseSize)
	u.stats.TotalLatency += latency
	u.stats.LastRequestTime = time.Now()

	// Calculate average latency
	if u.stats.SuccessfulRequests > 0 {
		u.stats.AverageLatency = u.stats.TotalLatency / time.Duration(u.stats.SuccessfulRequests)
	}

	// Estimate tokens
	u.stats.EstimatedTokens += int64((promptSize + responseSize) / 4)
}

// RecordFailure records a failed request
func (u *UsageTracker) RecordFailure() {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.stats.TotalRequests++
	u.stats.FailedRequests++
}

// RecordRateLimitHit records a rate limit hit
func (u *UsageTracker) RecordRateLimitHit() {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.stats.RateLimitHits++
}

// GetStats returns current usage statistics
func (u *UsageTracker) GetStats() *UsageStats {
	u.mu.Lock()
	defer u.mu.Unlock()

	// Return a copy
	stats := u.stats
	return &stats
}

// Reset resets usage statistics
func (u *UsageTracker) Reset() {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.stats = UsageStats{
		StartTime: time.Now(),
	}
}

// UsageBudget tracks usage against a budget
type UsageBudget struct {
	mu            sync.Mutex
	maxTokens     int64
	maxRequests   int
	currentTokens int64
	currentReqs   int
	exceeded      bool
}

// NewUsageBudget creates a usage budget
func NewUsageBudget(maxTokens int64, maxRequests int) *UsageBudget {
	return &UsageBudget{
		maxTokens:   maxTokens,
		maxRequests: maxRequests,
	}
}

// CanMakeRequest checks if a request can be made within budget
func (b *UsageBudget) CanMakeRequest(estimatedTokens int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.exceeded {
		return false
	}

	if b.maxRequests > 0 && b.currentReqs >= b.maxRequests {
		b.exceeded = true
		return false
	}

	if b.maxTokens > 0 && b.currentTokens+estimatedTokens > b.maxTokens {
		b.exceeded = true
		return false
	}

	return true
}

// RecordUsage records token usage
func (b *UsageBudget) RecordUsage(tokens int64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.currentTokens += tokens
	b.currentReqs++
}

// GetRemaining returns remaining budget
func (b *UsageBudget) GetRemaining() (tokens int64, requests int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	tokens = b.maxTokens - b.currentTokens
	if tokens < 0 {
		tokens = 0
	}

	requests = b.maxRequests - b.currentReqs
	if requests < 0 {
		requests = 0
	}

	return
}

// IsExceeded returns whether the budget has been exceeded
func (b *UsageBudget) IsExceeded() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exceeded
}

// CostEstimator estimates API costs
type CostEstimator struct {
	// Costs per 1M tokens (in USD cents)
	promptCost     float64
	completionCost float64
}

// ProviderCosts holds cost information for different providers
var ProviderCosts = map[string]*CostEstimator{
	"openai": {
		promptCost:     30,  // GPT-4 Turbo: $0.03/1K input
		completionCost: 60,  // GPT-4 Turbo: $0.06/1K output
	},
	"anthropic": {
		promptCost:     15,  // Claude 3 Sonnet: $0.015/1K input
		completionCost: 75,  // Claude 3 Sonnet: $0.075/1K output
	},
	"ollama": {
		promptCost:     0, // Free (local)
		completionCost: 0,
	},
	"lmstudio": {
		promptCost:     0, // Free (local)
		completionCost: 0,
	},
}

// NewCostEstimator creates a cost estimator for a provider
func NewCostEstimator(provider string) *CostEstimator {
	if costs, ok := ProviderCosts[provider]; ok {
		return costs
	}
	return &CostEstimator{}
}

// EstimateCost estimates the cost for given usage
func (c *CostEstimator) EstimateCost(stats *UsageStats) float64 {
	// Convert chars to estimated tokens (4 chars per token)
	promptTokens := float64(stats.TotalPromptChars) / 4
	completionTokens := float64(stats.TotalResponseChars) / 4

	// Calculate cost in cents, then convert to dollars
	promptCostCents := (promptTokens / 1000) * c.promptCost
	completionCostCents := (completionTokens / 1000) * c.completionCost

	return (promptCostCents + completionCostCents) / 100
}
