package fuzzer

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter controls request rate
type RateLimiter struct {
	limiter *rate.Limiter
	enabled bool
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(requestsPerSecond float64) *RateLimiter {
	if requestsPerSecond <= 0 {
		return &RateLimiter{enabled: false}
	}

	// Burst size allows a full second of requests to fire immediately,
	// with a minimum of 10 to avoid stalling at low rates.
	burst := int(requestsPerSecond)
	if burst < 10 {
		burst = 10
	}

	return &RateLimiter{
		limiter: rate.NewLimiter(rate.Limit(requestsPerSecond), burst),
		enabled: true,
	}
}

// Wait waits until a request can be made
func (r *RateLimiter) Wait(ctx context.Context) error {
	if !r.enabled {
		return nil
	}
	return r.limiter.Wait(ctx)
}

// Allow checks if a request is allowed
func (r *RateLimiter) Allow() bool {
	if !r.enabled {
		return true
	}
	return r.limiter.Allow()
}

// SetRate updates the rate limit
func (r *RateLimiter) SetRate(requestsPerSecond float64) {
	if requestsPerSecond <= 0 {
		r.enabled = false
		return
	}

	r.enabled = true
	if r.limiter == nil {
		r.limiter = rate.NewLimiter(rate.Limit(requestsPerSecond), int(requestsPerSecond))
	} else {
		r.limiter.SetLimit(rate.Limit(requestsPerSecond))
		r.limiter.SetBurst(int(requestsPerSecond))
	}
}

// AdaptiveRateLimiter adjusts rate based on response
type AdaptiveRateLimiter struct {
	mu                   sync.Mutex
	limiter              *RateLimiter
	baseRate             float64
	currentRate          float64
	minRate              float64
	maxRate              float64
	errorCount           int
	successCount         int
	windowSize           int
	responseTimes        []time.Duration
	baselineResponseTime time.Duration
	maxResponseTimes     int
	rateLimitReset       int64 // Unix timestamp from X-RateLimit-Reset
}

// NewAdaptiveRateLimiter creates an adaptive rate limiter
func NewAdaptiveRateLimiter(baseRate, minRate, maxRate float64) *AdaptiveRateLimiter {
	return &AdaptiveRateLimiter{
		limiter:          NewRateLimiter(baseRate),
		baseRate:         baseRate,
		currentRate:      baseRate,
		minRate:          minRate,
		maxRate:          maxRate,
		windowSize:       100,
		maxResponseTimes: 100,
	}
}

// Wait waits until a request can be made
func (a *AdaptiveRateLimiter) Wait(ctx context.Context) error {
	return a.limiter.Wait(ctx)
}

// RecordSuccess records a successful request
func (a *AdaptiveRateLimiter) RecordSuccess() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.successCount++
	a.maybeAdjustRate()
}

// RecordError records a failed request
func (a *AdaptiveRateLimiter) RecordError(statusCode int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.errorCount++

	// Immediately slow down for rate limit errors
	if statusCode == 429 {
		a.currentRate = a.currentRate * 0.5
		if a.currentRate < a.minRate {
			a.currentRate = a.minRate
		}
		a.limiter.SetRate(a.currentRate)
		a.errorCount = 0
		a.successCount = 0
	} else {
		a.maybeAdjustRate()
	}
}

// maybeAdjustRate adjusts rate based on recent results
func (a *AdaptiveRateLimiter) maybeAdjustRate() {
	total := a.errorCount + a.successCount
	if total < a.windowSize {
		return
	}

	errorRate := float64(a.errorCount) / float64(total)

	if errorRate > 0.2 {
		// Too many errors, slow down
		a.currentRate = a.currentRate * 0.8
		if a.currentRate < a.minRate {
			a.currentRate = a.minRate
		}
	} else if errorRate < 0.05 {
		// Very few errors, speed up
		a.currentRate = a.currentRate * 1.2
		if a.currentRate > a.maxRate {
			a.currentRate = a.maxRate
		}
	}

	a.limiter.SetRate(a.currentRate)
	a.errorCount = 0
	a.successCount = 0
}

// CurrentRate returns the current rate
func (a *AdaptiveRateLimiter) CurrentRate() float64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.currentRate
}

// RecordResponseHeaders parses rate-limit headers and adjusts rate accordingly
func (a *AdaptiveRateLimiter) RecordResponseHeaders(headers map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Parse Retry-After header (seconds or HTTP date)
	retryAfter := headers["Retry-After"]
	if retryAfter == "" {
		retryAfter = headers["retry-after"]
	}
	if retryAfter != "" {
		a.handleRetryAfter(retryAfter)
	}

	// Parse X-RateLimit-Reset (Unix timestamp)
	for _, key := range []string{"X-RateLimit-Reset", "x-ratelimit-reset"} {
		if resetStr, ok := headers[key]; ok && resetStr != "" {
			if ts, err := strconv.ParseInt(strings.TrimSpace(resetStr), 10, 64); err == nil {
				a.rateLimitReset = ts
			}
		}
	}

	// Parse X-RateLimit-Remaining
	remainStr := headers["X-RateLimit-Remaining"]
	if remainStr == "" {
		remainStr = headers["x-ratelimit-remaining"]
	}
	if remainStr != "" {
		if remaining, err := strconv.Atoi(strings.TrimSpace(remainStr)); err == nil {
			if remaining <= 2 {
				// Proactively reduce rate by 50%
				a.currentRate = a.currentRate * 0.5
				if a.currentRate < a.minRate {
					a.currentRate = a.minRate
				}
				a.limiter.SetRate(a.currentRate)
			}
		}
	}
}

// handleRetryAfter processes a Retry-After header value and reduces rate to minimum
func (a *AdaptiveRateLimiter) handleRetryAfter(value string) {
	value = strings.TrimSpace(value)
	// Try parsing as seconds first
	if _, err := strconv.Atoi(value); err == nil {
		a.currentRate = a.minRate
		a.limiter.SetRate(a.currentRate)
		return
	}
	// Try parsing as HTTP date (RFC1123)
	if _, err := http.ParseTime(value); err == nil {
		a.currentRate = a.minRate
		a.limiter.SetRate(a.currentRate)
	}
}

// RecordResponseTime records a response time and adjusts rate if p95 exceeds threshold
func (a *AdaptiveRateLimiter) RecordResponseTime(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Ring buffer: keep last maxResponseTimes entries
	if len(a.responseTimes) >= a.maxResponseTimes {
		newSlice := make([]time.Duration, len(a.responseTimes)-1, a.maxResponseTimes)
		copy(newSlice, a.responseTimes[1:])
		a.responseTimes = newSlice
	}
	a.responseTimes = append(a.responseTimes, d)

	// Need baseline and enough samples to make decisions
	if a.baselineResponseTime <= 0 || len(a.responseTimes) < 10 {
		return
	}

	p95 := calculateP95(a.responseTimes)
	if p95 > 2*a.baselineResponseTime {
		// Slow down by 20%
		a.currentRate = a.currentRate * 0.8
		if a.currentRate < a.minRate {
			a.currentRate = a.minRate
		}
		a.limiter.SetRate(a.currentRate)
	}
}

// SetBaselineResponseTime sets the baseline response time for adaptive throttling
func (a *AdaptiveRateLimiter) SetBaselineResponseTime(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.baselineResponseTime = d
}

// calculateP95 calculates the 95th percentile of a slice of durations
func calculateP95(times []time.Duration) time.Duration {
	if len(times) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(times))
	copy(sorted, times)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(float64(len(sorted)) * 0.95)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// TokenBucket implements a simple token bucket rate limiter
type TokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64
	lastRefill time.Time
}

// NewTokenBucket creates a new token bucket
func NewTokenBucket(maxTokens, refillRate float64) *TokenBucket {
	return &TokenBucket{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Take attempts to take n tokens, returns true if successful
func (tb *TokenBucket) Take(n float64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	if tb.tokens >= n {
		tb.tokens -= n
		return true
	}

	return false
}

// TakeWait waits until n tokens are available
func (tb *TokenBucket) TakeWait(ctx context.Context, n float64) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if tb.Take(n) {
			return nil
		}

		// Wait a bit before trying again
		time.Sleep(time.Duration(n/tb.refillRate*1000) * time.Millisecond)
	}
}

// refill refills tokens based on elapsed time
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.lastRefill = now

	tb.tokens += elapsed * tb.refillRate
	if tb.tokens > tb.maxTokens {
		tb.tokens = tb.maxTokens
	}
}
