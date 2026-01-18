package fuzzer

import (
	"context"
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

	return &RateLimiter{
		limiter: rate.NewLimiter(rate.Limit(requestsPerSecond), int(requestsPerSecond)),
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
	mu          sync.Mutex
	limiter     *RateLimiter
	baseRate    float64
	currentRate float64
	minRate     float64
	maxRate     float64
	errorCount  int
	successCount int
	windowSize  int
}

// NewAdaptiveRateLimiter creates an adaptive rate limiter
func NewAdaptiveRateLimiter(baseRate, minRate, maxRate float64) *AdaptiveRateLimiter {
	return &AdaptiveRateLimiter{
		limiter:     NewRateLimiter(baseRate),
		baseRate:    baseRate,
		currentRate: baseRate,
		minRate:     minRate,
		maxRate:     maxRate,
		windowSize:  100,
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
