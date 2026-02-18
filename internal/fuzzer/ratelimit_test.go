package fuzzer

import (
	"testing"
	"time"
)

func TestAdaptiveRateLimiter_RecordResponseHeaders_RetryAfterSeconds(t *testing.T) {
	arl := NewAdaptiveRateLimiter(10.0, 1.0, 20.0)
	initialRate := arl.CurrentRate()

	headers := map[string]string{
		"Retry-After": "30",
	}
	arl.RecordResponseHeaders(headers)

	if arl.CurrentRate() != arl.minRate {
		t.Errorf("expected rate to drop to minRate (%v) after Retry-After, got %v", arl.minRate, arl.CurrentRate())
	}
	if arl.CurrentRate() >= initialRate {
		t.Error("expected rate to decrease after Retry-After header")
	}
}

func TestAdaptiveRateLimiter_RecordResponseHeaders_RetryAfterHTTPDate(t *testing.T) {
	arl := NewAdaptiveRateLimiter(10.0, 1.0, 20.0)

	headers := map[string]string{
		"Retry-After": "Mon, 02 Jan 2006 15:04:05 GMT",
	}
	arl.RecordResponseHeaders(headers)

	if arl.CurrentRate() != arl.minRate {
		t.Errorf("expected rate to drop to minRate (%v) after Retry-After HTTP date, got %v", arl.minRate, arl.CurrentRate())
	}
}

func TestAdaptiveRateLimiter_RecordResponseHeaders_RetryAfterLowercase(t *testing.T) {
	arl := NewAdaptiveRateLimiter(10.0, 1.0, 20.0)

	headers := map[string]string{
		"retry-after": "60",
	}
	arl.RecordResponseHeaders(headers)

	if arl.CurrentRate() != arl.minRate {
		t.Errorf("expected rate to drop to minRate for lowercase retry-after, got %v", arl.CurrentRate())
	}
}

func TestAdaptiveRateLimiter_RecordResponseHeaders_RateLimitRemainingZero(t *testing.T) {
	arl := NewAdaptiveRateLimiter(10.0, 1.0, 20.0)
	initialRate := arl.CurrentRate()

	headers := map[string]string{
		"X-RateLimit-Remaining": "0",
	}
	arl.RecordResponseHeaders(headers)

	expectedRate := initialRate * 0.5
	if arl.CurrentRate() != expectedRate {
		t.Errorf("expected rate to halve to %v when remaining=0, got %v", expectedRate, arl.CurrentRate())
	}
}

func TestAdaptiveRateLimiter_RecordResponseHeaders_RateLimitRemainingLow(t *testing.T) {
	arl := NewAdaptiveRateLimiter(10.0, 1.0, 20.0)
	initialRate := arl.CurrentRate()

	headers := map[string]string{
		"X-RateLimit-Remaining": "2",
	}
	arl.RecordResponseHeaders(headers)

	expectedRate := initialRate * 0.5
	if arl.CurrentRate() != expectedRate {
		t.Errorf("expected rate to halve to %v when remaining<=2, got %v", expectedRate, arl.CurrentRate())
	}
}

func TestAdaptiveRateLimiter_RecordResponseHeaders_RateLimitRemainingHigh(t *testing.T) {
	arl := NewAdaptiveRateLimiter(10.0, 1.0, 20.0)
	initialRate := arl.CurrentRate()

	headers := map[string]string{
		"X-RateLimit-Remaining": "50",
	}
	arl.RecordResponseHeaders(headers)

	if arl.CurrentRate() != initialRate {
		t.Errorf("expected rate to remain at %v when remaining is high, got %v", initialRate, arl.CurrentRate())
	}
}

func TestAdaptiveRateLimiter_RecordResponseHeaders_RateLimitReset(t *testing.T) {
	arl := NewAdaptiveRateLimiter(10.0, 1.0, 20.0)

	headers := map[string]string{
		"X-RateLimit-Reset": "1700000000",
	}
	arl.RecordResponseHeaders(headers)

	arl.mu.Lock()
	reset := arl.rateLimitReset
	arl.mu.Unlock()

	if reset != 1700000000 {
		t.Errorf("expected rateLimitReset to be 1700000000, got %d", reset)
	}
}

func TestAdaptiveRateLimiter_RecordResponseHeaders_MinRateFloor(t *testing.T) {
	arl := NewAdaptiveRateLimiter(2.0, 1.0, 20.0)

	// Remaining=0 halves rate: 2.0 -> 1.0
	headers := map[string]string{
		"X-RateLimit-Remaining": "0",
	}
	arl.RecordResponseHeaders(headers)

	if arl.CurrentRate() != 1.0 {
		t.Errorf("expected rate at minRate 1.0, got %v", arl.CurrentRate())
	}

	// Calling again should not go below minRate
	arl.RecordResponseHeaders(headers)
	if arl.CurrentRate() != 1.0 {
		t.Errorf("expected rate to stay at minRate 1.0, got %v", arl.CurrentRate())
	}
}

func TestAdaptiveRateLimiter_RecordResponseTime(t *testing.T) {
	arl := NewAdaptiveRateLimiter(10.0, 1.0, 20.0)
	arl.SetBaselineResponseTime(100 * time.Millisecond)

	// Record 20 normal response times - no rate change expected
	for i := 0; i < 20; i++ {
		arl.RecordResponseTime(90 * time.Millisecond)
	}

	if arl.CurrentRate() != 10.0 {
		t.Errorf("expected rate to remain 10.0 with normal response times, got %v", arl.CurrentRate())
	}
}

func TestAdaptiveRateLimiter_RecordResponseTime_SlowDown(t *testing.T) {
	arl := NewAdaptiveRateLimiter(10.0, 1.0, 20.0)
	arl.SetBaselineResponseTime(100 * time.Millisecond)

	// Record enough slow responses to trigger throttling (p95 > 2x baseline)
	for i := 0; i < 20; i++ {
		arl.RecordResponseTime(250 * time.Millisecond)
	}

	if arl.CurrentRate() >= 10.0 {
		t.Errorf("expected rate to decrease with slow response times, got %v", arl.CurrentRate())
	}
}

func TestAdaptiveRateLimiter_RecordResponseTime_RingBuffer(t *testing.T) {
	arl := NewAdaptiveRateLimiter(10.0, 1.0, 20.0)
	arl.SetBaselineResponseTime(100 * time.Millisecond)

	// Fill beyond maxResponseTimes
	for i := 0; i < 150; i++ {
		arl.RecordResponseTime(50 * time.Millisecond)
	}

	arl.mu.Lock()
	count := len(arl.responseTimes)
	arl.mu.Unlock()

	if count > arl.maxResponseTimes {
		t.Errorf("expected responseTimes to be capped at %d, got %d", arl.maxResponseTimes, count)
	}
}

func TestAdaptiveRateLimiter_RecordResponseTime_NoBaseline(t *testing.T) {
	arl := NewAdaptiveRateLimiter(10.0, 1.0, 20.0)
	// No baseline set

	for i := 0; i < 20; i++ {
		arl.RecordResponseTime(500 * time.Millisecond)
	}

	// Should not adjust without baseline
	if arl.CurrentRate() != 10.0 {
		t.Errorf("expected rate to remain 10.0 without baseline, got %v", arl.CurrentRate())
	}
}

func TestAdaptiveRateLimiter_SetBaselineResponseTime(t *testing.T) {
	arl := NewAdaptiveRateLimiter(10.0, 1.0, 20.0)
	arl.SetBaselineResponseTime(200 * time.Millisecond)

	arl.mu.Lock()
	baseline := arl.baselineResponseTime
	arl.mu.Unlock()

	if baseline != 200*time.Millisecond {
		t.Errorf("expected baseline 200ms, got %v", baseline)
	}
}

func TestCalculateP95(t *testing.T) {
	t.Run("empty_slice", func(t *testing.T) {
		result := calculateP95(nil)
		if result != 0 {
			t.Errorf("expected 0 for empty slice, got %v", result)
		}
	})

	t.Run("single_element", func(t *testing.T) {
		result := calculateP95([]time.Duration{100 * time.Millisecond})
		if result != 100*time.Millisecond {
			t.Errorf("expected 100ms for single element, got %v", result)
		}
	})

	t.Run("uniform_values", func(t *testing.T) {
		times := make([]time.Duration, 100)
		for i := range times {
			times[i] = 50 * time.Millisecond
		}
		result := calculateP95(times)
		if result != 50*time.Millisecond {
			t.Errorf("expected 50ms for uniform values, got %v", result)
		}
	})

	t.Run("ascending_values", func(t *testing.T) {
		times := make([]time.Duration, 100)
		for i := range times {
			times[i] = time.Duration(i+1) * time.Millisecond
		}
		result := calculateP95(times)
		// p95 index = int(100*0.95) = 95, sorted[95] = 96ms (1-based values at 0-based index)
		expected := 96 * time.Millisecond
		if result != expected {
			t.Errorf("expected %v, got %v", expected, result)
		}
	})

	t.Run("does_not_modify_input", func(t *testing.T) {
		times := []time.Duration{300 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond}
		original := make([]time.Duration, len(times))
		copy(original, times)
		calculateP95(times)
		for i, v := range times {
			if v != original[i] {
				t.Errorf("input slice was modified at index %d: expected %v, got %v", i, original[i], v)
			}
		}
	})

	t.Run("outliers", func(t *testing.T) {
		times := make([]time.Duration, 100)
		for i := 0; i < 95; i++ {
			times[i] = 10 * time.Millisecond
		}
		for i := 95; i < 100; i++ {
			times[i] = 1000 * time.Millisecond
		}
		result := calculateP95(times)
		// p95 index = int(100*0.95) = 95, which is in the outlier range
		if result != 1000*time.Millisecond {
			t.Errorf("expected 1000ms at p95 with outliers, got %v", result)
		}
	})
}
