// Package payloads provides attack payload generation
package payloads

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/su1ph3r/indago/pkg/types"
)

const rateLimitBurstSize = 30

// authSensitivePaths are path segments that indicate auth-sensitive endpoints
// where missing rate limiting is high severity.
var authSensitivePaths = []string{
	"login", "signin", "sign-in", "auth", "authenticate",
	"password", "passwd", "reset", "forgot",
	"register", "signup", "sign-up",
	"token", "oauth", "otp", "verify", "confirm",
	"2fa", "mfa",
}

// RateLimitChecker sends rapid requests to detect missing rate limiting.
type RateLimitChecker struct{}

// NewRateLimitChecker creates a new rate limit checker.
func NewRateLimitChecker() *RateLimitChecker {
	return &RateLimitChecker{}
}

// Type returns the checker type.
func (c *RateLimitChecker) Type() string {
	return types.AttackRateLimitMissing
}

// Check sends a burst of requests and looks for rate-limit indicators.
func (c *RateLimitChecker) Check(ctx context.Context, endpoint types.Endpoint, client *http.Client) []types.Finding {
	url := endpoint.FullPath()
	if url == "" {
		return nil
	}

	var (
		found429  bool
		foundHdr  bool
		mu        sync.Mutex
		wg        sync.WaitGroup
	)

	for i := 0; i < rateLimitBurstSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			req, err := http.NewRequestWithContext(ctx, endpoint.Method, url, nil)
			if err != nil {
				return
			}

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()

			mu.Lock()
			defer mu.Unlock()

			if resp.StatusCode == 429 {
				found429 = true
			}
			if hasRateLimitHeaders(resp.Header) {
				foundHdr = true
			}
		}()
	}

	wg.Wait()

	if found429 || foundHdr {
		return nil // rate limiting is in place
	}

	severity := types.SeverityMedium
	if isAuthSensitive(endpoint.Path) {
		severity = types.SeverityHigh
	}

	return []types.Finding{
		{
			ID:          fmt.Sprintf("rlm-%s-%s", endpoint.Method, sanitizePath(endpoint.Path)),
			Type:        types.AttackRateLimitMissing,
			Severity:    severity,
			Confidence:  types.ConfidenceMedium,
			Title:       "No Rate Limiting Detected",
			Description: fmt.Sprintf("Sent %d rapid requests to %s %s with no 429 response or rate-limit headers", rateLimitBurstSize, endpoint.Method, endpoint.Path),
			Endpoint:    endpoint.Path,
			Method:      endpoint.Method,
			CWE:         "CWE-770",
			Remediation: "Implement rate limiting on this endpoint. Use 429 status codes and standard rate-limit headers (X-RateLimit-Limit, RateLimit-Remaining, Retry-After).",
			Timestamp:   time.Now(),
		},
	}
}

func hasRateLimitHeaders(h http.Header) bool {
	for key := range h {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "x-ratelimit") ||
			strings.HasPrefix(lower, "ratelimit") ||
			lower == "retry-after" {
			return true
		}
	}
	return false
}

func isAuthSensitive(path string) bool {
	lower := strings.ToLower(path)
	for _, seg := range authSensitivePaths {
		if strings.Contains(lower, seg) {
			return true
		}
	}
	return false
}

func sanitizePath(path string) string {
	r := strings.NewReplacer("/", "-", "{", "", "}", "", " ", "")
	return r.Replace(path)
}
