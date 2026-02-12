package payloads

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestRateLimitChecker_NoRateLimit(t *testing.T) {
	var count int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&count, 1)
		w.WriteHeader(200)
	}))
	defer ts.Close()

	checker := NewRateLimitChecker()
	ep := types.Endpoint{Method: "GET", Path: "/api/data", BaseURL: ts.URL}

	findings := checker.Check(context.Background(), ep, ts.Client())

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (no rate limit), got %d", len(findings))
	}
	if findings[0].Type != types.AttackRateLimitMissing {
		t.Errorf("expected type %s, got %s", types.AttackRateLimitMissing, findings[0].Type)
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Errorf("expected medium severity for non-auth path, got %s", findings[0].Severity)
	}
}

func TestRateLimitChecker_NoRateLimit_AuthSensitive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	checker := NewRateLimitChecker()
	ep := types.Endpoint{Method: "POST", Path: "/api/login", BaseURL: ts.URL}

	findings := checker.Check(context.Background(), ep, ts.Client())

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("expected high severity for auth-sensitive path, got %s", findings[0].Severity)
	}
}

func TestRateLimitChecker_WithRateLimit429(t *testing.T) {
	var count int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&count, 1)
		if n > 10 {
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	checker := NewRateLimitChecker()
	ep := types.Endpoint{Method: "GET", Path: "/api/data", BaseURL: ts.URL}

	findings := checker.Check(context.Background(), ep, ts.Client())

	if len(findings) != 0 {
		t.Errorf("expected 0 findings (rate limit detected via 429), got %d", len(findings))
	}
}

func TestRateLimitChecker_WithRateLimitHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "100")
		w.Header().Set("X-RateLimit-Remaining", "99")
		w.WriteHeader(200)
	}))
	defer ts.Close()

	checker := NewRateLimitChecker()
	ep := types.Endpoint{Method: "GET", Path: "/api/data", BaseURL: ts.URL}

	findings := checker.Check(context.Background(), ep, ts.Client())

	if len(findings) != 0 {
		t.Errorf("expected 0 findings (rate limit headers present), got %d", len(findings))
	}
}

func TestRateLimitChecker_EmptyURL(t *testing.T) {
	checker := NewRateLimitChecker()
	ep := types.Endpoint{Method: "GET", Path: "", BaseURL: ""}

	findings := checker.Check(context.Background(), ep, http.DefaultClient)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty URL, got %d", len(findings))
	}
}
