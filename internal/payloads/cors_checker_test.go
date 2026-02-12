package payloads

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestCORSChecker_ReflectedOriginWithCredentials(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	checker := NewCORSChecker()
	ep := types.Endpoint{Method: "GET", Path: "/api/data", BaseURL: ts.URL}

	findings := checker.Check(context.Background(), ep, ts.Client())

	// Should find reflected origin + credentials for both evil-cors-test.com and null
	if len(findings) < 1 {
		t.Fatalf("expected at least 1 finding, got %d", len(findings))
	}

	foundHigh := false
	for _, f := range findings {
		if f.Severity == types.SeverityHigh {
			foundHigh = true
		}
		if f.Type != types.AttackCORSMisconfig {
			t.Errorf("expected type %s, got %s", types.AttackCORSMisconfig, f.Type)
		}
	}
	if !foundHigh {
		t.Error("expected at least one high-severity finding for reflected origin + credentials")
	}
}

func TestCORSChecker_WildcardOrigin(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
	}))
	defer ts.Close()

	checker := NewCORSChecker()
	ep := types.Endpoint{Method: "GET", Path: "/api/data", BaseURL: ts.URL}

	findings := checker.Check(context.Background(), ep, ts.Client())

	if len(findings) == 0 {
		t.Fatal("expected findings for wildcard CORS")
	}

	for _, f := range findings {
		if f.Severity != types.SeverityLow {
			t.Errorf("expected low severity for wildcard without credentials, got %s", f.Severity)
		}
	}
}

func TestCORSChecker_NoCORSHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	checker := NewCORSChecker()
	ep := types.Endpoint{Method: "GET", Path: "/api/data", BaseURL: ts.URL}

	findings := checker.Check(context.Background(), ep, ts.Client())

	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no CORS headers, got %d", len(findings))
	}
}

func TestCORSChecker_ReflectedWithoutCredentials(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	checker := NewCORSChecker()
	ep := types.Endpoint{Method: "GET", Path: "/api/data", BaseURL: ts.URL}

	findings := checker.Check(context.Background(), ep, ts.Client())

	if len(findings) == 0 {
		t.Fatal("expected findings for reflected origin")
	}

	for _, f := range findings {
		if f.Severity != types.SeverityMedium {
			t.Errorf("expected medium severity for reflected without credentials, got %s", f.Severity)
		}
	}
}
