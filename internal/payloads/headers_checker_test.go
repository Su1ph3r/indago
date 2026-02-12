package payloads

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestSecurityHeaderChecker_AllMissing(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	checker := NewSecurityHeaderChecker()
	ep := types.Endpoint{Method: "GET", Path: "/api/data", BaseURL: ts.URL}

	findings := checker.Check(context.Background(), ep, ts.Client())

	if len(findings) != 1 {
		t.Fatalf("expected 1 aggregated finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Type != types.AttackMissingHeaders {
		t.Errorf("expected type %s, got %s", types.AttackMissingHeaders, f.Type)
	}
	if !strings.Contains(f.Description, "Strict-Transport-Security") {
		t.Error("expected HSTS in description")
	}
	if !strings.Contains(f.Description, "X-Content-Type-Options") {
		t.Error("expected X-Content-Type-Options in description")
	}
}

func TestSecurityHeaderChecker_AllPresent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(200)
	}))
	defer ts.Close()

	checker := NewSecurityHeaderChecker()
	ep := types.Endpoint{Method: "GET", Path: "/api/data", BaseURL: ts.URL}

	findings := checker.Check(context.Background(), ep, ts.Client())

	if len(findings) != 0 {
		t.Errorf("expected 0 findings when all headers present, got %d", len(findings))
	}
}

func TestSecurityHeaderChecker_AuthSensitiveMissingCacheControl(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// No Cache-Control: no-store on auth-sensitive endpoint
		w.WriteHeader(200)
	}))
	defer ts.Close()

	checker := NewSecurityHeaderChecker()
	ep := types.Endpoint{Method: "POST", Path: "/api/login", BaseURL: ts.URL}

	findings := checker.Check(context.Background(), ep, ts.Client())

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for missing Cache-Control on auth endpoint, got %d", len(findings))
	}
	if findings[0].Severity != types.SeverityMedium {
		t.Errorf("expected medium severity for missing Cache-Control on auth endpoint, got %s", findings[0].Severity)
	}
}

func TestSecurityHeaderChecker_AuthSensitiveWithCacheControl(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(200)
	}))
	defer ts.Close()

	checker := NewSecurityHeaderChecker()
	ep := types.Endpoint{Method: "POST", Path: "/api/login", BaseURL: ts.URL}

	findings := checker.Check(context.Background(), ep, ts.Client())

	if len(findings) != 0 {
		t.Errorf("expected 0 findings when all headers present on auth endpoint, got %d", len(findings))
	}
}
