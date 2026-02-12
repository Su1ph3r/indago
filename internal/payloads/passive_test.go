package payloads

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

// stubChecker is a test PassiveChecker that returns canned findings.
type stubChecker struct {
	typeName string
	findings []types.Finding
}

func (s *stubChecker) Type() string { return s.typeName }
func (s *stubChecker) Check(_ context.Context, _ types.Endpoint, _ *http.Client) []types.Finding {
	return s.findings
}

func TestPassiveCheckRunner_RunAll(t *testing.T) {
	// Create a test server that always returns 200
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	endpoints := []types.Endpoint{
		{Method: "GET", Path: "/api/users", BaseURL: ts.URL},
		{Method: "POST", Path: "/api/login", BaseURL: ts.URL},
	}

	runner := NewPassiveCheckRunner()

	// Register checkers that return findings
	runner.Register(&stubChecker{
		typeName: "test_a",
		findings: []types.Finding{{Type: "test_a", Title: "Finding A"}},
	})
	runner.Register(&stubChecker{
		typeName: "test_b",
		findings: []types.Finding{{Type: "test_b", Title: "Finding B"}},
	})

	findings := runner.RunAll(context.Background(), endpoints, ts.Client())

	// 2 checkers * 2 endpoints = 4 findings
	if len(findings) != 4 {
		t.Errorf("expected 4 findings, got %d", len(findings))
	}
}

func TestPassiveCheckRunner_EmptyCheckers(t *testing.T) {
	runner := NewPassiveCheckRunner()
	endpoints := []types.Endpoint{
		{Method: "GET", Path: "/test", BaseURL: "http://localhost"},
	}

	findings := runner.RunAll(context.Background(), endpoints, http.DefaultClient)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings with no checkers, got %d", len(findings))
	}
}

func TestPassiveCheckRunner_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancel

	runner := NewPassiveCheckRunner()
	runner.Register(&stubChecker{
		typeName: "test",
		findings: []types.Finding{{Type: "test"}},
	})

	endpoints := []types.Endpoint{
		{Method: "GET", Path: "/test", BaseURL: "http://localhost"},
	}

	findings := runner.RunAll(ctx, endpoints, http.DefaultClient)
	// With cancelled context, we may get 0 findings
	if len(findings) > 1 {
		t.Errorf("expected 0 or 1 findings with cancelled context, got %d", len(findings))
	}
}
