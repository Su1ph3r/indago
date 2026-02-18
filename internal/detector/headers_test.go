package detector

import (
	"testing"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestSecurityHeaderDetector_AllMissing(t *testing.T) {
	d := NewSecurityHeaderDetector()
	resp := &types.HTTPResponse{
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "application/json"},
	}

	findings := d.Detect(resp, "GET", "/api/v1/users")
	if len(findings) != len(requiredSecurityHeaders) {
		t.Fatalf("expected %d findings, got %d", len(requiredSecurityHeaders), len(findings))
	}

	for _, f := range findings {
		if f.Type != types.AttackMissingHeaders {
			t.Errorf("expected type %q, got %q", types.AttackMissingHeaders, f.Type)
		}
		if f.Severity != types.SeverityLow {
			t.Errorf("expected severity %q, got %q", types.SeverityLow, f.Severity)
		}
		if f.Confidence != types.ConfidenceHigh {
			t.Errorf("expected confidence %q, got %q", types.ConfidenceHigh, f.Confidence)
		}
		if f.CWE == "" {
			t.Error("expected CWE to be set")
		}
		if f.Remediation == "" {
			t.Error("expected Remediation to be set")
		}
		if f.Method != "GET" {
			t.Errorf("expected method GET, got %q", f.Method)
		}
		if f.Endpoint != "/api/v1/users" {
			t.Errorf("expected endpoint /api/v1/users, got %q", f.Endpoint)
		}
	}
}

func TestSecurityHeaderDetector_AllPresent(t *testing.T) {
	d := NewSecurityHeaderDetector()
	resp := &types.HTTPResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Strict-Transport-Security": "max-age=63072000",
			"X-Content-Type-Options":    "nosniff",
			"X-Frame-Options":           "DENY",
			"Content-Security-Policy":   "default-src 'self'",
			"X-XSS-Protection":          "1; mode=block",
		},
	}

	findings := d.Detect(resp, "GET", "/api/v1/users")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when all headers present, got %d", len(findings))
	}
}

func TestSecurityHeaderDetector_CaseInsensitive(t *testing.T) {
	d := NewSecurityHeaderDetector()
	resp := &types.HTTPResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"strict-transport-security": "max-age=63072000",
			"x-content-type-options":    "nosniff",
			"x-frame-options":           "DENY",
			"content-security-policy":   "default-src 'self'",
			"x-xss-protection":          "1; mode=block",
		},
	}

	findings := d.Detect(resp, "GET", "/api/v1/lower")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings with lowercase header names, got %d", len(findings))
	}
}

func TestSecurityHeaderDetector_Deduplication(t *testing.T) {
	d := NewSecurityHeaderDetector()
	resp := &types.HTTPResponse{
		StatusCode: 200,
		Headers:    map[string]string{},
	}

	first := d.Detect(resp, "GET", "/api/v1/users")
	if len(first) == 0 {
		t.Fatal("expected findings on first call")
	}

	second := d.Detect(resp, "GET", "/api/v1/users")
	if len(second) != 0 {
		t.Fatalf("expected 0 findings on duplicate endpoint, got %d", len(second))
	}
}

func TestSecurityHeaderDetector_DifferentEndpoints(t *testing.T) {
	d := NewSecurityHeaderDetector()
	resp := &types.HTTPResponse{
		StatusCode: 200,
		Headers:    map[string]string{},
	}

	first := d.Detect(resp, "GET", "/api/v1/users")
	second := d.Detect(resp, "POST", "/api/v1/users")
	third := d.Detect(resp, "GET", "/api/v1/orders")

	if len(first) == 0 || len(second) == 0 || len(third) == 0 {
		t.Fatal("expected findings for each unique method:path combination")
	}
}

func TestSecurityHeaderDetector_MixedPresence(t *testing.T) {
	d := NewSecurityHeaderDetector()
	resp := &types.HTTPResponse{
		StatusCode: 200,
		Headers: map[string]string{
			"Strict-Transport-Security": "max-age=63072000",
			"X-Content-Type-Options":    "nosniff",
		},
	}

	findings := d.Detect(resp, "GET", "/api/v1/mixed")
	// Missing: X-Frame-Options, Content-Security-Policy, X-XSS-Protection
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings for 3 missing headers, got %d", len(findings))
	}

	titles := make(map[string]bool)
	for _, f := range findings {
		titles[f.Title] = true
	}
	expected := []string{
		"Missing Security Header: X-Frame-Options",
		"Missing Security Header: Content-Security-Policy",
		"Missing Security Header: X-XSS-Protection",
	}
	for _, e := range expected {
		if !titles[e] {
			t.Errorf("expected finding with title %q", e)
		}
	}
}

func TestSecurityHeaderDetector_NilResponse(t *testing.T) {
	d := NewSecurityHeaderDetector()
	findings := d.Detect(nil, "GET", "/api/v1/nil")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for nil response, got %d", len(findings))
	}
}

func TestSecurityHeaderDetector_Reset(t *testing.T) {
	d := NewSecurityHeaderDetector()
	resp := &types.HTTPResponse{
		StatusCode: 200,
		Headers:    map[string]string{},
	}

	first := d.Detect(resp, "GET", "/api/v1/users")
	if len(first) == 0 {
		t.Fatal("expected findings on first call")
	}

	d.Reset()

	afterReset := d.Detect(resp, "GET", "/api/v1/users")
	if len(afterReset) == 0 {
		t.Fatal("expected findings again after Reset()")
	}
	if len(afterReset) != len(first) {
		t.Fatalf("expected same number of findings after reset, got %d vs %d", len(first), len(afterReset))
	}
}
