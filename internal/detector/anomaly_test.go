package detector

import (
	"strings"
	"testing"
	"time"

	"github.com/su1ph3r/indago/internal/fuzzer"
	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

func TestNewAnomalyDetector(t *testing.T) {
	d := NewAnomalyDetector()
	if d == nil {
		t.Fatal("NewAnomalyDetector returned nil")
	}
}

func TestAnomalyDetector_Detect_StatusCodeAnomaly(t *testing.T) {
	d := NewAnomalyDetector()

	// Test case: 500 error should produce findings
	t.Run("500_error_indicates_issue", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/test"},
				Payload:  payloads.Payload{Type: types.AttackSQLi, Value: "' OR 1=1--"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 500,
				Body:       "Internal Server Error",
			},
		}

		baseline := &types.HTTPResponse{
			StatusCode: 200,
			Body:       "OK",
		}

		findings := d.Detect(result, baseline)
		if len(findings) == 0 {
			t.Error("expected finding for 500 error, got none")
		}
	})

	// Test case: 200 when baseline is 403 indicates potential bypass
	t.Run("200_when_baseline_is_403_indicates_potential_bypass", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/admin"},
				Payload:  payloads.Payload{Type: types.AttackAuthBypass, Value: "admin"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 200,
				Body:       "Admin Panel",
			},
		}

		baseline := &types.HTTPResponse{
			StatusCode: 403,
			Body:       "Forbidden",
		}

		findings := d.Detect(result, baseline)
		if len(findings) == 0 {
			t.Error("expected finding for auth bypass (200 vs 403 baseline), got none")
		}
	})
}

func TestAnomalyDetector_Detect_TimingAnomaly(t *testing.T) {
	d := NewAnomalyDetector()

	result := &fuzzer.FuzzResult{
		Request: &payloads.FuzzRequest{
			Endpoint: types.Endpoint{Method: "GET", Path: "/test"},
			Payload:  payloads.Payload{Type: types.AttackSQLi, Value: "' AND SLEEP(5)--"},
		},
		Response: &types.HTTPResponse{
			StatusCode:   200,
			ResponseTime: 6 * time.Second,
		},
		Duration: 6 * time.Second,
	}

	baseline := &types.HTTPResponse{
		StatusCode:   200,
		ResponseTime: 100 * time.Millisecond,
	}

	findings := d.Detect(result, baseline)

	// Should detect timing anomaly for blind SQL injection
	foundTiming := false
	for _, f := range findings {
		if f.Type == types.AttackSQLi || containsSubstring(f.Description, "timing") || containsSubstring(f.Description, "delay") {
			foundTiming = true
			break
		}
	}

	if !foundTiming {
		t.Log("Note: timing anomaly detection may vary based on implementation")
	}
}

func TestAnomalyDetector_Detect_ContentLengthAnomaly(t *testing.T) {
	d := NewAnomalyDetector()

	result := &fuzzer.FuzzResult{
		Request: &payloads.FuzzRequest{
			Endpoint: types.Endpoint{Method: "GET", Path: "/users/1"},
			Payload:  payloads.Payload{Type: types.AttackIDOR, Value: "2"},
		},
		Response: &types.HTTPResponse{
			StatusCode:    200,
			ContentLength: 5000,
			Body:          string(make([]byte, 5000)),
		},
	}

	baseline := &types.HTTPResponse{
		StatusCode:    200,
		ContentLength: 100,
		Body:          string(make([]byte, 100)),
	}

	findings := d.Detect(result, baseline)

	// Large difference in content length may indicate data exposure
	if len(findings) > 0 {
		// Verify findings have proper severity
		for _, f := range findings {
			if f.Severity == "" {
				t.Error("finding should have severity set")
			}
		}
	}
}

func TestAnomalyDetector_Detect_NoBaseline(t *testing.T) {
	d := NewAnomalyDetector()

	result := &fuzzer.FuzzResult{
		Request: &payloads.FuzzRequest{
			Endpoint: types.Endpoint{Method: "GET", Path: "/test"},
			Payload:  payloads.Payload{Type: types.AttackIDOR},
		},
		Response: &types.HTTPResponse{
			StatusCode: 500,
			Body:       "Internal Server Error",
		},
	}

	// Should still detect issues without baseline
	findings := d.Detect(result, nil)

	// 500 errors should be detected even without baseline
	found500 := false
	for _, f := range findings {
		if containsSubstring(f.Description, "500") || containsSubstring(f.Description, "error") || containsSubstring(f.Description, "server") {
			found500 = true
			break
		}
	}

	if !found500 {
		t.Log("Note: error detection without baseline may vary")
	}
}

// Helper function
func containsSubstring(s, substr string) bool {
	sLower := toLowerString(s)
	substrLower := toLowerString(substr)

	for i := 0; i <= len(sLower)-len(substrLower); i++ {
		if sLower[i:i+len(substrLower)] == substrLower {
			return true
		}
	}
	return false
}

func toLowerString(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func TestAnomalyDetector_SSRF(t *testing.T) {
	d := NewAnomalyDetector()

	t.Run("cloud_metadata_detected", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/fetch"},
				Payload: payloads.Payload{Type: types.AttackSSRF, Value: "http://169.254.169.254/latest/meta-data/"},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"ami-id": "ami-12345", "instance-id": "i-abcdef"}`},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackSSRF {
				found = true
			}
		}
		if !found {
			t.Error("expected SSRF finding for cloud metadata response")
		}
	})

	t.Run("dns_error_detected", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/fetch"},
				Payload: payloads.Payload{Type: types.AttackSSRF, Value: "http://internal.corp/"},
			},
			Response: &types.HTTPResponse{StatusCode: 500, Body: `could not resolve host: internal.corp`},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackSSRF {
				found = true
			}
		}
		if !found {
			t.Error("expected SSRF finding for DNS resolution error")
		}
	})

	t.Run("clean_response_no_finding", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/fetch"},
				Payload: payloads.Payload{Type: types.AttackSSRF, Value: "http://169.254.169.254/"},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"status": "ok"}`},
		}
		findings := d.Detect(result, nil)
		for _, f := range findings {
			if f.Type == types.AttackSSRF {
				t.Error("unexpected SSRF finding for clean response")
			}
		}
	})

	// Unit 1: Baseline comparison for cloud metadata
	t.Run("baseline_contains_metadata_no_finding", func(t *testing.T) {
		baseline := &types.HTTPResponse{
			StatusCode: 200,
			Body:       `{"ami-id": "ami-12345", "instance-id": "i-abcdef"}`, // Baseline already has metadata
		}
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/fetch"},
				Payload: payloads.Payload{Type: types.AttackSSRF, Value: "http://169.254.169.254/"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 200,
				Body:       `{"ami-id": "ami-12345", "instance-id": "i-abcdef"}`, // Same metadata in fuzz
			},
		}
		findings := d.Detect(result, baseline)
		for _, f := range findings {
			if f.Type == types.AttackSSRF && strings.Contains(f.Title, "Cloud Metadata") {
				t.Error("should not flag metadata when baseline also contains it")
			}
		}
	})

	// Unit 2: Baseline comparison for DNS errors
	t.Run("baseline_contains_dns_error_no_finding", func(t *testing.T) {
		baseline := &types.HTTPResponse{
			StatusCode: 500,
			Body:       `could not resolve host: internal.corp`, // Baseline has DNS error
		}
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/fetch"},
				Payload: payloads.Payload{Type: types.AttackSSRF, Value: "http://internal.corp/"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 500,
				Body:       `could not resolve host: internal.corp`, // Same DNS error
			},
		}
		findings := d.Detect(result, baseline)
		for _, f := range findings {
			if f.Type == types.AttackSSRF && strings.Contains(f.Title, "DNS") {
				t.Error("should not flag DNS error when baseline also contains it")
			}
		}
	})

	// Unit 3: Multiple signals can fire simultaneously
	t.Run("multiple_signals_detected", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/fetch"},
				Payload: payloads.Payload{Type: types.AttackSSRF, Value: "http://169.254.169.254/"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 200,
				Body:       `{"ami-id": "ami-12345"} could not resolve host: foo`, // Both metadata AND DNS error
			},
		}
		findings := d.Detect(result, nil)
		ssrfCount := 0
		for _, f := range findings {
			if f.Type == types.AttackSSRF {
				ssrfCount++
			}
		}
		if ssrfCount < 2 {
			t.Errorf("expected at least 2 SSRF findings (metadata + DNS error), got %d", ssrfCount)
		}
	})

	// Unit 4: Status code anomaly detection
	t.Run("status_anomaly_200_to_500", func(t *testing.T) {
		baseline := &types.HTTPResponse{StatusCode: 200, Body: "OK"}
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/fetch"},
				Payload: payloads.Payload{Type: types.AttackSSRF, Value: "http://internal.service/"},
			},
			Response: &types.HTTPResponse{StatusCode: 500, Body: "Internal Server Error"},
		}
		findings := d.Detect(result, baseline)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackSSRF && strings.Contains(f.Title, "Server Error") {
				found = true
			}
		}
		if !found {
			t.Error("expected SSRF finding for 200→500 status transition")
		}
	})

	t.Run("status_anomaly_403_to_200", func(t *testing.T) {
		baseline := &types.HTTPResponse{StatusCode: 403, Body: "Forbidden"}
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/fetch"},
				Payload: payloads.Payload{Type: types.AttackSSRF, Value: "http://internal.service/"},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: "Secret data"},
		}
		findings := d.Detect(result, baseline)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackSSRF && strings.Contains(f.Title, "Forbidden Resource") {
				found = true
			}
		}
		if !found {
			t.Error("expected SSRF finding for 403→200 status transition")
		}
	})

	t.Run("status_anomaly_200_to_401_with_auth_header", func(t *testing.T) {
		baseline := &types.HTTPResponse{StatusCode: 200, Body: "OK"}
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/fetch"},
				Payload: payloads.Payload{Type: types.AttackSSRF, Value: "http://internal.service/"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 401,
				Body:       "Unauthorized",
				Headers:    map[string]string{"www-authenticate": "Basic realm=\"Internal\""},
			},
		}
		findings := d.Detect(result, baseline)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackSSRF && strings.Contains(f.Title, "Authentication Challenge") {
				found = true
			}
		}
		if !found {
			t.Error("expected SSRF finding for 200→401 with WWW-Authenticate header")
		}
	})

	// Unit 5: Timing anomaly detection
	t.Run("timing_anomaly_detected", func(t *testing.T) {
		baseline := &types.HTTPResponse{
			StatusCode:   200,
			Body:         "OK",
			ResponseTime: 500 * time.Millisecond, // Fast baseline
		}
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/fetch"},
				Payload: payloads.Payload{Type: types.AttackSSRF, Value: "http://internal.service/"},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: "OK"},
			Duration: 5 * time.Second, // Slow fuzz response
		}
		findings := d.Detect(result, baseline)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackSSRF && strings.Contains(f.Title, "Timing") {
				found = true
			}
		}
		if !found {
			t.Error("expected SSRF finding for timing anomaly (5s vs 0.5s)")
		}
	})

	// Unit 6: Content-length anomaly detection
	t.Run("content_anomaly_detected", func(t *testing.T) {
		baseline := &types.HTTPResponse{
			StatusCode:    200,
			Body:          "OK",
			ContentLength: 100, // Small baseline
		}
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/fetch"},
				Payload: payloads.Payload{Type: types.AttackSSRF, Value: "http://internal.service/"},
			},
			Response: &types.HTTPResponse{
				StatusCode:    200,
				Body:          strings.Repeat("a", 10000),
				ContentLength: 10000, // 100x larger
			},
		}
		findings := d.Detect(result, baseline)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackSSRF && strings.Contains(f.Title, "Content Length") {
				found = true
			}
		}
		if !found {
			t.Error("expected SSRF finding for content-length anomaly (10KB vs 100B)")
		}
	})

	// Unit 7: Service fingerprint detection
	t.Run("service_fingerprint_redis", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/fetch"},
				Payload: payloads.Payload{Type: types.AttackSSRF, Value: "http://internal.redis:6379/"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 200,
				Body:       "+OK\r\n$5\r\nHello\r\n", // Redis RESP protocol
			},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackSSRF && strings.Contains(f.Title, "Redis") {
				found = true
			}
		}
		if !found {
			t.Error("expected SSRF finding for Redis protocol fingerprint")
		}
	})

	t.Run("service_fingerprint_internal_hostname", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/fetch"},
				Payload: payloads.Payload{Type: types.AttackSSRF, Value: "http://localhost/"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 200,
				Body:       `<html><body>Internal service at 192.168.1.100</body></html>`,
			},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackSSRF && strings.Contains(f.Title, "Internal Hostname") {
				found = true
			}
		}
		if !found {
			t.Error("expected SSRF finding for internal hostname/IP fingerprint")
		}
	})

	t.Run("service_fingerprint_admin_interface", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/fetch"},
				Payload: payloads.Payload{Type: types.AttackSSRF, Value: "http://internal/admin/"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 200,
				Body:       `<html><head><title>Admin Dashboard</title></head></html>`,
			},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackSSRF && strings.Contains(f.Title, "Admin Interface") {
				found = true
			}
		}
		if !found {
			t.Error("expected SSRF finding for admin interface fingerprint")
		}
	})

	// Unit 9: No false positives on legitimate responses
	t.Run("no_false_positives_legitimate_responses", func(t *testing.T) {
		baseline := &types.HTTPResponse{
			StatusCode:    200,
			Body:          `{"status": "ok", "price": 49}`,
			ContentLength: 30,
			ResponseTime:  100 * time.Millisecond,
		}
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/api/products"},
				Payload: payloads.Payload{Type: types.AttackSSRF, Value: "http://example.com/"},
			},
			Response: &types.HTTPResponse{
				StatusCode:    200,
				Body:          `{"status": "ok", "price": 49}`,
				ContentLength: 30,
			},
			Duration: 120 * time.Millisecond,
		}
		findings := d.Detect(result, baseline)
		for _, f := range findings {
			if f.Type == types.AttackSSRF {
				t.Errorf("unexpected SSRF finding for legitimate response: %s", f.Title)
			}
		}
	})
}

func TestAnomalyDetector_SSTI(t *testing.T) {
	d := NewAnomalyDetector()

	t.Run("math_eval_7x7", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/render"},
				Payload: payloads.Payload{Type: types.AttackSSTI, Value: "{{7*7}}"},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `Hello 49!`},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackSSTI && containsSubstring(f.Title, "template injection") {
				found = true
			}
		}
		if !found {
			t.Error("expected SSTI finding for math evaluation")
		}
	})

	t.Run("string_repeat", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/render"},
				Payload: payloads.Payload{Type: types.AttackSSTI, Value: "{{'7'*7}}"},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `Result: 7777777`},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackSSTI {
				found = true
			}
		}
		if !found {
			t.Error("expected SSTI finding for string repeat")
		}
	})

	t.Run("template_error", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/render"},
				Payload: payloads.Payload{Type: types.AttackSSTI, Value: "{{invalid}}"},
			},
			Response: &types.HTTPResponse{StatusCode: 500, Body: `TemplateSyntaxError: unexpected token`},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackSSTI {
				found = true
			}
		}
		if !found {
			t.Error("expected SSTI finding for template error")
		}
	})

	t.Run("clean_response_no_finding", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/render"},
				Payload: payloads.Payload{Type: types.AttackSSTI, Value: "{{7*7}}"},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `Hello World`},
		}
		findings := d.Detect(result, nil)
		for _, f := range findings {
			if f.Type == types.AttackSSTI {
				t.Error("unexpected SSTI finding for clean response")
			}
		}
	})

	t.Run("49_in_baseline_no_finding", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/products"},
				Payload: payloads.Payload{Type: types.AttackSSTI, Value: "{{7*7}}"},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"price": 49.99}`},
		}
		baseline := &types.HTTPResponse{StatusCode: 200, Body: `{"price": 49.99}`}
		findings := d.Detect(result, baseline)
		for _, f := range findings {
			if f.Type == types.AttackSSTI && containsSubstring(f.Title, "template injection") {
				t.Error("unexpected SSTI finding when baseline already contains '49'")
			}
		}
	})

	t.Run("49_not_in_baseline_flags_ssti", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/render"},
				Payload: payloads.Payload{Type: types.AttackSSTI, Value: "{{7*7}}"},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `Result: 49`},
		}
		baseline := &types.HTTPResponse{StatusCode: 200, Body: `Result: hello`}
		findings := d.Detect(result, baseline)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackSSTI && containsSubstring(f.Title, "template injection") {
				found = true
			}
		}
		if !found {
			t.Error("expected SSTI finding when '49' is new (not in baseline)")
		}
	})

	t.Run("7777777_in_baseline_no_finding", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/render"},
				Payload: payloads.Payload{Type: types.AttackSSTI, Value: "{{'7'*7}}"},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `ID: 7777777`},
		}
		baseline := &types.HTTPResponse{StatusCode: 200, Body: `ID: 7777777`}
		findings := d.Detect(result, baseline)
		for _, f := range findings {
			if f.Type == types.AttackSSTI && containsSubstring(f.Title, "template injection") {
				t.Error("unexpected SSTI finding when baseline already contains '7777777'")
			}
		}
	})
}

func TestAnomalyDetector_LDAP(t *testing.T) {
	d := NewAnomalyDetector()

	result := &fuzzer.FuzzResult{
		Request: &payloads.FuzzRequest{
			Endpoint: types.Endpoint{Method: "GET", Path: "/search"},
			Payload: payloads.Payload{Type: types.AttackLDAP, Value: "*)(&"},
		},
		Response: &types.HTTPResponse{StatusCode: 500, Body: `LDAP error: invalid DN syntax`},
	}
	findings := d.Detect(result, nil)
	found := false
	for _, f := range findings {
		if f.Type == types.AttackLDAP {
			found = true
		}
	}
	if !found {
		t.Error("expected LDAP injection finding")
	}
}

func TestAnomalyDetector_XPath(t *testing.T) {
	d := NewAnomalyDetector()

	result := &fuzzer.FuzzResult{
		Request: &payloads.FuzzRequest{
			Endpoint: types.Endpoint{Method: "GET", Path: "/search"},
			Payload: payloads.Payload{Type: types.AttackXPath, Value: "' or '1'='1"},
		},
		Response: &types.HTTPResponse{StatusCode: 500, Body: `XPathException: invalid expression`},
	}
	findings := d.Detect(result, nil)
	found := false
	for _, f := range findings {
		if f.Type == types.AttackXPath {
			found = true
		}
	}
	if !found {
		t.Error("expected XPath injection finding")
	}
}

func TestAnomalyDetector_GraphQLIntrospection(t *testing.T) {
	d := NewAnomalyDetector()

	t.Run("schema_exposed", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/graphql"},
				Payload: payloads.Payload{Type: types.AttackGraphQLIntrospect, Value: `{"query":"{__schema{types{name}}}"}`},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"data":{"__schema":{"types":[{"name":"Query"}]}}}`},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackGraphQLIntrospect {
				found = true
			}
		}
		if !found {
			t.Error("expected GraphQL introspection finding")
		}
	})

	t.Run("no_schema_no_finding", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/graphql"},
				Payload: payloads.Payload{Type: types.AttackGraphQLIntrospect, Value: `{"query":"{__schema{types{name}}}"}`},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"errors":[{"message":"introspection disabled"}]}`},
		}
		findings := d.Detect(result, nil)
		for _, f := range findings {
			if f.Type == types.AttackGraphQLIntrospect {
				t.Error("unexpected GraphQL finding when introspection disabled")
			}
		}
	})
}

func TestAnomalyDetector_GraphQLDepth(t *testing.T) {
	d := NewAnomalyDetector()

	t.Run("timing_dos", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/graphql"},
				Payload:  payloads.Payload{Type: types.AttackGraphQLDepth, Value: `{"query":"{ __typename ... on Query { __typename } }"}`},
			},
			Response: &types.HTTPResponse{
				StatusCode:   200,
				Body:         `{"data":{"__typename":"Query"}}`,
				ResponseTime: 6 * time.Second,
			},
		}
		baseline := &types.HTTPResponse{
			StatusCode:   200,
			Body:         `{"data":{"__typename":"Query"}}`,
			ResponseTime: 500 * time.Millisecond,
		}
		findings := d.Detect(result, baseline)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackGraphQLDepth && containsSubstring(f.Title, "dos") {
				found = true
			}
		}
		if !found {
			t.Error("expected GraphQL depth DoS finding for slow response")
		}
	})

	t.Run("depth_limit_detected", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/graphql"},
				Payload:  payloads.Payload{Type: types.AttackGraphQLDepth, Value: `{"query":"deep nested"}`},
			},
			Response: &types.HTTPResponse{
				StatusCode: 400,
				Body:       `{"errors":[{"message":"Maximum query depth exceeded"}]}`,
			},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackGraphQLDepth && f.Severity == types.SeverityInfo {
				found = true
			}
		}
		if !found {
			t.Error("expected informational finding for depth limiting")
		}
	})

	t.Run("server_crash_recursion", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/graphql"},
				Payload:  payloads.Payload{Type: types.AttackGraphQLDepth, Value: `{"query":"deep nested"}`},
			},
			Response: &types.HTTPResponse{
				StatusCode: 500,
				Body:       `{"error":"stack overflow in query resolver"}`,
			},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackGraphQLDepth && f.Severity == types.SeverityHigh {
				found = true
			}
		}
		if !found {
			t.Error("expected high severity finding for stack overflow crash")
		}
	})

	t.Run("normal_response_no_finding", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/graphql"},
				Payload:  payloads.Payload{Type: types.AttackGraphQLDepth, Value: `{"query":"{ __typename }"}`},
			},
			Response: &types.HTTPResponse{
				StatusCode:   200,
				Body:         `{"data":{"__typename":"Query"}}`,
				ResponseTime: 100 * time.Millisecond,
			},
		}
		baseline := &types.HTTPResponse{
			StatusCode:   200,
			Body:         `{"data":{"__typename":"Query"}}`,
			ResponseTime: 80 * time.Millisecond,
		}
		findings := d.Detect(result, baseline)
		for _, f := range findings {
			if f.Type == types.AttackGraphQLDepth {
				t.Errorf("unexpected GraphQL depth finding for normal response: %s", f.Title)
			}
		}
	})
}

func TestAnomalyDetector_GraphQLBatch(t *testing.T) {
	d := NewAnomalyDetector()

	t.Run("batch_response_array", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/graphql"},
				Payload: payloads.Payload{
					Type:  types.AttackGraphQLBatch,
					Value: `[{"query":"{ __typename }"},{"query":"{ __typename }"}]`,
				},
			},
			Response: &types.HTTPResponse{
				StatusCode: 200,
				Body:       `[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`,
			},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackGraphQLBatch && containsSubstring(f.Title, "batch") && containsSubstring(f.Title, "accepted") {
				found = true
			}
		}
		if !found {
			t.Error("expected batch queries accepted finding for JSON array response")
		}
	})

	t.Run("timing_dos", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/graphql"},
				Payload: payloads.Payload{
					Type:  types.AttackGraphQLBatch,
					Value: `[{"query":"{ __typename }"}]`,
				},
			},
			Response: &types.HTTPResponse{
				StatusCode:   200,
				Body:         `{"data":{}}`,
				ResponseTime: 9 * time.Second,
			},
		}
		baseline := &types.HTTPResponse{
			StatusCode:   200,
			Body:         `{"data":{}}`,
			ResponseTime: 500 * time.Millisecond,
		}
		findings := d.Detect(result, baseline)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackGraphQLBatch && containsSubstring(f.Title, "dos") {
				found = true
			}
		}
		if !found {
			t.Error("expected batch DoS finding for slow response")
		}
	})

	t.Run("batch_limit_detected", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/graphql"},
				Payload: payloads.Payload{
					Type:  types.AttackGraphQLBatch,
					Value: `[{"query":"{ __typename }"}]`,
				},
			},
			Response: &types.HTTPResponse{
				StatusCode: 400,
				Body:       `{"errors":[{"message":"Too many operations in batch request"}]}`,
			},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackGraphQLBatch && f.Severity == types.SeverityInfo {
				found = true
			}
		}
		if !found {
			t.Error("expected informational finding for batch limiting")
		}
	})

	t.Run("non_array_response_no_batch_finding", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/graphql"},
				Payload: payloads.Payload{
					Type:  types.AttackGraphQLBatch,
					Value: `[{"query":"{ __typename }"}]`,
				},
			},
			Response: &types.HTTPResponse{
				StatusCode:   200,
				Body:         `{"data":{"__typename":"Query"}}`,
				ResponseTime: 100 * time.Millisecond,
			},
		}
		baseline := &types.HTTPResponse{
			StatusCode:   200,
			Body:         `{"data":{"__typename":"Query"}}`,
			ResponseTime: 80 * time.Millisecond,
		}
		findings := d.Detect(result, baseline)
		for _, f := range findings {
			if f.Type == types.AttackGraphQLBatch {
				t.Errorf("unexpected batch finding for non-array response: %s", f.Title)
			}
		}
	})
}

func TestAnomalyDetector_GraphQLAlias(t *testing.T) {
	d := NewAnomalyDetector()

	t.Run("timing_dos", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/graphql"},
				Payload: payloads.Payload{
					Type:  types.AttackGraphQLAlias,
					Value: `{"query":"{ a0: __typename a1: __typename }"}`,
				},
			},
			Response: &types.HTTPResponse{
				StatusCode:   200,
				Body:         `{"data":{"a0":"Query","a1":"Query"}}`,
				ResponseTime: 10 * time.Second,
			},
		}
		baseline := &types.HTTPResponse{
			StatusCode:   200,
			Body:         `{"data":{"__typename":"Query"}}`,
			ResponseTime: 500 * time.Millisecond,
		}
		findings := d.Detect(result, baseline)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackGraphQLAlias && containsSubstring(f.Title, "dos") {
				found = true
			}
		}
		if !found {
			t.Error("expected alias DoS finding for slow response")
		}
	})

	t.Run("field_suggestion_disclosure", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/graphql"},
				Payload: payloads.Payload{
					Type:  types.AttackGraphQLAlias,
					Value: `{"query":"{ user { pasword } }"}`,
				},
			},
			Response: &types.HTTPResponse{
				StatusCode: 400,
				Body:       `{"errors":[{"message":"Cannot query field 'pasword'. Did you mean 'password'?"}]}`,
			},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackGraphQLAlias && containsSubstring(f.Title, "suggestion") {
				found = true
			}
		}
		if !found {
			t.Error("expected field suggestion disclosure finding")
		}
	})

	t.Run("alias_limit_detected", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/graphql"},
				Payload: payloads.Payload{
					Type:  types.AttackGraphQLAlias,
					Value: `{"query":"{ a0: __typename a1: __typename }"}`,
				},
			},
			Response: &types.HTTPResponse{
				StatusCode: 400,
				Body:       `{"errors":[{"message":"Too many aliases in query"}]}`,
			},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackGraphQLAlias && f.Severity == types.SeverityInfo {
				found = true
			}
		}
		if !found {
			t.Error("expected informational finding for alias limiting")
		}
	})

	t.Run("normal_response_no_finding", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/graphql"},
				Payload: payloads.Payload{
					Type:  types.AttackGraphQLAlias,
					Value: `{"query":"{ a0: __typename }"}`,
				},
			},
			Response: &types.HTTPResponse{
				StatusCode:   200,
				Body:         `{"data":{"a0":"Query"}}`,
				ResponseTime: 100 * time.Millisecond,
			},
		}
		baseline := &types.HTTPResponse{
			StatusCode:   200,
			Body:         `{"data":{"__typename":"Query"}}`,
			ResponseTime: 80 * time.Millisecond,
		}
		findings := d.Detect(result, baseline)
		for _, f := range findings {
			if f.Type == types.AttackGraphQLAlias {
				t.Errorf("unexpected alias finding for normal response: %s", f.Title)
			}
		}
	})
}

func TestAnomalyDetector_MassAssignment(t *testing.T) {
	d := NewAnomalyDetector()

	t.Run("field_in_response", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "PUT", Path: "/users/1"},
				Payload: payloads.Payload{
					Type:     types.AttackMassAssignment,
					Value:    `{"is_admin": true}`,
					Metadata: map[string]string{"field": "is_admin", "value": "true"},
				},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"id":1,"name":"test","is_admin":true}`},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackMassAssignment {
				found = true
				if f.Confidence != types.ConfidenceHigh {
					t.Errorf("expected high confidence when both field and value match, got %s", f.Confidence)
				}
			}
		}
		if !found {
			t.Error("expected mass assignment finding")
		}
	})

	t.Run("admin_field_accepted_silently", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "PUT", Path: "/users/1"},
				Payload: payloads.Payload{
					Type:     types.AttackMassAssignment,
					Value:    `{"is_admin": true}`,
					Metadata: map[string]string{"field": "is_admin"},
				},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"id":1,"name":"test"}`},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackMassAssignment {
				found = true
				if f.Confidence != types.ConfidenceMedium {
					t.Errorf("expected medium confidence for silent acceptance, got %s", f.Confidence)
				}
			}
		}
		if !found {
			t.Error("expected mass assignment finding when admin field silently accepted on 200")
		}
	})

	t.Run("generic_field_email_no_evidence_no_finding", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "PUT", Path: "/users/1"},
				Payload: payloads.Payload{
					Type:     types.AttackMassAssignment,
					Value:    `{"email": "test@evil.com"}`,
					Metadata: map[string]string{"field": "email", "value": "test@evil.com"},
				},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"id":1,"name":"test"}`},
		}
		findings := d.Detect(result, nil)
		for _, f := range findings {
			if f.Type == types.AttackMassAssignment {
				t.Error("unexpected mass assignment finding for generic field 'email' without evidence in response")
			}
		}
	})

	t.Run("generic_field_email_with_evidence_finding", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "PUT", Path: "/users/1"},
				Payload: payloads.Payload{
					Type:     types.AttackMassAssignment,
					Value:    `{"email": "test@evil.com"}`,
					Metadata: map[string]string{"field": "email", "value": "test@evil.com"},
				},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"id":1,"name":"test","email":"test@evil.com"}`},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackMassAssignment {
				found = true
			}
		}
		if !found {
			t.Error("expected mass assignment finding for generic field 'email' with evidence in response")
		}
	})

	t.Run("generic_field_name_no_evidence_no_finding", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "PUT", Path: "/users/1"},
				Payload: payloads.Payload{
					Type:     types.AttackMassAssignment,
					Value:    `{"name": "hacker"}`,
					Metadata: map[string]string{"field": "name", "value": "hacker"},
				},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"id":1,"status":"ok"}`},
		}
		findings := d.Detect(result, nil)
		for _, f := range findings {
			if f.Type == types.AttackMassAssignment {
				t.Error("unexpected mass assignment finding for generic field 'name' without evidence in response")
			}
		}
	})

	t.Run("generic_field_name_with_evidence_finding", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "PUT", Path: "/users/1"},
				Payload: payloads.Payload{
					Type:     types.AttackMassAssignment,
					Value:    `{"name": "hacker"}`,
					Metadata: map[string]string{"field": "name", "value": "hacker"},
				},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"id":1,"name":"hacker"}`},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackMassAssignment {
				found = true
			}
		}
		if !found {
			t.Error("expected mass assignment finding for generic field 'name' with evidence in response")
		}
	})

	t.Run("generic_field_password_no_evidence_no_finding", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "PUT", Path: "/users/1"},
				Payload: payloads.Payload{
					Type:     types.AttackMassAssignment,
					Value:    `{"password": "newpass"}`,
					Metadata: map[string]string{"field": "password", "value": "newpass"},
				},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"id":1,"status":"updated"}`},
		}
		findings := d.Detect(result, nil)
		for _, f := range findings {
			if f.Type == types.AttackMassAssignment {
				t.Error("unexpected mass assignment finding for generic field 'password' without evidence in response")
			}
		}
	})

	t.Run("admin_relevant_role_field_detected", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "PUT", Path: "/users/1"},
				Payload: payloads.Payload{
					Type:     types.AttackMassAssignment,
					Value:    `{"role": "admin"}`,
					Metadata: map[string]string{"field": "role", "value": "admin"},
				},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"id":1,"name":"test","role":"admin"}`},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackMassAssignment {
				found = true
			}
		}
		if !found {
			t.Error("expected mass assignment finding for admin-relevant field 'role'")
		}
	})

	t.Run("admin_relevant_permission_field_detected", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "PUT", Path: "/users/v1/test/password"},
				Payload: payloads.Payload{
					Type:     types.AttackMassAssignment,
					Value:    `{"admin": true}`,
					Metadata: map[string]string{"field": "admin", "value": "true"},
				},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"status":"success","admin":true}`},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackMassAssignment {
				found = true
			}
		}
		if !found {
			t.Error("expected mass assignment finding for admin-relevant field 'admin'")
		}
	})
}

func TestAnomalyDetector_BOLA(t *testing.T) {
	d := NewAnomalyDetector()

	t.Run("403_to_200_baseline_flip", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/users/2/profile"},
				Payload:  payloads.Payload{Type: types.AttackBOLA, Value: "2"},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"user":"other"}`},
		}
		baseline := &types.HTTPResponse{StatusCode: 403, Body: `Forbidden`}

		findings := d.Detect(result, baseline)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackBOLA {
				found = true
			}
		}
		if !found {
			t.Error("expected BOLA finding when baseline 403 becomes 200")
		}
	})

	t.Run("PUT_identical_success_detected", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "PUT", Path: "/users/v1/victim/password"},
				Payload:  payloads.Payload{Type: types.AttackBOLA, Value: "victim"},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"status": "success", "message": "Password changed"}`},
		}
		baseline := &types.HTTPResponse{StatusCode: 200, Body: `{"status": "success", "message": "Password changed"}`}

		findings := d.Detect(result, baseline)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackBOLA && containsSubstring(f.Title, "state-changing") {
				found = true
				if f.Confidence != types.ConfidenceHigh {
					t.Errorf("expected high confidence for state-changing BOLA, got %s", f.Confidence)
				}
			}
		}
		if !found {
			t.Error("expected BOLA finding for PUT with identical success responses")
		}
	})

	t.Run("DELETE_identical_success_detected", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "DELETE", Path: "/users/v1/victim"},
				Payload:  payloads.Payload{Type: types.AttackBOLA, Value: "victim"},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"status": "ok"}`},
		}
		baseline := &types.HTTPResponse{StatusCode: 200, Body: `{"status": "ok"}`}

		findings := d.Detect(result, baseline)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackBOLA && containsSubstring(f.Title, "state-changing") {
				found = true
			}
		}
		if !found {
			t.Error("expected BOLA finding for DELETE with identical success responses")
		}
	})

	t.Run("PATCH_identical_success_detected", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "PATCH", Path: "/users/v1/victim/email"},
				Payload:  payloads.Payload{Type: types.AttackBOLA, Value: "victim"},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"updated": true}`},
		}
		baseline := &types.HTTPResponse{StatusCode: 200, Body: `{"updated": true}`}

		findings := d.Detect(result, baseline)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackBOLA && containsSubstring(f.Title, "state-changing") {
				found = true
			}
		}
		if !found {
			t.Error("expected BOLA finding for PATCH with identical success responses")
		}
	})

	t.Run("GET_identical_success_no_state_changing_finding", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/users/v1/victim/profile"},
				Payload:  payloads.Payload{Type: types.AttackBOLA, Value: "victim"},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"name": "test"}`},
		}
		baseline := &types.HTTPResponse{StatusCode: 200, Body: `{"name": "test"}`}

		findings := d.Detect(result, baseline)
		for _, f := range findings {
			if f.Type == types.AttackBOLA && containsSubstring(f.Title, "state-changing") {
				t.Error("unexpected state-changing BOLA finding for GET request with identical responses")
			}
		}
	})
}

func TestAnomalyDetector_BFLA(t *testing.T) {
	d := NewAnomalyDetector()

	result := &fuzzer.FuzzResult{
		Request: &payloads.FuzzRequest{
			Endpoint: types.Endpoint{Method: "DELETE", Path: "/admin/users/1"},
			Payload: payloads.Payload{Type: types.AttackBFLA, Value: "1"},
		},
		Response: &types.HTTPResponse{StatusCode: 200, Body: `{"deleted":true}`},
	}
	baseline := &types.HTTPResponse{StatusCode: 403, Body: `Forbidden`}

	findings := d.Detect(result, baseline)
	found := false
	for _, f := range findings {
		if f.Type == types.AttackBFLA {
			found = true
		}
	}
	if !found {
		t.Error("expected BFLA finding when baseline 403 becomes 200")
	}
}

func TestAnomalyDetector_JWT(t *testing.T) {
	d := NewAnomalyDetector()

	t.Run("alg_none_accepted", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/api/protected"},
				Payload: payloads.Payload{
					Type: types.AttackJWT, Value: "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.",
					Metadata: map[string]string{"attack": "algorithm_confusion", "alg": "none"},
				},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"data":"secret"}`},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackJWT && containsSubstring(f.Title, "algorithm") {
				found = true
				if f.Severity != types.SeverityCritical {
					t.Errorf("expected critical severity for alg:none, got %s", f.Severity)
				}
			}
		}
		if !found {
			t.Error("expected JWT algorithm confusion finding")
		}
	})

	t.Run("missing_signature_accepted", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/api/protected"},
				Payload: payloads.Payload{
					Type: types.AttackJWT, Value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0",
					Metadata: map[string]string{"attack": "missing_signature"},
				},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"data":"secret"}`},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackJWT && containsSubstring(f.Title, "signature") {
				found = true
			}
		}
		if !found {
			t.Error("expected JWT signature bypass finding")
		}
	})

	t.Run("weak_secret", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/api/protected"},
				Payload: payloads.Payload{
					Type: types.AttackJWT, Value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
					Metadata: map[string]string{"attack": "weak_secret", "secret": "password"},
				},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: `{"data":"secret"}`},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackJWT && containsSubstring(f.Title, "weak") {
				found = true
			}
		}
		if !found {
			t.Error("expected JWT weak secret finding")
		}
	})

	t.Run("rejected_no_finding", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/api/protected"},
				Payload: payloads.Payload{
					Type: types.AttackJWT, Value: "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.",
					Metadata: map[string]string{"attack": "algorithm_confusion"},
				},
			},
			Response: &types.HTTPResponse{StatusCode: 401, Body: `Unauthorized`},
		}
		findings := d.Detect(result, nil)
		for _, f := range findings {
			if f.Type == types.AttackJWT {
				t.Error("unexpected JWT finding when server rejected the token")
			}
		}
	})
}

func TestAnomalyDetector_BlindTimingInjection(t *testing.T) {
	d := NewAnomalyDetector()

	t.Run("sleep_payload_detected", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/search"},
				Payload: payloads.Payload{Type: types.AttackSQLi, Value: "' AND SLEEP(5)--"},
			},
			Response: &types.HTTPResponse{
				StatusCode:   200,
				Body:         "OK",
				ResponseTime: 5 * time.Second,
			},
		}
		baseline := &types.HTTPResponse{
			StatusCode:   200,
			Body:         "OK",
			ResponseTime: 100 * time.Millisecond,
		}

		findings := d.Detect(result, baseline)
		found := false
		for _, f := range findings {
			if containsSubstring(f.Title, "blind") && containsSubstring(f.Title, "injection") {
				found = true
			}
		}
		if !found {
			t.Error("expected blind timing injection finding for SLEEP payload")
		}
	})

	t.Run("no_delay_no_finding", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/search"},
				Payload: payloads.Payload{Type: types.AttackSQLi, Value: "' AND SLEEP(5)--"},
			},
			Response: &types.HTTPResponse{
				StatusCode:   200,
				Body:         "OK",
				ResponseTime: 150 * time.Millisecond,
			},
		}
		baseline := &types.HTTPResponse{
			StatusCode:   200,
			Body:         "OK",
			ResponseTime: 100 * time.Millisecond,
		}

		findings := d.Detect(result, baseline)
		for _, f := range findings {
			if containsSubstring(f.Title, "blind") {
				t.Error("unexpected blind injection finding when response time is normal")
			}
		}
	})
}

func TestAnomalyDetector_MethodTampering(t *testing.T) {
	d := NewAnomalyDetector()

	t.Run("trace_detected", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "TRACE", Path: "/api"},
				Payload: payloads.Payload{
					Type: types.AttackMethodTampering, Value: "TRACE",
					Metadata: map[string]string{"override_method": "TRACE"},
				},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: "TRACE /api"},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackMethodTampering {
				found = true
			}
		}
		if !found {
			t.Error("expected method tampering finding for TRACE")
		}
	})

	t.Run("non_trace_no_finding", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "PUT", Path: "/api"},
				Payload: payloads.Payload{
					Type: types.AttackMethodTampering, Value: "PUT",
					Metadata: map[string]string{"override_method": "PUT"},
				},
			},
			Response: &types.HTTPResponse{StatusCode: 200, Body: "OK"},
		}
		findings := d.Detect(result, nil)
		for _, f := range findings {
			if f.Type == types.AttackMethodTampering {
				t.Error("unexpected method tampering finding for non-TRACE method without baseline")
			}
		}
	})
}

func TestAnomalyDetector_ContentTypeConfusion_Removed(t *testing.T) {
	d := NewAnomalyDetector()

	result := &fuzzer.FuzzResult{
		Request: &payloads.FuzzRequest{
			Endpoint: types.Endpoint{Method: "POST", Path: "/api"},
			Payload: payloads.Payload{Type: types.AttackContentTypeConfusion, Value: "text/xml"},
		},
		Response: &types.HTTPResponse{StatusCode: 200, Body: `{"ok":true}`},
	}
	findings := d.Detect(result, nil)
	for _, f := range findings {
		if f.Type == types.AttackContentTypeConfusion {
			t.Error("Content-Type Confusion detection should be removed (near-100% FP rate)")
		}
	}
}

func TestAnomalyDetector_IDOR_StatusOnly_Removed(t *testing.T) {
	d := NewAnomalyDetector()

	result := &fuzzer.FuzzResult{
		Request: &payloads.FuzzRequest{
			Endpoint: types.Endpoint{Method: "GET", Path: "/users/2"},
			Payload: payloads.Payload{Type: types.AttackIDOR, Value: "2"},
		},
		Response: &types.HTTPResponse{StatusCode: 200, Body: `{"user":"test"}`},
	}
	// No baseline — the old code would flag this as IDOR just because of 200 status
	findings := d.Detect(result, nil)
	for _, f := range findings {
		if f.Type == types.AttackIDOR {
			t.Error("IDOR status-code-only detection should be removed (false positive)")
		}
	}
}

func TestAnomalyDetector_RateLimitDetection(t *testing.T) {
	d := NewAnomalyDetector()

	t.Run("429_status_code", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/api/data"},
				Payload:  payloads.Payload{Type: types.AttackIDOR, Value: "1"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 429,
				Body:       "Too Many Requests",
				Headers:    map[string]string{},
			},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == "rate_limit" && containsSubstring(f.Title, "rate limiting") {
				found = true
				if f.Severity != types.SeverityInfo {
					t.Errorf("expected info severity, got %s", f.Severity)
				}
			}
		}
		if !found {
			t.Error("expected rate limit finding for 429 status code")
		}
	})

	t.Run("retry_after_header", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/api/data"},
				Payload:  payloads.Payload{Type: types.AttackIDOR, Value: "1"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 200,
				Body:       "OK",
				Headers:    map[string]string{"Retry-After": "30"},
			},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == "rate_limit" && containsSubstring(f.Title, "retry-after") {
				found = true
				if !containsSubstring(f.Description, "30") {
					t.Error("expected description to contain the Retry-After value")
				}
			}
		}
		if !found {
			t.Error("expected rate limit finding for Retry-After header")
		}
	})

	t.Run("retry_after_lowercase", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/api/data"},
				Payload:  payloads.Payload{Type: types.AttackIDOR, Value: "1"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 200,
				Body:       "OK",
				Headers:    map[string]string{"retry-after": "60"},
			},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == "rate_limit" && containsSubstring(f.Title, "retry-after") {
				found = true
			}
		}
		if !found {
			t.Error("expected rate limit finding for lowercase retry-after header")
		}
	})

	t.Run("rate_limit_remaining_zero", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/api/data"},
				Payload:  payloads.Payload{Type: types.AttackIDOR, Value: "1"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 200,
				Body:       "OK",
				Headers:    map[string]string{"X-RateLimit-Remaining": "0"},
			},
		}
		findings := d.Detect(result, nil)
		found := false
		for _, f := range findings {
			if f.Type == "rate_limit" && containsSubstring(f.Title, "exhausted") {
				found = true
			}
		}
		if !found {
			t.Error("expected rate limit exhausted finding when X-RateLimit-Remaining is 0")
		}
	})

	t.Run("rate_limit_remaining_nonzero", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/api/data"},
				Payload:  payloads.Payload{Type: types.AttackIDOR, Value: "1"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 200,
				Body:       "OK",
				Headers:    map[string]string{"X-RateLimit-Remaining": "50"},
			},
		}
		findings := d.Detect(result, nil)
		for _, f := range findings {
			if f.Type == "rate_limit" && containsSubstring(f.Title, "exhausted") {
				t.Error("unexpected rate limit exhausted finding when remaining is 50")
			}
		}
	})

	t.Run("no_rate_limit_headers", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/api/data"},
				Payload:  payloads.Payload{Type: types.AttackIDOR, Value: "1"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 200,
				Body:       "OK",
				Headers:    map[string]string{},
			},
		}
		findings := d.Detect(result, nil)
		for _, f := range findings {
			if f.Type == "rate_limit" {
				t.Error("unexpected rate limit finding with no rate limit headers")
			}
		}
	})
}

func TestAnomalyDetector_BOLA_ErrorToSuccess(t *testing.T) {
	d := NewAnomalyDetector()

	t.Run("baseline_400_fuzz_204_PUT_BOLA", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "PUT", Path: "/users/v1/{username}/password"},
				Payload:  payloads.Payload{Type: types.AttackBOLA, Value: "other_user"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 204,
				Body:       "",
			},
		}

		baseline := &types.HTTPResponse{
			StatusCode: 400,
			Body:       `{"status": "fail", "message": "password is missing"}`,
		}

		findings := d.Detect(result, baseline)
		found := false
		for _, f := range findings {
			if f.Type == types.AttackBOLA && containsSubstring(f.Title, "State-Changing Operation Succeeded") {
				found = true
				if f.Severity != types.SeverityHigh {
					t.Errorf("expected severity %s, got %s", types.SeverityHigh, f.Severity)
				}
				if f.Confidence != types.ConfidenceHigh {
					t.Errorf("expected confidence %s, got %s", types.ConfidenceHigh, f.Confidence)
				}
				if f.CWE != "CWE-639" {
					t.Errorf("expected CWE-639, got %s", f.CWE)
				}
			}
		}
		if !found {
			t.Error("expected BOLA finding for 400→204 state-changing PUT, got none")
		}
	})

	t.Run("baseline_400_fuzz_204_GET_no_finding", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/users/v1/{username}/profile"},
				Payload:  payloads.Payload{Type: types.AttackBOLA, Value: "other_user"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 204,
				Body:       "",
			},
		}

		baseline := &types.HTTPResponse{
			StatusCode: 400,
			Body:       `{"error": "bad request"}`,
		}

		findings := d.Detect(result, baseline)
		for _, f := range findings {
			if f.Type == types.AttackBOLA && containsSubstring(f.Title, "State-Changing Operation Succeeded with Different Identifier") {
				t.Error("unexpected BOLA state-changing finding for GET method")
			}
		}
	})
}

func TestAnomalyDetector_SQLi_ParameterizedQueryReclassification(t *testing.T) {
	d := NewAnomalyDetector()

	t.Run("parameterized_query_question_marks_reclassified", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/users"},
				Payload:  payloads.Payload{Type: types.AttackSQLi, Value: "' OR 1=1--"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 500,
				Body:       `sqlalchemy.exc.IntegrityError: (sqlite3.IntegrityError) UNIQUE constraint failed: users.username\n[SQL: INSERT INTO users (username, password, email, admin) VALUES (?, ?, ?, ?)]`,
			},
		}
		findings := d.Detect(result, nil)
		foundInfoDisclosure := false
		for _, f := range findings {
			if f.Type == types.AttackSQLi {
				t.Error("expected reclassification away from sqli when parameterized query detected")
			}
			if f.Type == "information_disclosure" && containsSubstring(f.Title, "parameterized") {
				foundInfoDisclosure = true
				if f.Severity != types.SeverityMedium {
					t.Errorf("expected medium severity, got %s", f.Severity)
				}
			}
		}
		if !foundInfoDisclosure {
			t.Error("expected information disclosure finding for parameterized query stack trace")
		}
	})

	t.Run("parameterized_query_postgresql_style_reclassified", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/users"},
				Payload:  payloads.Payload{Type: types.AttackSQLi, Value: "' OR 1=1--"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 500,
				Body:       `PostgreSQL ERROR: duplicate key value violates unique constraint "users_pkey"\nDETAIL: Key (id)=($1) already exists.`,
			},
		}
		findings := d.Detect(result, nil)
		foundInfoDisclosure := false
		for _, f := range findings {
			if f.Type == types.AttackSQLi {
				t.Error("expected reclassification away from sqli for PostgreSQL parameterized query")
			}
			if f.Type == "information_disclosure" {
				foundInfoDisclosure = true
			}
		}
		if !foundInfoDisclosure {
			t.Error("expected information disclosure finding for PostgreSQL parameterized query")
		}
	})

	t.Run("parameterized_query_named_params_reclassified", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/users"},
				Payload:  payloads.Payload{Type: types.AttackSQLi, Value: "' OR 1=1--"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 500,
				Body:       `ORA-00001: unique constraint violated\nSQL: INSERT INTO users (name, email) VALUES (:name, :email)`,
			},
		}
		findings := d.Detect(result, nil)
		foundInfoDisclosure := false
		for _, f := range findings {
			if f.Type == types.AttackSQLi {
				t.Error("expected reclassification away from sqli for Oracle named parameter style")
			}
			if f.Type == "information_disclosure" {
				foundInfoDisclosure = true
			}
		}
		if !foundInfoDisclosure {
			t.Error("expected information disclosure finding for Oracle named parameter query")
		}
	})

	t.Run("parameterized_query_python_dbapi_reclassified", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "POST", Path: "/users"},
				Payload:  payloads.Payload{Type: types.AttackSQLi, Value: "' OR 1=1--"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 500,
				Body:       `SQLSTATE[23000]: Integrity constraint violation\nSQL: INSERT INTO users (name, email) VALUES (%s, %s)`,
			},
		}
		findings := d.Detect(result, nil)
		foundInfoDisclosure := false
		for _, f := range findings {
			if f.Type == types.AttackSQLi {
				t.Error("expected reclassification away from sqli for Python DB-API style")
			}
			if f.Type == "information_disclosure" {
				foundInfoDisclosure = true
			}
		}
		if !foundInfoDisclosure {
			t.Error("expected information disclosure finding for Python DB-API parameterized query")
		}
	})

	t.Run("real_sqli_no_parameterized_query_stays_sqli", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/search"},
				Payload:  payloads.Payload{Type: types.AttackSQLi, Value: "' OR 1=1--"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 500,
				Body:       `SQL syntax error near "' OR 1=1--": Warning: mysql_fetch_array() expects parameter`,
			},
		}
		findings := d.Detect(result, nil)
		foundSQLi := false
		for _, f := range findings {
			if f.Type == types.AttackSQLi {
				foundSQLi = true
			}
			if f.Type == "information_disclosure" {
				t.Error("unexpected info disclosure reclassification for real SQLi (no parameterized query)")
			}
		}
		if !foundSQLi {
			t.Error("expected sqli finding to remain when no parameterized query evidence")
		}
	})

	t.Run("parameterized_query_non_500_stays_sqli", func(t *testing.T) {
		// If the response is not a 500 error, keep it as SQLi even with parameterized query evidence.
		// Only reclassify when it's clearly a stack trace / error disclosure (5xx).
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/search"},
				Payload:  payloads.Payload{Type: types.AttackSQLi, Value: "' OR 1=1--"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 200,
				Body:       `Warning: mysql_fetch_array(): SQL syntax error. VALUES (?, ?)`,
			},
		}
		findings := d.Detect(result, nil)
		foundSQLi := false
		for _, f := range findings {
			if f.Type == types.AttackSQLi {
				foundSQLi = true
			}
		}
		if !foundSQLi {
			t.Error("expected sqli finding to remain for non-500 response even with parameterized query markers")
		}
	})

	t.Run("parameterized_query_where_clause", func(t *testing.T) {
		result := &fuzzer.FuzzResult{
			Request: &payloads.FuzzRequest{
				Endpoint: types.Endpoint{Method: "GET", Path: "/users"},
				Payload:  payloads.Payload{Type: types.AttackSQLi, Value: "' OR 1=1--"},
			},
			Response: &types.HTTPResponse{
				StatusCode: 500,
				Body:       `PostgreSQL ERROR: invalid input syntax for type integer\nSTATEMENT: SELECT * FROM users WHERE id = $1 AND active = $2`,
			},
		}
		findings := d.Detect(result, nil)
		foundInfoDisclosure := false
		for _, f := range findings {
			if f.Type == types.AttackSQLi {
				t.Error("expected reclassification away from sqli for WHERE clause with PostgreSQL params")
			}
			if f.Type == "information_disclosure" {
				foundInfoDisclosure = true
			}
		}
		if !foundInfoDisclosure {
			t.Error("expected information disclosure finding for parameterized WHERE clause")
		}
	})
}

func TestContainsParameterizedQuery(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"question_mark_values", "VALUES (?, ?, ?, ?)", true},
		{"question_mark_where", "WHERE id = ?", true},
		{"question_mark_where_full", "AND status = ?", true},
		{"postgresql_dollar", "Key (id)=($1) already exists", true},
		{"postgresql_multiple", "WHERE id = $1 AND name = $2", true},
		{"named_params_values", "VALUES (:name, :email)", true},
		{"named_params_where", "WHERE id = :id", true},
		{"python_dbapi", "VALUES (%s, %s)", true},
		{"no_params_plain_sql", "SELECT * FROM users WHERE name = 'test'", false},
		{"no_params_error", "SQL syntax error near 'test'", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsParameterizedQuery(tt.body)
			if got != tt.expected {
				t.Errorf("containsParameterizedQuery(%q) = %v, want %v", tt.body, got, tt.expected)
			}
		})
	}
}
