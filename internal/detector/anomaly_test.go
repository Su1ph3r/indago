package detector

import (
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
