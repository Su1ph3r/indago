package waf

import (
	"testing"
	"time"

	"github.com/su1ph3r/indago/pkg/types"
)

func TestNewWAFDetector(t *testing.T) {
	tests := []struct {
		name          string
		threshold     int
		bypassEnabled bool
	}{
		{"nil provider default threshold", 5, false},
		{"nil provider bypass enabled", 3, true},
		{"zero threshold", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wd := NewWAFDetector(nil, tt.threshold, tt.bypassEnabled)
			if wd == nil {
				t.Fatal("NewWAFDetector returned nil")
			}
			if wd.provider != nil {
				t.Error("expected nil provider")
			}
			if wd.threshold != tt.threshold {
				t.Errorf("threshold = %d, want %d", wd.threshold, tt.threshold)
			}
			if wd.bypassEnabled != tt.bypassEnabled {
				t.Errorf("bypassEnabled = %v, want %v", wd.bypassEnabled, tt.bypassEnabled)
			}
			if !wd.enabled {
				t.Error("expected detector to be enabled by default")
			}
			if wd.blockHistory == nil {
				t.Error("expected blockHistory to be initialized")
			}
			if len(wd.fingerprints) == 0 {
				t.Error("expected fingerprints to be loaded")
			}
		})
	}
}

func TestAnalyzeResponse_Cloudflare(t *testing.T) {
	tests := []struct {
		name     string
		resp     *types.HTTPResponse
		wantName string
	}{
		{
			name: "cloudflare server header",
			resp: &types.HTTPResponse{
				StatusCode:   403,
				Headers:      map[string]string{"Server": "cloudflare"},
				Body:         "",
				ResponseTime: 100 * time.Millisecond,
			},
			wantName: "Cloudflare",
		},
		{
			name: "CF-RAY header",
			resp: &types.HTTPResponse{
				StatusCode:   403,
				Headers:      map[string]string{"CF-RAY": "abc123-LAX"},
				Body:         "",
				ResponseTime: 100 * time.Millisecond,
			},
			wantName: "Cloudflare",
		},
		{
			name: "cloudflare body pattern",
			resp: &types.HTTPResponse{
				StatusCode:   403,
				Headers:      map[string]string{},
				Body:         "Attention Required! Cloudflare detected a threat",
				ResponseTime: 100 * time.Millisecond,
			},
			wantName: "Cloudflare",
		},
		{
			name: "cloudflare ray id in body",
			resp: &types.HTTPResponse{
				StatusCode:   403,
				Headers:      map[string]string{},
				Body:         "Cloudflare Ray ID: abc123",
				ResponseTime: 100 * time.Millisecond,
			},
			wantName: "Cloudflare",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wd := NewWAFDetector(nil, 5, false)
			detected := wd.AnalyzeResponse(tt.resp, "/test", "payload")
			if detected == nil {
				t.Fatal("expected WAF detection, got nil")
			}
			if detected.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", detected.Name, tt.wantName)
			}
			if detected.DetectionMethod != "fingerprint" {
				t.Errorf("DetectionMethod = %q, want %q", detected.DetectionMethod, "fingerprint")
			}
			if detected.Confidence <= 0 {
				t.Error("expected positive confidence")
			}
		})
	}
}

func TestAnalyzeResponse_AWSWAF(t *testing.T) {
	tests := []struct {
		name string
		resp *types.HTTPResponse
	}{
		{
			name: "AMZ-CF-ID header",
			resp: &types.HTTPResponse{
				StatusCode:   403,
				Headers:      map[string]string{"X-AMZ-CF-ID": "abc123"},
				Body:         "",
				ResponseTime: 100 * time.Millisecond,
			},
		},
		{
			name: "aws waf body pattern",
			resp: &types.HTTPResponse{
				StatusCode:   403,
				Headers:      map[string]string{},
				Body:         "Request blocked by AWS WAF",
				ResponseTime: 100 * time.Millisecond,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wd := NewWAFDetector(nil, 5, false)
			detected := wd.AnalyzeResponse(tt.resp, "/test", "payload")
			if detected == nil {
				t.Fatal("expected WAF detection, got nil")
			}
			if detected.Name != "AWS WAF" {
				t.Errorf("Name = %q, want %q", detected.Name, "AWS WAF")
			}
		})
	}
}

func TestAnalyzeResponse_Akamai(t *testing.T) {
	tests := []struct {
		name string
		resp *types.HTTPResponse
	}{
		{
			name: "X-Akamai-Transformed header",
			resp: &types.HTTPResponse{
				StatusCode:   403,
				Headers:      map[string]string{"X-Akamai-Transformed": "9 12345 0 pmb=mRUM,1"},
				Body:         "",
				ResponseTime: 100 * time.Millisecond,
			},
		},
		{
			name: "akamai server header",
			resp: &types.HTTPResponse{
				StatusCode:   403,
				Headers:      map[string]string{"Server": "AkamaiGHost"},
				Body:         "",
				ResponseTime: 100 * time.Millisecond,
			},
		},
		{
			name: "akamai reference in body",
			resp: &types.HTTPResponse{
				StatusCode:   403,
				Headers:      map[string]string{},
				Body:         "Access Denied. Akamai Reference #18.abc123",
				ResponseTime: 100 * time.Millisecond,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wd := NewWAFDetector(nil, 5, false)
			detected := wd.AnalyzeResponse(tt.resp, "/test", "payload")
			if detected == nil {
				t.Fatal("expected WAF detection, got nil")
			}
			if detected.Name != "Akamai" {
				t.Errorf("Name = %q, want %q", detected.Name, "Akamai")
			}
		})
	}
}

func TestAnalyzeResponse_NoWAF(t *testing.T) {
	tests := []struct {
		name string
		resp *types.HTTPResponse
	}{
		{
			name: "clean 200 response",
			resp: &types.HTTPResponse{
				StatusCode:   200,
				Headers:      map[string]string{"Content-Type": "application/json"},
				Body:         `{"status": "ok"}`,
				ResponseTime: 200 * time.Millisecond,
			},
		},
		{
			name: "201 created response",
			resp: &types.HTTPResponse{
				StatusCode:   201,
				Headers:      map[string]string{"Content-Type": "application/json"},
				Body:         `{"id": 1}`,
				ResponseTime: 150 * time.Millisecond,
			},
		},
		{
			name: "nil response",
			resp: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wd := NewWAFDetector(nil, 5, false)
			detected := wd.AnalyzeResponse(tt.resp, "/test", "payload")
			if detected != nil {
				t.Errorf("expected nil detection, got %+v", detected)
			}
		})
	}
}

func TestIsWAFDetected(t *testing.T) {
	wd := NewWAFDetector(nil, 5, false)

	if wd.IsWAFDetected() {
		t.Error("expected false before any detection")
	}

	// Trigger a detection
	resp := &types.HTTPResponse{
		StatusCode:   403,
		Headers:      map[string]string{"Server": "cloudflare", "CF-RAY": "abc123"},
		Body:         "",
		ResponseTime: 100 * time.Millisecond,
	}
	wd.AnalyzeResponse(resp, "/test", "payload")

	if !wd.IsWAFDetected() {
		t.Error("expected true after detection")
	}
}

func TestGetDetectedWAF(t *testing.T) {
	wd := NewWAFDetector(nil, 5, false)

	if wd.GetDetectedWAF() != nil {
		t.Error("expected nil before detection")
	}

	resp := &types.HTTPResponse{
		StatusCode:   403,
		Headers:      map[string]string{"Server": "cloudflare"},
		Body:         "",
		ResponseTime: 100 * time.Millisecond,
	}
	wd.AnalyzeResponse(resp, "/test", "payload")

	detected := wd.GetDetectedWAF()
	if detected == nil {
		t.Fatal("expected non-nil after detection")
	}
	if detected.Name != "Cloudflare" {
		t.Errorf("Name = %q, want %q", detected.Name, "Cloudflare")
	}
}

func TestBlockCounting(t *testing.T) {
	wd := NewWAFDetector(nil, 5, false)

	if wd.GetBlockCount() != 0 {
		t.Errorf("initial block count = %d, want 0", wd.GetBlockCount())
	}
	if wd.GetTotalBlocks() != 0 {
		t.Errorf("initial total blocks = %d, want 0", wd.GetTotalBlocks())
	}

	// Send blocked responses (403 triggers isBlockedResponse)
	for i := 0; i < 3; i++ {
		resp := &types.HTTPResponse{
			StatusCode:   403,
			Headers:      map[string]string{},
			Body:         "Access denied",
			ResponseTime: 100 * time.Millisecond,
		}
		wd.AnalyzeResponse(resp, "/test", "payload")
	}

	if wd.GetBlockCount() != 3 {
		t.Errorf("block count = %d, want 3", wd.GetBlockCount())
	}
	if wd.GetTotalBlocks() != 3 {
		t.Errorf("total blocks = %d, want 3", wd.GetTotalBlocks())
	}
}

func TestShouldTriggerBypass(t *testing.T) {
	tests := []struct {
		name          string
		threshold     int
		bypassEnabled bool
		blocks        int
		want          bool
	}{
		{"below threshold", 5, true, 3, false},
		{"at threshold", 5, true, 5, true},
		{"above threshold", 5, true, 7, true},
		{"bypass disabled", 5, false, 10, false},
		{"zero threshold met", 0, true, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wd := NewWAFDetector(nil, tt.threshold, tt.bypassEnabled)

			for i := 0; i < tt.blocks; i++ {
				resp := &types.HTTPResponse{
					StatusCode:   403,
					Headers:      map[string]string{},
					Body:         "blocked",
					ResponseTime: 100 * time.Millisecond,
				}
				wd.AnalyzeResponse(resp, "/test", "payload")
			}

			if got := wd.ShouldTriggerBypass(); got != tt.want {
				t.Errorf("ShouldTriggerBypass() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResetBlockCount(t *testing.T) {
	wd := NewWAFDetector(nil, 5, false)

	// Accumulate blocks
	for i := 0; i < 5; i++ {
		resp := &types.HTTPResponse{
			StatusCode:   403,
			Headers:      map[string]string{},
			Body:         "blocked",
			ResponseTime: 100 * time.Millisecond,
		}
		wd.AnalyzeResponse(resp, "/test", "payload")
	}

	if wd.GetBlockCount() != 5 {
		t.Fatalf("block count = %d, want 5", wd.GetBlockCount())
	}
	if wd.GetTotalBlocks() != 5 {
		t.Fatalf("total blocks = %d, want 5", wd.GetTotalBlocks())
	}

	wd.ResetBlockCount()

	if wd.GetBlockCount() != 0 {
		t.Errorf("block count after reset = %d, want 0", wd.GetBlockCount())
	}
	// Total blocks should NOT be reset
	if wd.GetTotalBlocks() != 5 {
		t.Errorf("total blocks after reset = %d, want 5", wd.GetTotalBlocks())
	}
}

func TestGetBlockHistory(t *testing.T) {
	wd := NewWAFDetector(nil, 5, false)

	history := wd.GetBlockHistory()
	if len(history) != 0 {
		t.Errorf("initial history length = %d, want 0", len(history))
	}

	// Generate some block events
	endpoints := []string{"/api/users", "/api/admin", "/api/login"}
	for _, ep := range endpoints {
		resp := &types.HTTPResponse{
			StatusCode:   403,
			Headers:      map[string]string{},
			Body:         "forbidden",
			ResponseTime: 100 * time.Millisecond,
		}
		wd.AnalyzeResponse(resp, ep, "test-payload")
	}

	history = wd.GetBlockHistory()
	if len(history) != 3 {
		t.Fatalf("history length = %d, want 3", len(history))
	}

	// Verify history contains correct endpoints
	for i, ep := range endpoints {
		if history[i].Endpoint != ep {
			t.Errorf("history[%d].Endpoint = %q, want %q", i, history[i].Endpoint, ep)
		}
		if history[i].StatusCode != 403 {
			t.Errorf("history[%d].StatusCode = %d, want 403", i, history[i].StatusCode)
		}
		if history[i].Payload != "test-payload" {
			t.Errorf("history[%d].Payload = %q, want %q", i, history[i].Payload, "test-payload")
		}
	}

	// Verify returned history is a copy (mutation doesn't affect internal state)
	history[0].Endpoint = "modified"
	original := wd.GetBlockHistory()
	if original[0].Endpoint == "modified" {
		t.Error("GetBlockHistory should return a copy, not the internal slice")
	}
}

func TestIsBlockedResponse(t *testing.T) {
	tests := []struct {
		name string
		resp *types.HTTPResponse
		want bool
	}{
		{
			name: "403 status",
			resp: &types.HTTPResponse{
				StatusCode:   403,
				Headers:      map[string]string{},
				Body:         "",
				ResponseTime: 200 * time.Millisecond,
			},
			want: true,
		},
		{
			name: "406 status",
			resp: &types.HTTPResponse{
				StatusCode:   406,
				Headers:      map[string]string{},
				Body:         "",
				ResponseTime: 200 * time.Millisecond,
			},
			want: true,
		},
		{
			name: "429 status",
			resp: &types.HTTPResponse{
				StatusCode:   429,
				Headers:      map[string]string{},
				Body:         "",
				ResponseTime: 200 * time.Millisecond,
			},
			want: true,
		},
		{
			name: "503 status",
			resp: &types.HTTPResponse{
				StatusCode:   503,
				Headers:      map[string]string{},
				Body:         "",
				ResponseTime: 200 * time.Millisecond,
			},
			want: true,
		},
		{
			name: "body contains access denied",
			resp: &types.HTTPResponse{
				StatusCode:   200,
				Headers:      map[string]string{},
				Body:         "Access Denied: your request has been blocked",
				ResponseTime: 200 * time.Millisecond,
			},
			want: true,
		},
		{
			name: "body contains forbidden",
			resp: &types.HTTPResponse{
				StatusCode:   200,
				Headers:      map[string]string{},
				Body:         "Request is forbidden by security policy",
				ResponseTime: 200 * time.Millisecond,
			},
			want: true,
		},
		{
			name: "body contains request rejected",
			resp: &types.HTTPResponse{
				StatusCode:   200,
				Headers:      map[string]string{},
				Body:         "The Request Rejected due to security rules",
				ResponseTime: 200 * time.Millisecond,
			},
			want: true,
		},
		{
			name: "body contains attack detected",
			resp: &types.HTTPResponse{
				StatusCode:   200,
				Headers:      map[string]string{},
				Body:         "Attack Detected - malicious content found",
				ResponseTime: 200 * time.Millisecond,
			},
			want: true,
		},
		{
			name: "fast 4xx rejection",
			resp: &types.HTTPResponse{
				StatusCode:   400,
				Headers:      map[string]string{},
				Body:         "",
				ResponseTime: 10 * time.Millisecond,
			},
			want: true,
		},
		{
			name: "normal 200 response",
			resp: &types.HTTPResponse{
				StatusCode:   200,
				Headers:      map[string]string{},
				Body:         `{"status": "ok"}`,
				ResponseTime: 200 * time.Millisecond,
			},
			want: false,
		},
		{
			name: "301 redirect not blocked",
			resp: &types.HTTPResponse{
				StatusCode:   301,
				Headers:      map[string]string{"Location": "/new"},
				Body:         "",
				ResponseTime: 200 * time.Millisecond,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wd := NewWAFDetector(nil, 5, false)
			if got := wd.isBlockedResponse(tt.resp); got != tt.want {
				t.Errorf("isBlockedResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetectGenericWAF(t *testing.T) {
	tests := []struct {
		name       string
		resp       *types.HTTPResponse
		wantNil    bool
		wantIndicator string
	}{
		{
			name: "403 forbidden",
			resp: &types.HTTPResponse{
				StatusCode:   403,
				Headers:      map[string]string{},
				Body:         "",
				ResponseTime: 200 * time.Millisecond,
			},
			wantNil:       false,
			wantIndicator: "403 Forbidden response",
		},
		{
			name: "406 not acceptable",
			resp: &types.HTTPResponse{
				StatusCode:   406,
				Headers:      map[string]string{},
				Body:         "",
				ResponseTime: 200 * time.Millisecond,
			},
			wantNil:       false,
			wantIndicator: "406 Not Acceptable response",
		},
		{
			name: "429 too many requests",
			resp: &types.HTTPResponse{
				StatusCode:   429,
				Headers:      map[string]string{},
				Body:         "",
				ResponseTime: 200 * time.Millisecond,
			},
			wantNil:       false,
			wantIndicator: "429 Too Many Requests",
		},
		{
			name: "access denied in body",
			resp: &types.HTTPResponse{
				StatusCode:   200,
				Headers:      map[string]string{},
				Body:         "access denied by policy",
				ResponseTime: 200 * time.Millisecond,
			},
			wantNil:       false,
			wantIndicator: "Access denied message",
		},
		{
			name: "blocked in body",
			resp: &types.HTTPResponse{
				StatusCode:   200,
				Headers:      map[string]string{},
				Body:         "your request has been blocked",
				ResponseTime: 200 * time.Millisecond,
			},
			wantNil:       false,
			wantIndicator: "Block message in response",
		},
		{
			name: "no indicators",
			resp: &types.HTTPResponse{
				StatusCode:   200,
				Headers:      map[string]string{},
				Body:         "everything is fine",
				ResponseTime: 200 * time.Millisecond,
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wd := NewWAFDetector(nil, 5, false)
			result := wd.detectGenericWAF(tt.resp)

			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("expected non-nil detection")
			}
			if result.Name != "Unknown WAF" {
				t.Errorf("Name = %q, want %q", result.Name, "Unknown WAF")
			}
			if result.Vendor != "Unknown" {
				t.Errorf("Vendor = %q, want %q", result.Vendor, "Unknown")
			}
			if result.DetectionMethod != "heuristic" {
				t.Errorf("DetectionMethod = %q, want %q", result.DetectionMethod, "heuristic")
			}
			if result.Confidence != 0.5 {
				t.Errorf("Confidence = %f, want 0.5", result.Confidence)
			}

			found := false
			for _, ind := range result.Indicators {
				if ind == tt.wantIndicator {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected indicator %q in %v", tt.wantIndicator, result.Indicators)
			}
		})
	}
}

func TestGenerateStaticBypasses(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		attackType string
		wantMin    int
	}{
		{"sqli bypasses", "' OR 1=1--", "sqli", 1},
		{"xss bypasses", "<script>alert(1)</script>", "xss", 1},
		{"command injection bypasses", "; cat /etc/passwd", "command_injection", 1},
		{"generic bypasses", "test payload", "unknown_type", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wd := NewWAFDetector(nil, 5, false)
			strategies := wd.generateStaticBypasses(tt.payload, tt.attackType)
			if len(strategies) < tt.wantMin {
				t.Errorf("got %d strategies, want at least %d", len(strategies), tt.wantMin)
			}

			for i, s := range strategies {
				if s.OriginalPayload != tt.payload {
					t.Errorf("strategy[%d].OriginalPayload = %q, want %q", i, s.OriginalPayload, tt.payload)
				}
				if s.Technique == "" {
					t.Errorf("strategy[%d].Technique is empty", i)
				}
				if s.Rationale == "" {
					t.Errorf("strategy[%d].Rationale is empty", i)
				}
				if len(s.BypassPayloads) == 0 {
					t.Errorf("strategy[%d].BypassPayloads is empty", i)
				}
			}
		})
	}
}

func TestGenerateSQLiBypasses(t *testing.T) {
	payload := "' UNION SELECT 1,2,3--"
	strategies := generateSQLiBypasses(payload)

	if len(strategies) != 5 {
		t.Fatalf("got %d strategies, want 5", len(strategies))
	}

	expectedTechniques := map[string]bool{
		TechniqueCommentInsertion: false,
		TechniqueCaseVariation:    false,
		TechniqueURLEncode:        false,
		TechniqueWhitespace:       false,
		TechniqueAlternativeSyntax: false,
	}

	for _, s := range strategies {
		if _, ok := expectedTechniques[s.Technique]; ok {
			expectedTechniques[s.Technique] = true
		}
		if len(s.BypassPayloads) == 0 {
			t.Errorf("technique %q produced no bypass payloads", s.Technique)
		}
	}

	for technique, found := range expectedTechniques {
		if !found {
			t.Errorf("missing technique: %s", technique)
		}
	}
}

func TestGenerateXSSBypasses(t *testing.T) {
	payload := "<script>alert(1)</script>"
	strategies := generateXSSBypasses(payload)

	if len(strategies) != 4 {
		t.Fatalf("got %d strategies, want 4", len(strategies))
	}

	expectedTechniques := map[string]bool{
		TechniqueURLEncode:        false,
		TechniqueUnicode:          false,
		TechniqueCaseVariation:    false,
		TechniqueAlternativeSyntax: false,
	}

	for _, s := range strategies {
		if _, ok := expectedTechniques[s.Technique]; ok {
			expectedTechniques[s.Technique] = true
		}
	}

	for technique, found := range expectedTechniques {
		if !found {
			t.Errorf("missing technique: %s", technique)
		}
	}
}

func TestGenerateCommandBypasses(t *testing.T) {
	payload := "; cat /etc/passwd"
	strategies := generateCommandBypasses(payload)

	if len(strategies) != 4 {
		t.Fatalf("got %d strategies, want 4", len(strategies))
	}

	expectedTechniques := map[string]bool{
		TechniqueAlternativeSyntax: false,
		TechniqueStringConcat:      false,
		TechniqueURLEncode:         false,
		TechniqueWhitespace:        false,
	}

	for _, s := range strategies {
		if _, ok := expectedTechniques[s.Technique]; ok {
			expectedTechniques[s.Technique] = true
		}
	}

	for technique, found := range expectedTechniques {
		if !found {
			t.Errorf("missing technique: %s", technique)
		}
	}
}

func TestGenerateGenericBypasses(t *testing.T) {
	payload := "test<>payload"
	strategies := generateGenericBypasses(payload)

	if len(strategies) != 3 {
		t.Fatalf("got %d strategies, want 3", len(strategies))
	}

	expectedTechniques := map[string]bool{
		TechniqueURLEncode:     false,
		TechniqueDoubleEncode:  false,
		TechniqueCaseVariation: false,
	}

	for _, s := range strategies {
		if _, ok := expectedTechniques[s.Technique]; ok {
			expectedTechniques[s.Technique] = true
		}
	}

	for technique, found := range expectedTechniques {
		if !found {
			t.Errorf("missing technique: %s", technique)
		}
	}
}

func TestGenerateBypassPayloads_NilProvider(t *testing.T) {
	wd := NewWAFDetector(nil, 5, false)
	strategies, err := wd.GenerateBypassPayloads(nil, "' OR 1=1--", "sqli")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(strategies) == 0 {
		t.Error("expected strategies from static bypass generator")
	}
}

func TestSetEnabled(t *testing.T) {
	wd := NewWAFDetector(nil, 5, false)

	// Detector is enabled by default, should detect
	resp := &types.HTTPResponse{
		StatusCode:   403,
		Headers:      map[string]string{"Server": "cloudflare"},
		Body:         "",
		ResponseTime: 100 * time.Millisecond,
	}
	detected := wd.AnalyzeResponse(resp, "/test", "payload")
	if detected == nil {
		t.Fatal("expected detection when enabled")
	}

	// Disable and verify no detection
	wd2 := NewWAFDetector(nil, 5, false)
	wd2.SetEnabled(false)
	detected = wd2.AnalyzeResponse(resp, "/test", "payload")
	if detected != nil {
		t.Error("expected nil when disabled")
	}
}

func TestAnalyzeResponse_GenericWAFDetection(t *testing.T) {
	// A 403 response with no known WAF fingerprint headers should still
	// trigger generic WAF detection since the response is "blocked"
	wd := NewWAFDetector(nil, 5, false)
	resp := &types.HTTPResponse{
		StatusCode:   403,
		Headers:      map[string]string{"Content-Type": "text/html"},
		Body:         "Your request has been blocked by our security system",
		ResponseTime: 100 * time.Millisecond,
	}

	detected := wd.AnalyzeResponse(resp, "/api/test", "malicious-payload")
	if detected == nil {
		t.Fatal("expected generic WAF detection")
	}
	if detected.Name != "Unknown WAF" {
		t.Errorf("Name = %q, want %q", detected.Name, "Unknown WAF")
	}
	if detected.DetectionMethod != "heuristic" {
		t.Errorf("DetectionMethod = %q, want %q", detected.DetectionMethod, "heuristic")
	}
}

func TestMatchFingerprint_CookieDetection(t *testing.T) {
	wd := NewWAFDetector(nil, 5, false)
	resp := &types.HTTPResponse{
		StatusCode:   403,
		Headers:      map[string]string{"Set-Cookie": "__cfduid=abc; cf_clearance=xyz"},
		Body:         "",
		ResponseTime: 100 * time.Millisecond,
	}

	detected := wd.AnalyzeResponse(resp, "/test", "payload")
	if detected == nil {
		t.Fatal("expected detection from cookie pattern")
	}
	if detected.Name != "Cloudflare" {
		t.Errorf("Name = %q, want %q", detected.Name, "Cloudflare")
	}
}

func TestBlockHistoryTrimming(t *testing.T) {
	wd := NewWAFDetector(nil, 5000, false)

	// Add more than 1000 block events to trigger trimming
	for i := 0; i < 1010; i++ {
		resp := &types.HTTPResponse{
			StatusCode:   403,
			Headers:      map[string]string{},
			Body:         "blocked",
			ResponseTime: 100 * time.Millisecond,
		}
		wd.AnalyzeResponse(resp, "/test", "payload")
	}

	history := wd.GetBlockHistory()
	// After exceeding 1000, it trims the first 100, so 1001 entries -> trim to 901
	// then entries 1002-1010 get added -> 910
	// The exact count depends on when the trim happens (at >1000)
	if len(history) > 1000 {
		t.Errorf("history length = %d, should be trimmed to <= 1000", len(history))
	}
}

func TestGenerateBase64Bypasses(t *testing.T) {
	payload := "cat /etc/passwd"
	bypasses := GenerateBase64Bypasses(payload)

	if len(bypasses) != 3 {
		t.Fatalf("got %d bypasses, want 3", len(bypasses))
	}

	for _, b := range bypasses {
		if b == "" {
			t.Error("empty bypass payload")
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	wd := NewWAFDetector(nil, 100, true)
	done := make(chan struct{})

	// Concurrent writes
	go func() {
		defer func() { done <- struct{}{} }()
		for i := 0; i < 50; i++ {
			resp := &types.HTTPResponse{
				StatusCode:   403,
				Headers:      map[string]string{"Server": "cloudflare"},
				Body:         "blocked",
				ResponseTime: 100 * time.Millisecond,
			}
			wd.AnalyzeResponse(resp, "/test", "payload")
		}
	}()

	// Concurrent reads
	go func() {
		defer func() { done <- struct{}{} }()
		for i := 0; i < 50; i++ {
			_ = wd.IsWAFDetected()
			_ = wd.GetDetectedWAF()
			_ = wd.GetBlockCount()
			_ = wd.GetTotalBlocks()
			_ = wd.ShouldTriggerBypass()
			_ = wd.GetBlockHistory()
		}
	}()

	// Concurrent resets
	go func() {
		defer func() { done <- struct{}{} }()
		for i := 0; i < 50; i++ {
			wd.ResetBlockCount()
		}
	}()

	<-done
	<-done
	<-done
}
