package detector

import (
	"testing"

	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

func newErrorTestReq() *payloads.FuzzRequest {
	return &payloads.FuzzRequest{
		Endpoint: types.Endpoint{Method: "GET", Path: "/test"},
		Payload:  payloads.Payload{Type: types.AttackSQLi, Value: "' OR 1=1--"},
	}
}

func TestErrorDetector_StackTrace(t *testing.T) {
	d := NewErrorPatternDetector()
	resp := &types.HTTPResponse{Body: `at com.example.Service.process(Service.java:42)`}
	findings := d.Detect(resp, newErrorTestReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Stack Trace Exposure" {
			found = true
		}
	}
	if !found {
		t.Error("expected stack trace finding")
	}
}

func TestErrorDetector_DebugMode(t *testing.T) {
	d := NewErrorPatternDetector()
	resp := &types.HTTPResponse{Body: `{"debug": true, "DEBUG_MODE": "enabled"}`}
	findings := d.Detect(resp, newErrorTestReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Debug Mode Enabled" {
			found = true
		}
	}
	if !found {
		t.Error("expected debug mode finding")
	}
}

func TestErrorDetector_DatabaseError(t *testing.T) {
	d := NewErrorPatternDetector()
	resp := &types.HTTPResponse{Body: `Error: can't connect to mysql server on 'db.internal'`}
	findings := d.Detect(resp, newErrorTestReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Database Connection Error" {
			found = true
		}
	}
	if !found {
		t.Error("expected database connection error finding")
	}
}

func TestErrorDetector_FilePathDisclosure(t *testing.T) {
	d := NewErrorPatternDetector()
	resp := &types.HTTPResponse{Body: `Error in /var/www/html/app/index.php`}
	findings := d.Detect(resp, newErrorTestReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "File Path Disclosure" {
			found = true
		}
	}
	if !found {
		t.Error("expected file path disclosure finding")
	}
}

func TestErrorDetector_TechVersionDisclosure(t *testing.T) {
	d := NewErrorPatternDetector()
	resp := &types.HTTPResponse{Body: `Powered by Apache/2.4.41 (Ubuntu)`}
	findings := d.Detect(resp, newErrorTestReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Technology Version Disclosure" {
			found = true
			if f.Severity != types.SeverityInfo {
				t.Errorf("expected info severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected technology version disclosure finding")
	}
}

func TestErrorDetector_ASPNETError(t *testing.T) {
	d := NewErrorPatternDetector()
	resp := &types.HTTPResponse{Body: `Server Error in '/' Application. Description: An unhandled exception occurred.`}
	findings := d.Detect(resp, newErrorTestReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "ASP.NET Error" {
			found = true
		}
	}
	if !found {
		t.Error("expected ASP.NET error finding")
	}
}

func TestErrorDetector_PHPError(t *testing.T) {
	d := NewErrorPatternDetector()
	resp := &types.HTTPResponse{Body: `Fatal error: Uncaught Exception in /var/www/test.php on line 42`}
	findings := d.Detect(resp, newErrorTestReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "PHP Error" {
			found = true
		}
	}
	if !found {
		t.Error("expected PHP error finding")
	}
}

func TestErrorDetector_JavaException(t *testing.T) {
	d := NewErrorPatternDetector()
	resp := &types.HTTPResponse{Body: `java.lang.NullPointerException\n\tat com.example.App.main`}
	findings := d.Detect(resp, newErrorTestReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Java Exception" {
			found = true
		}
	}
	if !found {
		t.Error("expected Java exception finding")
	}
}

func TestErrorDetector_PythonError(t *testing.T) {
	d := NewErrorPatternDetector()
	resp := &types.HTTPResponse{Body: `Traceback (most recent call last):\n  File "app.py", line 10`}
	findings := d.Detect(resp, newErrorTestReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Python Error" || f.Title == "Stack Trace Exposure" {
			found = true
		}
	}
	if !found {
		t.Error("expected Python error finding")
	}
}

func TestErrorDetector_RubyError(t *testing.T) {
	d := NewErrorPatternDetector()
	resp := &types.HTTPResponse{Body: `NoMethodError: undefined method 'foo' for nil:NilClass`}
	findings := d.Detect(resp, newErrorTestReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Ruby Error" {
			found = true
		}
	}
	if !found {
		t.Error("expected Ruby error finding")
	}
}

func TestErrorDetector_CleanResponse(t *testing.T) {
	d := NewErrorPatternDetector()
	resp := &types.HTTPResponse{Body: `{"status":"ok","data":[1,2,3]}`}
	findings := d.Detect(resp, newErrorTestReq(), nil)
	if len(findings) != 0 {
		t.Errorf("expected no findings for clean response, got %d", len(findings))
	}
}

func TestErrorDetector_BaselineSuppression(t *testing.T) {
	d := NewErrorPatternDetector()
	body := `at com.example.Service.process(Service.java:42)`
	resp := &types.HTTPResponse{Body: body}
	baseline := &types.HTTPResponse{Body: body}
	findings := d.Detect(resp, newErrorTestReq(), baseline)
	for _, f := range findings {
		if f.Title == "Stack Trace Exposure" {
			t.Error("finding should be suppressed when pattern exists in baseline")
		}
	}
}

func TestErrorDetector_BaselineNull(t *testing.T) {
	d := NewErrorPatternDetector()
	resp := &types.HTTPResponse{Body: `at com.example.Service.process(Service.java:42)`}
	findings := d.Detect(resp, newErrorTestReq(), nil)
	found := false
	for _, f := range findings {
		if f.Title == "Stack Trace Exposure" {
			found = true
		}
	}
	if !found {
		t.Error("expected finding when baseline is nil")
	}
}
