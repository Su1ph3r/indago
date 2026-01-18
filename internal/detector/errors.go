package detector

import (
	"regexp"

	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/pkg/types"
)

// ErrorPatternDetector detects error patterns in responses
type ErrorPatternDetector struct {
	rules []*DetectionRule
}

// NewErrorPatternDetector creates a new error pattern detector
func NewErrorPatternDetector() *ErrorPatternDetector {
	d := &ErrorPatternDetector{
		rules: make([]*DetectionRule, 0),
	}
	d.initRules()
	return d
}

// initRules initializes detection rules
func (d *ErrorPatternDetector) initRules() {
	// Stack trace exposure
	d.rules = append(d.rules, &DetectionRule{
		Name:        "Stack Trace Exposure",
		Description: "Application stack trace exposed in response",
		Type:        "information_disclosure",
		Severity:    types.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)(at\s+[\w\.$]+\([\w]+\.java:\d+\)|File\s+".*",\s+line\s+\d+|Traceback\s+\(most recent call last\)|at\s+[\w\._]+\s+\(.*:\d+:\d+\))`),
		CWE:         "CWE-209",
		Remediation: "Disable verbose error messages in production. Use custom error pages.",
	})

	// Debug mode enabled
	d.rules = append(d.rules, &DetectionRule{
		Name:        "Debug Mode Enabled",
		Description: "Application running in debug mode",
		Type:        "misconfiguration",
		Severity:    types.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)(debug\s*=\s*true|DEBUG_MODE|development\s+mode|django\.debug|flask\.debug)`),
		CWE:         "CWE-489",
		Remediation: "Disable debug mode in production environments.",
	})

	// Database connection errors
	d.rules = append(d.rules, &DetectionRule{
		Name:        "Database Connection Error",
		Description: "Database connection details exposed",
		Type:        "information_disclosure",
		Severity:    types.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)(connection\s+refused|can't\s+connect\s+to\s+(mysql|postgresql|mongodb)|database\s+connection\s+failed|ECONNREFUSED)`),
		CWE:         "CWE-200",
		Remediation: "Handle database errors gracefully without exposing connection details.",
	})

	// File path disclosure
	d.rules = append(d.rules, &DetectionRule{
		Name:        "File Path Disclosure",
		Description: "Server file paths exposed in response",
		Type:        "information_disclosure",
		Severity:    types.SeverityLow,
		Pattern:     regexp.MustCompile(`(?i)(/var/www/|/home/\w+/|C:\\\\(Users|Program Files|inetpub)|/usr/local/)`),
		CWE:         "CWE-200",
		Remediation: "Configure error handling to not include file paths in error messages.",
	})

	// Technology disclosure
	d.rules = append(d.rules, &DetectionRule{
		Name:        "Technology Version Disclosure",
		Description: "Specific technology versions exposed",
		Type:        "information_disclosure",
		Severity:    types.SeverityInfo,
		Pattern:     regexp.MustCompile(`(?i)(powered\s+by\s+[\w\s]+[\d\.]+|version\s+[\d\.]+|PHP/[\d\.]+|Apache/[\d\.]+|nginx/[\d\.]+)`),
		CWE:         "CWE-200",
		Remediation: "Remove or obfuscate version information in HTTP headers and responses.",
	})

	// ASP.NET errors
	d.rules = append(d.rules, &DetectionRule{
		Name:        "ASP.NET Error",
		Description: "ASP.NET verbose error exposed",
		Type:        "information_disclosure",
		Severity:    types.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)(Server\s+Error\s+in\s+'.*'\s+Application|ASP\.NET\s+Error|Description:\s+An\s+unhandled\s+exception)`),
		CWE:         "CWE-209",
		Remediation: "Configure custom error pages in web.config. Set customErrors mode to 'On'.",
	})

	// PHP errors
	d.rules = append(d.rules, &DetectionRule{
		Name:        "PHP Error",
		Description: "PHP error message exposed",
		Type:        "information_disclosure",
		Severity:    types.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)(Fatal\s+error:|Parse\s+error:|Warning:|Notice:)\s+.*\s+in\s+/.+\.php\s+on\s+line\s+\d+`),
		CWE:         "CWE-209",
		Remediation: "Set display_errors to Off and log_errors to On in php.ini.",
	})

	// Java exceptions
	d.rules = append(d.rules, &DetectionRule{
		Name:        "Java Exception",
		Description: "Java exception stack trace exposed",
		Type:        "information_disclosure",
		Severity:    types.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)(java\.lang\.\w+Exception|javax?\.\w+\.\w+Exception|Caused\s+by:|at\s+\w+\.\w+\.)`),
		CWE:         "CWE-209",
		Remediation: "Implement proper exception handling. Use generic error messages in production.",
	})

	// Python errors
	d.rules = append(d.rules, &DetectionRule{
		Name:        "Python Error",
		Description: "Python traceback exposed",
		Type:        "information_disclosure",
		Severity:    types.SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)(Traceback\s+\(most\s+recent\s+call\s+last\)|File\s+".*\.py",\s+line\s+\d+)`),
		CWE:         "CWE-209",
		Remediation: "Use try/except blocks and return generic error messages in production.",
	})

	// Ruby errors
	d.rules = append(d.rules, &DetectionRule{
		Name:        "Ruby Error",
		Description: "Ruby error exposed",
		Type:        "information_disclosure",
		Severity:    types.SeverityMedium,
		Pattern:     regexp.MustCompile("(?i)(\\.rb:\\d+:in\\s+|ActionController::RoutingError|NoMethodError|ArgumentError)"),
		CWE:         "CWE-209",
		Remediation: "Configure proper error handling in production. Use rescue blocks.",
	})
}

// Detect detects error patterns in a response
func (d *ErrorPatternDetector) Detect(resp *types.HTTPResponse, req *payloads.FuzzRequest) []types.Finding {
	var findings []types.Finding

	for _, rule := range d.rules {
		if rule.Match(resp) {
			finding := rule.ToFinding()
			findings = append(findings, finding)
		}
	}

	return findings
}

// AddRule adds a custom detection rule
func (d *ErrorPatternDetector) AddRule(rule *DetectionRule) {
	d.rules = append(d.rules, rule)
}
