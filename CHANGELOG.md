# Changelog

All notable changes to Indago will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2026-01-19

### Added

#### GraphQL Support
- GraphQL endpoint parsing and introspection
- Depth attacks for DoS testing
- Batch query abuse detection
- Alias-based resource exhaustion attacks
- New attack types: `graphql_depth`, `graphql_batch`, `graphql_introspection`, `graphql_alias`

#### Multi-Auth Differential Analysis
- Compare responses across multiple authentication contexts
- Detect BOLA (Broken Object Level Authorization) vulnerabilities
- Detect horizontal privilege escalation
- Configurable auth contexts with priority levels

#### Stateful Session Tracking
- Extract tokens, IDs, and session values from responses
- Inject extracted values into subsequent requests
- Custom extraction rules via YAML configuration

#### Attack Chains
- Multi-step attack sequences
- Privilege escalation chains
- Data leakage chains
- Sequential IDOR exploitation
- New attack types: `privilege_escalation_chain`, `data_leakage_chain`, `idor_chain`

#### WAF Detection & Bypass
- Automatic WAF detection based on response patterns
- WAF bypass techniques (encoding, case manipulation, etc.)
- Configurable detection threshold and retry limits
- New attack type: `waf_bypass`

#### Out-of-Band (OOB) Detection
- Built-in callback server for blind vulnerability detection
- HTTP and DNS callback support
- Blind SSRF, XXE, and command injection detection
- New attack types: `blind_ssrf`, `blind_xxe`, `blind_command_injection`

#### Schema Inference
- Generate OpenAPI specifications from observed traffic
- Configurable confidence thresholds
- Endpoint clustering for pattern detection

#### Business Rules Engine
- Define custom validation rules for API behavior
- YAML-based rule configuration
- Strict mode for CI/CD integration

### Fixed
- Integer-to-string conversion bugs in differential analyzer
- Removed unused regex import in differential.go

### Security
- Auth tokens and cookies excluded from JSON report serialization (`json:"-"` tags)
- Prevents credential leakage in generated reports

### Documentation
- Added advanced configuration section to README
- Documented all new attack types
- Added configuration examples for new features

## [1.0.1] - 2026-01-18

### Added
- Context-aware LLM payload generation (`--use-llm-payloads`)
- Concurrent LLM processing (`--llm-concurrency`)
- New attack generators: SSTI, JWT manipulation, LDAP injection, XPath injection
- Curl commands for finding reproduction in all output formats
- Text output format (Nmap-style terminal output)
- Burp Suite XML export format
- `--no-color` flag for piping text output

### Changed
- Fixed ASCII banner display
- Updated demo GIF

## [1.0.0] - 2026-01-17

### Added
- Initial release of Indago API security fuzzer
- AI-powered API analysis using LLMs (OpenAI, Anthropic, Ollama, LM Studio)
- Multiple input format support (OpenAPI, Postman, HAR, Burp Suite, raw URLs)
- Comprehensive attack coverage:
  - IDOR (Insecure Direct Object Reference)
  - SQL Injection
  - NoSQL Injection
  - Command Injection
  - XSS (Cross-Site Scripting)
  - Authentication Bypass
  - Mass Assignment
  - SSRF (Server-Side Request Forgery)
  - Path Traversal
  - BOLA (Broken Object Level Authorization)
  - BFLA (Broken Function Level Authorization)
  - Rate Limit Bypass
  - Sensitive Data Exposure
- Smart detection with anomaly analysis, error pattern matching, sensitive data leak detection
- Multiple output formats (JSON, HTML, Markdown, SARIF)
- Concurrent scanning with rate limiting
- Session management and authentication support
- Proxy support for debugging

[1.0.2]: https://github.com/Su1ph3r/indago/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Su1ph3r/indago/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Su1ph3r/indago/releases/tag/v1.0.0
