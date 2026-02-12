# Changelog

All notable changes to Indago will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.1] - 2026-02-12

### Improved
- **Report findings sorted by severity**: All output formats (HTML, JSON, SARIF, Burp XML) now sort findings from Critical → High → Medium → Low → Info for easier triage
- **Actual HTTP request/response in evidence**: Reports now show the real HTTP request that was sent (including payload-injected URL, session/auth headers, request body) instead of reconstructed endpoint metadata
- **Full evidence bodies**: Removed artificial truncation of request and response bodies in HTML, JSON, and Markdown reports — full evidence is now preserved for accurate analysis

## [1.2.1] - 2026-02-12

### Added
- `--context` CLI flag for providing user-defined API context to LLM analysis (e.g., `--context "E-commerce API with payment processing and user accounts"`)
- `user_context` YAML config field for persistent API context configuration
- User context is injected into both business analysis and payload generation prompts for more targeted security testing

## [1.2.0] - 2026-02-09

### Added

#### Cross-Tool Integration
- `--targets-from` flag for importing endpoints from Reticustos or Ariadne JSON exports
- `--export-waf-blocked` flag for exporting WAF-blocked findings in BypassBurrito-compatible format
- Export source validation for imported endpoint files
- Placeholder hostname warning for incomplete endpoint data
- WAF export file permissions set to 0600 for security

## [1.1.0] - 2026-01-26

### Added

#### Interactive Features
- **Interactive TUI Mode**: Real-time progress display with progress bars, findings list with keyboard navigation (j/k, up/down), interactive triage view for marking findings as true/false positive, pause/resume scan functionality. Use `--interactive` flag or `indago interactive` command.
- **Scan Checkpointing**: Save scan progress automatically and resume interrupted scans. Use `--checkpoint` to set checkpoint file path and `--resume` to continue from a checkpoint.
- **Dry Run Mode**: Preview all requests that would be sent without making actual HTTP calls. Use `--dry-run` flag.
- **Request/Response Logging**: Log all HTTP requests and responses to JSON file for offline analysis. Use `--log-requests <file>` flag.
- **Finding Verification**: Re-test findings with payload variations to confirm vulnerabilities. Use `--verify` flag.
- **Configuration Validation**: Validate config files with detailed error messages. Use `--validate-config` flag.

#### Credential Management
- **Secure Credential Storage**: New `indago credentials` command with `set`, `get`, `list`, `delete` subcommands.
- **Platform Keychain Integration**: Uses macOS Keychain on macOS, Linux Secret Service on Linux.
- **Encrypted File Fallback**: AES-256-GCM encrypted storage using machine-specific key derivation.

#### Configuration Profiles
- `configs/idor-focus.yaml` - IDOR/BOLA focused scanning with differential analysis settings
- `configs/injection-focus.yaml` - Injection attacks focus (SQL, NoSQL, Command, SSTI, LDAP, XPath)
- `configs/ci-quick.yaml` - Fast CI pipeline scans with SARIF output and limited payloads
- `configs/thorough.yaml` - Comprehensive security audit with all features enabled

#### Backend Improvements
- **False Positive Filtering**: Confidence scoring based on evidence strength, severity-based filtering, pattern-based noise reduction, finding deduplication by endpoint.
- **Request Caching**: Baseline response caching, request fingerprinting to avoid duplicates, LRU eviction for memory efficiency.
- **LLM Rate Limiting**: Per-provider rate limiters with configurable tokens/refill, automatic backoff on 429 responses, exponential retry with jitter.
- **Token Usage Tracking**: Track input/output tokens per provider with budget limits.
- **Plugin System**: `AttackPlugin` interface for custom payload generators, `ResponseMatcher` interface for custom detection, external payload file loading.
- **Scan Statistics**: Detailed metrics including requests/sec, avg/min/max response times, success/failure counts, bytes sent/received.

#### Test Suite
- Unit tests for payload generators (IDOR, injection, generator)
- Unit tests for detectors (analyzer, anomaly detection)
- Integration tests for parsers (OpenAPI)
- Mock LLM provider for testing
- Test fixtures: `testdata/petstore.yaml`, `testdata/postman_collection.json`, `testdata/sample.har`

### Changed
- Improved error messages with actionable suggestions
- Memory-efficient processing for large API specifications

## [1.0.3] - 2026-01-20

### Added
- Burp Suite extension for importing Indago findings directly into Burp.

### Fixed
- Code quality and security issues in Burp extension.

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

[1.2.0]: https://github.com/Su1ph3r/indago/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Su1ph3r/indago/compare/v1.0.3...v1.1.0
[1.0.3]: https://github.com/Su1ph3r/indago/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/Su1ph3r/indago/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Su1ph3r/indago/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Su1ph3r/indago/releases/tag/v1.0.0
