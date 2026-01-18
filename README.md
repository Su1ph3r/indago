# Indago

> *Indago* (Latin): "to track down, investigate"

AI-Powered API Security Fuzzer that uses LLMs to understand API business context and generate intelligent, contextually relevant attack payloads.

## Features

- **AI-Powered Analysis**: Uses LLMs to understand API business logic and generate targeted attacks
- **Multiple Input Formats**: OpenAPI/Swagger, Postman, HAR, Burp Suite exports, raw URLs
- **Multiple LLM Providers**: OpenAI, Anthropic Claude, Ollama, LM Studio
- **Comprehensive Attack Coverage**: IDOR, SQLi, NoSQLi, Command Injection, XSS, Auth Bypass, Mass Assignment, SSRF, Path Traversal
- **Smart Detection**: Anomaly detection, error pattern matching, sensitive data leak detection
- **Multiple Output Formats**: JSON, HTML, Markdown, SARIF (for CI/CD integration)
- **Concurrent Scanning**: Worker pool with rate limiting and session management

## Installation

```bash
# Clone the repository
git clone https://github.com/su1ph3r/indago.git
cd indago

# Build
go build -o indago ./cmd/indago

# Or install directly
go install github.com/su1ph3r/indago/cmd/indago@latest
```

## Quick Start

```bash
# Scan an OpenAPI spec with AI analysis (requires API key)
export ANTHROPIC_API_KEY=your-api-key
indago scan --spec api.yaml --provider anthropic

# Scan without AI (uses heuristic-based analysis)
indago scan --spec api.yaml

# Scan with authentication
indago scan --spec api.yaml --auth-header "Bearer your-token"

# Scan a Postman collection
indago scan --postman collection.json

# Scan from HAR file (exported from browser)
indago scan --har requests.har

# Scan Burp Suite export
indago scan --burp burp-export.xml

# Scan raw endpoints
indago scan --url https://api.example.com --endpoints "/users,/orders,/products/{id}"

# Output to HTML report
indago scan --spec api.yaml -o report -f html

# Use with proxy (e.g., Burp Suite)
indago scan --spec api.yaml --proxy http://127.0.0.1:8080
```

## Configuration

Create `~/.indago.yaml` or use `--config` flag:

```yaml
provider:
  name: anthropic
  api_key: your-api-key
  model: claude-sonnet-4-20250514

scan:
  concurrency: 10
  rate_limit: 10.0
  timeout: 30s

http:
  user_agent: "Custom User Agent"
  proxy_url: "http://127.0.0.1:8080"

attacks:
  enabled:
    - idor
    - sqli
    - auth_bypass
```

Or use environment variables:

```bash
export INDAGO_PROVIDER_NAME=openai
export INDAGO_PROVIDER_API_KEY=sk-xxx
export OPENAI_API_KEY=sk-xxx  # Also supported
```

## CLI Reference

### Scan Command

```
indago scan [flags]

Input Flags:
  -s, --spec string        OpenAPI/Swagger specification file
      --postman string     Postman collection file
      --har string         HAR file
      --burp string        Burp Suite XML export
  -u, --url string         Base URL for raw endpoints
      --endpoints strings  Raw endpoints to scan

LLM Flags:
  -p, --provider string    LLM provider (openai, anthropic, ollama, lmstudio)
      --model string       LLM model to use
      --api-key string     API key for LLM provider
      --llm-url string     Base URL for local LLM

Output Flags:
  -o, --output string      Output file path
  -f, --format string      Output format (json, html, markdown, sarif)
      --verbose            Verbose output

HTTP Flags:
      --auth-header string    Authorization header
      --headers stringToString Additional headers
      --proxy string          HTTP proxy URL

Scan Flags:
      --concurrency int       Concurrent requests (default 10)
      --rate-limit float      Requests per second (default 10)
      --timeout duration      Request timeout (default 30s)
      --no-ssl-verify         Skip SSL verification

Attack Flags:
      --attacks strings       Attack types to enable
      --skip-attacks strings  Attack types to skip
```

### Config Command

```bash
# Set a configuration value
indago config set provider.name anthropic

# Get a configuration value
indago config get provider.name

# Show all configuration
indago config show
```

## Attack Types

| Type | Description |
|------|-------------|
| `idor` | Insecure Direct Object Reference |
| `sqli` | SQL Injection |
| `nosqli` | NoSQL Injection |
| `command_injection` | Command Injection |
| `xss` | Cross-Site Scripting |
| `auth_bypass` | Authentication Bypass |
| `mass_assignment` | Mass Assignment |
| `ssrf` | Server-Side Request Forgery |
| `path_traversal` | Path Traversal |
| `bola` | Broken Object Level Authorization |
| `bfla` | Broken Function Level Authorization |
| `rate_limit` | Rate Limit Bypass |
| `data_exposure` | Sensitive Data Exposure |

## Output Formats

- **JSON**: Machine-readable format for integration
- **HTML**: Interactive web report with dark theme
- **Markdown**: Documentation-friendly format
- **SARIF**: Static Analysis Results Interchange Format for CI/CD

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLI Interface                            │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Input Parsers                             │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │
│  │ OpenAPI │ │ Postman │ │   HAR   │ │  Burp   │ │   Raw   │   │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Business Logic Analyzer                        │
│            (LLM understands context & relationships)             │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Payload Generator                            │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Fuzzer Engine                              │
│    (concurrent requests, rate limiting, session handling)        │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Response Analyzer                             │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Reporter                                 │
└─────────────────────────────────────────────────────────────────┘
```

## License

MIT License - See LICENSE file for details.

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before testing any system. The authors are not responsible for misuse of this tool.
