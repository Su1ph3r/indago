# Indago

> *Indago* (Latin): "to track down, investigate"

AI-Powered API Security Fuzzer that uses LLMs to understand API business context and generate intelligent, contextually relevant attack payloads.

![Indago Demo](demo.gif)

<details>
<summary>Scan Results Summary</summary>

![Scan Results](demo-results.gif)

</details>

> **Demo**: Scanning [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) with AI-powered analysis. The LLM analyzed 12 endpoints and generated **942 context-aware payloads**, discovering **469 vulnerabilities** (177 High, 155 Medium, 137 Low) including SQL injection, authentication bypass, and sensitive data exposure.

## Features

- **AI-Powered Analysis**: Uses LLMs to understand API business logic and generate targeted attacks
- **Context-Aware Payloads**: LLM-generated payloads based on endpoint semantics and business context
- **Parallel LLM Processing**: Concurrent LLM calls for fast payload generation on powerful hardware
- **Multiple Input Formats**: OpenAPI/Swagger, Postman, HAR, Burp Suite exports, raw URLs
- **Multiple LLM Providers**: OpenAI, Anthropic Claude, Ollama, LM Studio
- **Comprehensive Attack Coverage**: IDOR, SQLi, NoSQLi, Command Injection, XSS, Auth Bypass, Mass Assignment, SSRF, Path Traversal
- **Smart Detection**: Anomaly detection, error pattern matching, sensitive data leak detection
- **Multiple Output Formats**: JSON, HTML, Markdown, SARIF, Text (Nmap-style), Burp Suite XML
- **Reproducible Findings**: Every finding includes curl commands for easy reproduction
- **Concurrent Scanning**: Worker pool with rate limiting and session management

## Installation

### Pre-built Binaries

Download the latest release for your platform from the [Releases](https://github.com/Su1ph3r/indago/releases) page.

```bash
# Linux (amd64)
curl -L https://github.com/Su1ph3r/indago/releases/latest/download/indago-linux-amd64.tar.gz | tar xz
sudo mv indago /usr/local/bin/

# macOS (Apple Silicon)
curl -L https://github.com/Su1ph3r/indago/releases/latest/download/indago-darwin-arm64.tar.gz | tar xz
sudo mv indago /usr/local/bin/

# macOS (Intel)
curl -L https://github.com/Su1ph3r/indago/releases/latest/download/indago-darwin-amd64.tar.gz | tar xz
sudo mv indago /usr/local/bin/
```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/Su1ph3r/indago.git
cd indago

# Build
go build -o indago ./cmd/indago

# Or install directly
go install github.com/Su1ph3r/indago/cmd/indago@latest
```

## Quick Start

```bash
# Scan an OpenAPI spec with AI analysis (requires API key)
export ANTHROPIC_API_KEY=your-api-key
indago scan --spec api.yaml --provider anthropic

# Full AI-powered scan with dynamic LLM payloads (local LLM)
indago scan --spec api.yaml --provider lmstudio --llm-url http://localhost:1234/v1 \
  --use-llm-payloads --llm-concurrency 20

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

# Nmap-style text output to terminal
indago scan --spec api.yaml -f text

# Export for Burp Suite
indago scan --spec api.yaml -f burp -o findings.xml

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
  -p, --provider string       LLM provider (openai, anthropic, ollama, lmstudio)
      --model string          LLM model to use
      --api-key string        API key for LLM provider
      --llm-url string        Base URL for local LLM
      --use-llm-payloads      Generate context-aware payloads using LLM
      --llm-concurrency int   Concurrent LLM payload generators (default 8)

Output Flags:
  -o, --output string      Output file path (text format prints to stdout if not specified)
  -f, --format string      Output format (json, html, markdown, sarif, text, burp)
      --verbose            Verbose output
      --no-color           Disable colored output (useful for piping text format)

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

| Format | Extension | Description |
|--------|-----------|-------------|
| `json` | `.json` | Machine-readable format with curl commands and replication steps |
| `html` | `.html` | Interactive web report with dark theme and copy-to-clipboard curl commands |
| `markdown` | `.md` | Documentation-friendly format with code blocks |
| `sarif` | `.sarif` | Static Analysis Results Interchange Format for CI/CD integration |
| `text` | `.txt` | Nmap-style terminal output (prints to stdout by default) |
| `burp` | `.xml` | Burp Suite compatible XML for importing findings |

### Text Output (Nmap-style)

```bash
# Print to terminal
indago scan --spec api.yaml -f text

# Pipe to file or other tools
indago scan --spec api.yaml -f text --no-color | tee report.txt

# Save directly to file
indago scan --spec api.yaml -f text -o report.txt
```

### Burp Suite Integration

Export findings for import into Burp Suite:

```bash
indago scan --spec api.yaml -f burp -o findings.xml
# Then: Burp Suite > Target > Import > Paste from file
```

### Curl Commands for Reproduction

All output formats now include curl commands for easy reproduction of findings:

```bash
# JSON output includes curl_command and replicate_steps fields
indago scan --spec api.yaml -f json | jq '.findings[0].curl_command'

# HTML report has "Reproduce with curl" section with copy button
# Markdown includes "Steps to Reproduce" code blocks
```

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
