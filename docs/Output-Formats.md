# Output Formats

Indago supports multiple output formats to integrate with your security testing workflow.

## Available Formats

| Format | Flag | Extension | Use Case |
|--------|------|-----------|----------|
| JSON | `-f json` | `.json` | Automation, CI/CD pipelines, custom processing |
| HTML | `-f html` | `.html` | Interactive reports for stakeholders |
| Markdown | `-f markdown` | `.md` | Documentation, GitHub issues, wikis |
| SARIF | `-f sarif` | `.sarif` | GitHub Code Scanning, IDE integrations |
| Text | `-f text` | `.txt` | Terminal output, quick review |
| Burp | `-f burp` | `.xml` | Burp Suite import for manual testing |

---

## JSON Format

Machine-readable format ideal for automation and integration.

```bash
indago scan --spec api.yaml -f json -o report.json
```

### Structure

```json
{
  "scan_id": "uuid",
  "target": "https://api.example.com",
  "start_time": "2026-01-18T10:00:00Z",
  "end_time": "2026-01-18T10:05:00Z",
  "duration": "5m0s",
  "summary": {
    "total_findings": 10,
    "critical_findings": 0,
    "high_findings": 3,
    "medium_findings": 5,
    "low_findings": 2
  },
  "findings": [
    {
      "id": "finding-uuid",
      "type": "sqli",
      "severity": "high",
      "title": "SQL Injection Detected",
      "endpoint": "https://api.example.com/users",
      "method": "GET",
      "parameter": "id",
      "payload": "' OR '1'='1",
      "curl_command": "curl -X GET 'https://api.example.com/users?id=%27%20OR%20%271%27%3D%271'",
      "replicate_steps": [
        "1. Navigate to the target endpoint: GET https://api.example.com/users",
        "2. Locate the 'id' parameter",
        "3. Submit the following payload: ' OR '1'='1",
        "4. Or use this curl command:\n   curl -X GET 'https://api.example.com/users?id=%27%20OR%20%271%27%3D%271'"
      ],
      "evidence": {
        "request": { ... },
        "response": { ... }
      }
    }
  ]
}
```

### Extracting Curl Commands

```bash
# Get curl command for first finding
indago scan --spec api.yaml -f json | jq -r '.findings[0].curl_command'

# Get all curl commands
indago scan --spec api.yaml -f json | jq -r '.findings[].curl_command'

# Get high severity curl commands
indago scan --spec api.yaml -f json | jq -r '.findings[] | select(.severity == "high") | .curl_command'
```

---

## HTML Format

Interactive web report with dark theme, collapsible sections, and copy-to-clipboard functionality.

```bash
indago scan --spec api.yaml -f html -o report.html
```

### Features

- **Dark theme** optimized for security professionals
- **Severity badges** with color coding
- **Collapsible evidence** sections for request/response data
- **Copy-to-clipboard** button for curl commands
- **Vulnerability summary** dashboard
- **Matched patterns** highlighting

---

## Markdown Format

Documentation-friendly format for GitHub issues, wikis, and reports.

```bash
indago scan --spec api.yaml -f markdown -o report.md
```

### Structure

- Summary table with scan metadata
- Findings grouped by severity
- Each finding includes:
  - Details table (type, confidence, endpoint, CWE, CVSS)
  - Description
  - Payload (in code block)
  - Evidence (collapsible)
  - Remediation
  - **Steps to Reproduce** with curl command

---

## SARIF Format

Static Analysis Results Interchange Format for CI/CD integration.

```bash
indago scan --spec api.yaml -f sarif -o report.sarif
```

### GitHub Code Scanning Integration

```yaml
# .github/workflows/security.yml
name: API Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Indago
        run: |
          indago scan --spec api.yaml -f sarif -o results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### SARIF Properties

Each finding includes:
- `ruleId`: Vulnerability type
- `level`: error/warning/note based on severity
- `message`: Finding description
- `locations`: Endpoint information
- `properties.curlCommand`: Curl command for reproduction

---

## Text Format (Nmap-style)

Terminal-friendly output inspired by Nmap's format.

```bash
# Print to stdout (default when no -o specified)
indago scan --spec api.yaml -f text

# Disable colors for piping
indago scan --spec api.yaml -f text --no-color | tee report.txt

# Save to file
indago scan --spec api.yaml -f text -o report.txt
```

### Example Output

```
Starting Indago 1.0.0 ( https://github.com/su1ph3r/indago )
Scan report for https://api.example.com
Scan started at 2026-01-18 10:00 EST

Scanned 12 endpoints in 2m30s (767 requests)

VULNERABILITY SUMMARY
SEVERITY     COUNT
CRITICAL     0
HIGH         3
MEDIUM       5
LOW          2
TOTAL        10

FINDINGS DETAIL
----------------------------------------------------------------------
[HIGH] SQL Injection Detected
    Endpoint:   GET /users
    Type:       sqli
    Parameter:  id
    CWE:        CWE-89
    Replicate:  curl -X GET 'https://api.example.com/users?id=%27...'

[HIGH] Authentication Bypass
    Endpoint:   POST /login
    Type:       auth_bypass
    Parameter:  admin
    CWE:        CWE-287
    Replicate:  curl -X POST -d '{"admin":true}' 'https://...'

----------------------------------------------------------------------
Scan completed at 2026-01-18 10:02 EST
Indago done: 12 endpoints scanned, 10 findings
```

---

## Burp Suite XML Format

Export findings for import into Burp Suite for manual verification and further testing.

```bash
indago scan --spec api.yaml -f burp -o findings.xml
```

### Importing into Burp Suite

1. Generate the Burp XML export:
   ```bash
   indago scan --spec api.yaml -f burp -o findings.xml
   ```

2. Open Burp Suite

3. Go to **Target** > **Site map**

4. Right-click > **Import** > **From file**

5. Select `findings.xml`

### XML Structure

The export follows Burp Suite's XML format:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<items burpVersion="2023.1">
  <item>
    <time>Sat Jan 18 10:00:00 EST 2026</time>
    <url>https://api.example.com/users?id=1</url>
    <host>api.example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/users?id=1</path>
    <request base64="true">R0VUIC91c2Vycy4uLg==</request>
    <status>200</status>
    <responselength>1234</responselength>
    <mimetype>application/json</mimetype>
    <response base64="true">SFRUUC8xLjEgMjAw...</response>
    <comment>[HIGH] SQL Injection Detected - sqli (CWE-89)</comment>
  </item>
</items>
```

### Use Cases

- **Manual verification** of automated findings
- **Exploitation** using Burp's tools (Repeater, Intruder)
- **Session handling** for authenticated endpoints
- **Traffic interception** for deeper analysis

---

## Multiple Formats

Generate reports in multiple formats simultaneously:

```bash
# Generate JSON and HTML
indago scan --spec api.yaml -f json -o report.json
indago scan --spec api.yaml -f html -o report.html

# Or use shell scripting
for fmt in json html markdown sarif; do
  indago scan --spec api.yaml -f $fmt -o "report.$fmt"
done
```
