# Reproducing Findings

Every finding in Indago includes curl commands and step-by-step instructions for reproduction. This enables quick verification and demonstration of vulnerabilities.

## Curl Commands

Indago automatically generates curl commands for each finding based on the evidence captured during scanning.

### JSON Output

```bash
# Get the curl command for the first finding
indago scan --spec api.yaml -f json | jq -r '.findings[0].curl_command'

# Output:
# curl -X GET -H 'Authorization: Bearer token123' 'https://api.example.com/users?id=%27%20OR%20%271%27%3D%271'
```

### HTML Output

The HTML report includes a "Reproduce with curl" section for each finding:

1. Click on a finding to expand it
2. Scroll to the "Reproduce with curl" section
3. Click the **Copy** button to copy the command
4. Paste and execute in your terminal

### Text Output

The text format shows truncated curl commands inline:

```
[HIGH] SQL Injection Detected
    Endpoint:   GET /users
    Parameter:  id
    Replicate:  curl -X GET 'https://api.example.com/users?id=%27...'
```

---

## Replication Steps

Each finding includes numbered steps for manual reproduction:

```json
{
  "replicate_steps": [
    "1. Navigate to the target endpoint: GET https://api.example.com/users",
    "2. Locate the 'id' parameter",
    "3. Submit the following payload: ' OR '1'='1",
    "4. Or use this curl command:\n   curl -X GET 'https://api.example.com/users?id=%27%20OR%20%271%27%3D%271'"
  ]
}
```

---

## Shell Escaping

Curl commands are safely escaped for POSIX shells (bash, sh, zsh):

- Single quotes are used for values containing special characters
- Shell metacharacters are properly escaped
- URLs are percent-encoded where necessary

**Note:** On Windows, you may need to adjust the quoting style for cmd.exe or PowerShell.

### Windows PowerShell

```powershell
# Convert single quotes to double quotes
$cmd = "curl -X GET 'https://api.example.com/users?id=test'"
$cmd = $cmd -replace "'", '"'
Invoke-Expression $cmd
```

### Windows cmd.exe

```cmd
# Use double quotes and escape special characters
curl -X GET "https://api.example.com/users?id=test"
```

---

## Workflow Examples

### Quick Verification

```bash
# Run scan and immediately test first high-severity finding
CURL_CMD=$(indago scan --spec api.yaml -f json 2>/dev/null | \
  jq -r '.findings[] | select(.severity == "high") | .curl_command' | head -1)

echo "Testing: $CURL_CMD"
eval $CURL_CMD
```

### Batch Verification

```bash
# Extract all curl commands to a script
indago scan --spec api.yaml -f json | \
  jq -r '.findings[].curl_command' > verify_findings.sh

# Review and execute
chmod +x verify_findings.sh
./verify_findings.sh
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Verify Critical Findings
  run: |
    # Run scan
    indago scan --spec api.yaml -f json -o results.json

    # Check for critical findings
    CRITICAL=$(jq '.summary.critical_findings' results.json)
    if [ "$CRITICAL" -gt 0 ]; then
      echo "Critical findings detected!"
      jq -r '.findings[] | select(.severity == "critical") | .curl_command' results.json
      exit 1
    fi
```

### Burp Suite Integration

```bash
# Export findings to Burp format
indago scan --spec api.yaml -f burp -o findings.xml

# Import into Burp Suite, then use Repeater to:
# 1. Modify payloads
# 2. Test variations
# 3. Verify exploitability
```

---

## Curl Command Options

The generated curl commands include:

| Component | Description |
|-----------|-------------|
| Method | `-X POST`, `-X PUT`, etc. (omitted for GET) |
| Headers | `-H 'Header: Value'` for each captured header |
| Body | `-d 'data'` for request bodies |
| URL | Fully qualified URL with encoded parameters |

### Headers Included

- `Authorization` (if present)
- `Content-Type`
- Custom headers from the original request

### Headers Excluded

- `Host` (handled by curl automatically)
- `Content-Length` (calculated by curl)
- `Accept-Encoding` (curl handles compression)
- `Connection` (managed by curl)

---

## Security Considerations

**Always exercise caution when executing curl commands:**

1. **Review before executing** - Commands may contain attack payloads
2. **Test environment only** - Only execute against authorized targets
3. **Avoid production** - Payloads may cause data corruption or service disruption
4. **Log everything** - Keep records of testing activities
5. **Get authorization** - Ensure you have permission to test

---

## Troubleshooting

### Command fails with "connection refused"

The target may not be accessible. Check:
- Network connectivity
- VPN/firewall settings
- Target availability

### SSL certificate errors

Add `-k` flag to bypass certificate verification (testing only):

```bash
curl -k -X GET 'https://api.example.com/...'
```

### Authentication expired

The captured auth tokens may have expired. Re-run with fresh authentication:

```bash
indago scan --spec api.yaml --auth-header "Bearer NEW_TOKEN"
```

### Payload not working

The vulnerability may be:
- Already patched
- Context-dependent
- Requiring specific session state

Use Burp Suite for interactive testing and payload modification.
