package reporter

import (
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/su1ph3r/indago/pkg/types"
)

// HTMLReporter generates HTML reports
type HTMLReporter struct {
	options ReportOptions
}

// NewHTMLReporter creates a new HTML reporter
func NewHTMLReporter(options ReportOptions) *HTMLReporter {
	return &HTMLReporter{options: options}
}

// Format returns the format name
func (r *HTMLReporter) Format() string {
	return "html"
}

// Extension returns the file extension
func (r *HTMLReporter) Extension() string {
	return "html"
}

// Generate generates an HTML report
func (r *HTMLReporter) Generate(result *types.ScanResult) ([]byte, error) {
	var buf strings.Builder
	if err := r.Write(result, &buf); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// Write writes the HTML report to a writer
func (r *HTMLReporter) Write(result *types.ScanResult, w io.Writer) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"severityClass": severityClass,
		"severityIcon":  severityIconHTML,
		"truncate":      TruncateString,
		"formatTime":    formatTime,
		"escapeHTML":    template.HTMLEscapeString,
		"generateCurl":  generateCurlForFinding,
		"safeID":        sanitizeID,
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	data := struct {
		*types.ScanResult
		Title       string
		GeneratedAt string
		Options     ReportOptions
	}{
		ScanResult:  result,
		Title:       r.options.Title,
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Options:     r.options,
	}

	return tmpl.Execute(w, data)
}

func severityClass(severity string) string {
	switch severity {
	case types.SeverityCritical:
		return "critical"
	case types.SeverityHigh:
		return "high"
	case types.SeverityMedium:
		return "medium"
	case types.SeverityLow:
		return "low"
	case types.SeverityInfo:
		return "info"
	default:
		return "unknown"
	}
}

func severityIconHTML(severity string) string {
	switch severity {
	case types.SeverityCritical:
		return "&#9888;"
	case types.SeverityHigh:
		return "&#9888;"
	case types.SeverityMedium:
		return "&#9888;"
	case types.SeverityLow:
		return "&#8505;"
	case types.SeverityInfo:
		return "&#8505;"
	default:
		return "&#8226;"
	}
}

func formatTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}

func generateCurlForFinding(f types.Finding) string {
	return GenerateCurlFromFinding(&f)
}

// sanitizeID removes or replaces characters that are not safe for HTML IDs
func sanitizeID(s string) string {
	var result strings.Builder
	for _, c := range s {
		// Allow alphanumeric, dash, and underscore only
		if (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' {
			result.WriteRune(c)
		} else {
			result.WriteRune('_') // Replace unsafe chars with underscore
		}
	}
	return result.String()
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        :root {
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #2563eb;
            --info: #0891b2;
            --bg: #0f172a;
            --bg-card: #1e293b;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --border: #334155;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }

        .container { max-width: 1200px; margin: 0 auto; }

        header {
            text-align: center;
            margin-bottom: 2rem;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--border);
        }

        h1 { font-size: 2rem; margin-bottom: 0.5rem; }
        .subtitle { color: var(--text-muted); }

        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--bg-card);
            padding: 1.5rem;
            border-radius: 8px;
            text-align: center;
        }

        .stat-value { font-size: 2rem; font-weight: bold; }
        .stat-label { color: var(--text-muted); font-size: 0.875rem; }

        .stat-critical .stat-value { color: var(--critical); }
        .stat-high .stat-value { color: var(--high); }
        .stat-medium .stat-value { color: var(--medium); }
        .stat-low .stat-value { color: var(--low); }

        .findings { margin-top: 2rem; }

        .finding {
            background: var(--bg-card);
            border-radius: 8px;
            margin-bottom: 1rem;
            overflow: hidden;
        }

        .finding-header {
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 1rem 1.5rem;
            cursor: pointer;
            border-left: 4px solid;
        }

        .finding-header.critical { border-color: var(--critical); }
        .finding-header.high { border-color: var(--high); }
        .finding-header.medium { border-color: var(--medium); }
        .finding-header.low { border-color: var(--low); }
        .finding-header.info { border-color: var(--info); }

        .severity-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .severity-badge.critical { background: var(--critical); }
        .severity-badge.high { background: var(--high); }
        .severity-badge.medium { background: var(--medium); }
        .severity-badge.low { background: var(--low); }
        .severity-badge.info { background: var(--info); }

        .finding-title { flex: 1; font-weight: 600; }
        .finding-endpoint { color: var(--text-muted); font-family: monospace; font-size: 0.875rem; }

        .finding-details {
            padding: 1.5rem;
            border-top: 1px solid var(--border);
            display: none;
        }

        .finding.open .finding-details { display: block; }

        .detail-section { margin-bottom: 1rem; }
        .detail-section:last-child { margin-bottom: 0; }
        .detail-label { color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; margin-bottom: 0.25rem; }

        .code-block {
            background: var(--bg);
            padding: 1rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.875rem;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .evidence-section {
            margin-top: 1rem;
            border: 1px solid var(--border);
            border-radius: 6px;
            overflow: hidden;
        }

        .evidence-header {
            background: var(--bg);
            padding: 0.75rem 1rem;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-weight: 600;
            font-size: 0.875rem;
        }

        .evidence-header:hover {
            background: rgba(255,255,255,0.05);
        }

        .evidence-header .arrow {
            transition: transform 0.2s;
        }

        .evidence-section.open .evidence-header .arrow {
            transform: rotate(90deg);
        }

        .evidence-content {
            display: none;
            padding: 1rem;
            background: var(--bg);
        }

        .evidence-section.open .evidence-content {
            display: block;
        }

        .http-line {
            color: var(--info);
            font-weight: 600;
            margin-bottom: 0.5rem;
        }

        .http-headers {
            color: var(--text-muted);
            font-size: 0.8rem;
            margin-bottom: 0.5rem;
        }

        .http-body {
            background: rgba(0,0,0,0.3);
            padding: 0.75rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.8rem;
            max-height: 200px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .status-success { color: #22c55e; }
        .status-redirect { color: var(--medium); }
        .status-client-error { color: var(--high); }
        .status-server-error { color: var(--critical); }

        .matched-patterns {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.5rem;
        }

        .pattern-badge {
            background: rgba(234, 88, 12, 0.2);
            color: var(--high);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-family: monospace;
        }

        .reproduce-section {
            margin-top: 1rem;
            border: 1px solid var(--border);
            border-radius: 6px;
            overflow: hidden;
        }

        .reproduce-header {
            background: rgba(34, 197, 94, 0.1);
            padding: 0.75rem 1rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-weight: 600;
            font-size: 0.875rem;
            color: #22c55e;
        }

        .reproduce-content {
            padding: 1rem;
            background: var(--bg);
        }

        .curl-command {
            background: rgba(0,0,0,0.3);
            padding: 1rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.8rem;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            position: relative;
        }

        .copy-btn {
            position: absolute;
            top: 0.5rem;
            right: 0.5rem;
            background: var(--border);
            border: none;
            color: var(--text);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.75rem;
        }

        .copy-btn:hover {
            background: #475569;
        }

        .copy-btn.copied {
            background: #22c55e;
        }

        .meta-info {
            display: flex;
            gap: 2rem;
            flex-wrap: wrap;
            margin-top: 2rem;
            padding-top: 2rem;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 0.875rem;
        }

        footer {
            text-align: center;
            margin-top: 3rem;
            padding-top: 2rem;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{{.Title}}</h1>
            <p class="subtitle">Target: {{.Target}} | Generated: {{.GeneratedAt}}</p>
        </header>

        <section class="summary">
            <div class="stat-card stat-critical">
                <div class="stat-value">{{.Summary.CriticalFindings}}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card stat-high">
                <div class="stat-value">{{.Summary.HighFindings}}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card stat-medium">
                <div class="stat-value">{{.Summary.MediumFindings}}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card stat-low">
                <div class="stat-value">{{.Summary.LowFindings}}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.Endpoints}}</div>
                <div class="stat-label">Endpoints</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{.Requests}}</div>
                <div class="stat-label">Requests</div>
            </div>
        </section>

        <section class="findings">
            <h2>Findings</h2>
            {{range .Findings}}
            <div class="finding">
                <div class="finding-header {{severityClass .Severity}}" onclick="this.parentElement.classList.toggle('open')">
                    <span class="severity-badge {{severityClass .Severity}}">{{.Severity}}</span>
                    <span class="finding-title">{{.Title}}</span>
                    <span class="finding-endpoint">{{.Method}} {{.Endpoint}}</span>
                </div>
                <div class="finding-details">
                    <div class="detail-section">
                        <div class="detail-label">Description</div>
                        <p>{{.Description}}</p>
                    </div>
                    {{if .Parameter}}
                    <div class="detail-section">
                        <div class="detail-label">Parameter</div>
                        <p>{{.Parameter}}</p>
                    </div>
                    {{end}}
                    {{if .Payload}}
                    <div class="detail-section">
                        <div class="detail-label">Payload</div>
                        <div class="code-block">{{.Payload}}</div>
                    </div>
                    {{end}}
                    {{if .CWE}}
                    <div class="detail-section">
                        <div class="detail-label">CWE</div>
                        <p>{{.CWE}}</p>
                    </div>
                    {{end}}
                    {{if .Remediation}}
                    <div class="detail-section">
                        <div class="detail-label">Remediation</div>
                        <p>{{.Remediation}}</p>
                    </div>
                    {{end}}
                    {{if .Evidence}}
                    {{if .Evidence.Request}}
                    <div class="evidence-section" onclick="this.classList.toggle('open')">
                        <div class="evidence-header">
                            <span class="arrow">▶</span> Request
                        </div>
                        <div class="evidence-content">
                            <div class="http-line">{{.Evidence.Request.Method}} {{.Evidence.Request.URL}}</div>
                            {{if .Evidence.Request.Headers}}
                            <div class="http-headers">
                                {{range $key, $value := .Evidence.Request.Headers}}{{$key}}: {{$value}}<br>{{end}}
                            </div>
                            {{end}}
                            {{if .Evidence.Request.Body}}
                            <div class="detail-label">Body</div>
                            <div class="http-body">{{truncate .Evidence.Request.Body 1000}}</div>
                            {{end}}
                        </div>
                    </div>
                    {{end}}
                    {{if .Evidence.Response}}
                    <div class="evidence-section" onclick="this.classList.toggle('open')">
                        <div class="evidence-header">
                            <span class="arrow">▶</span> Response
                            <span class="{{if lt .Evidence.Response.StatusCode 300}}status-success{{else if lt .Evidence.Response.StatusCode 400}}status-redirect{{else if lt .Evidence.Response.StatusCode 500}}status-client-error{{else}}status-server-error{{end}}">
                                ({{.Evidence.Response.StatusCode}})
                            </span>
                        </div>
                        <div class="evidence-content">
                            <div class="http-line">HTTP {{.Evidence.Response.StatusCode}} {{.Evidence.Response.Status}}</div>
                            {{if .Evidence.Response.Headers}}
                            <div class="http-headers">
                                {{range $key, $value := .Evidence.Response.Headers}}{{$key}}: {{$value}}<br>{{end}}
                            </div>
                            {{end}}
                            {{if .Evidence.Response.Body}}
                            <div class="detail-label">Body</div>
                            <div class="http-body">{{truncate .Evidence.Response.Body 2000}}</div>
                            {{end}}
                        </div>
                    </div>
                    {{end}}
                    {{if .Evidence.MatchedData}}
                    <div class="detail-section">
                        <div class="detail-label">Matched Patterns</div>
                        <div class="matched-patterns">
                            {{range .Evidence.MatchedData}}<span class="pattern-badge">{{.}}</span>{{end}}
                        </div>
                    </div>
                    {{end}}
                    {{end}}
                    {{$curl := generateCurl .}}
                    {{if $curl}}
                    <div class="reproduce-section">
                        <div class="reproduce-header">
                            <span>Reproduce with curl</span>
                        </div>
                        <div class="reproduce-content">
                            <div class="curl-command" id="curl-{{safeID .ID}}">
                                <button class="copy-btn" onclick="copyToClipboard('curl-{{safeID .ID}}', this)">Copy</button>
                                {{$curl}}
                            </div>
                        </div>
                    </div>
                    {{end}}
                </div>
            </div>
            {{else}}
            <p style="text-align: center; color: var(--text-muted); padding: 2rem;">No findings detected.</p>
            {{end}}
        </section>

        <div class="meta-info">
            <div>Scan ID: {{.ScanID}}</div>
            <div>Duration: {{.Duration}}</div>
            <div>Start: {{formatTime .StartTime}}</div>
            <div>End: {{formatTime .EndTime}}</div>
        </div>

        <footer>
            <p>Generated by Indago - AI-Powered API Security Fuzzer</p>
        </footer>
    </div>
    <script>
        function copyToClipboard(elementId, button) {
            const element = document.getElementById(elementId);
            // Get text content, excluding the button text
            let text = element.textContent.replace('Copy', '').trim();
            navigator.clipboard.writeText(text).then(function() {
                button.textContent = 'Copied!';
                button.classList.add('copied');
                setTimeout(function() {
                    button.textContent = 'Copy';
                    button.classList.remove('copied');
                }, 2000);
            }).catch(function(err) {
                console.error('Failed to copy: ', err);
            });
        }
    </script>
</body>
</html>`
