// Package reporter provides output formatting for scan results
package reporter

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// BurpReporter generates Burp Suite compatible XML exports
type BurpReporter struct {
	options ReportOptions
}

// NewBurpReporter creates a new Burp XML reporter
func NewBurpReporter(options ReportOptions) *BurpReporter {
	return &BurpReporter{options: options}
}

// Format returns the format name
func (r *BurpReporter) Format() string {
	return "burp"
}

// Extension returns the file extension
func (r *BurpReporter) Extension() string {
	return "xml"
}

// Generate generates a Burp XML report
func (r *BurpReporter) Generate(result *types.ScanResult) ([]byte, error) {
	var buf strings.Builder
	if err := r.Write(result, &buf); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// Write writes the Burp XML report to a writer
func (r *BurpReporter) Write(result *types.ScanResult, w io.Writer) error {
	export := r.buildExport(result)

	// Write XML header
	if _, err := w.Write([]byte(xml.Header)); err != nil {
		return err
	}

	encoder := xml.NewEncoder(w)
	encoder.Indent("", "  ")
	return encoder.Encode(export)
}

// BurpExport represents a Burp Suite XML export
type BurpExport struct {
	XMLName xml.Name   `xml:"items"`
	Version string     `xml:"burpVersion,attr"`
	Items   []BurpItem `xml:"item"`
}

// BurpItem represents a single request/response in Burp format
type BurpItem struct {
	Time           string   `xml:"time"`
	URL            string   `xml:"url"`
	Host           BurpHost `xml:"host"`
	Port           string   `xml:"port"`
	Protocol       string   `xml:"protocol"`
	Method         string   `xml:"method"`
	Path           string   `xml:"path"`
	Extension      string   `xml:"extension,omitempty"`
	Request        BurpData `xml:"request"`
	Status         string   `xml:"status"`
	ResponseLength string   `xml:"responselength"`
	MimeType       string   `xml:"mimetype"`
	Response       BurpData `xml:"response"`
	Comment        string   `xml:"comment"`
}

// BurpHost represents the host element with IP attribute
type BurpHost struct {
	IP    string `xml:"ip,attr,omitempty"`
	Value string `xml:",chardata"`
}

// BurpData represents base64-encoded data
type BurpData struct {
	Base64 bool   `xml:"base64,attr"`
	Value  string `xml:",chardata"`
}

// buildExport builds the Burp export structure from scan results
func (r *BurpReporter) buildExport(result *types.ScanResult) *BurpExport {
	export := &BurpExport{
		Version: "2023.1", // Burp version compatibility
		Items:   make([]BurpItem, 0, len(result.Findings)),
	}

	for _, finding := range result.Findings {
		item := r.buildItem(finding)
		export.Items = append(export.Items, item)
	}

	return export
}

// buildItem builds a Burp item from a finding
func (r *BurpReporter) buildItem(finding types.Finding) BurpItem {
	// Parse the endpoint URL
	parsedURL, err := url.Parse(finding.Endpoint)
	if err != nil {
		parsedURL = &url.URL{
			Scheme: "http",
			Host:   "unknown",
			Path:   finding.Endpoint,
		}
	}

	// Determine protocol and port
	protocol := parsedURL.Scheme
	if protocol == "" {
		protocol = "http"
	}

	port := parsedURL.Port()
	if port == "" {
		if protocol == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	host := parsedURL.Hostname()
	if host == "" {
		host = parsedURL.Host
	}

	path := parsedURL.Path
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	}
	if path == "" {
		path = "/"
	}

	// Build raw request
	rawRequest := r.buildRawRequest(finding)
	rawResponse := r.buildRawResponse(finding)

	// Create comment from finding info
	comment := fmt.Sprintf("[%s] %s - %s",
		strings.ToUpper(finding.Severity),
		finding.Title,
		finding.Type)

	if finding.CWE != "" {
		comment += " (" + finding.CWE + ")"
	}

	// Get status code
	status := "0"
	mimeType := ""
	responseLength := "0"
	if finding.Evidence != nil && finding.Evidence.Response != nil {
		status = fmt.Sprintf("%d", finding.Evidence.Response.StatusCode)
		responseLength = fmt.Sprintf("%d", finding.Evidence.Response.ContentLength)
		if ct, ok := finding.Evidence.Response.Headers["Content-Type"]; ok {
			mimeType = ct
		}
	}

	item := BurpItem{
		Time:     finding.Timestamp.Format("Mon Jan 02 15:04:05 MST 2006"),
		URL:      finding.Endpoint,
		Host:     BurpHost{Value: host},
		Port:     port,
		Protocol: protocol,
		Method:   finding.Method,
		Path:     path,
		Request: BurpData{
			Base64: true,
			Value:  base64.StdEncoding.EncodeToString([]byte(rawRequest)),
		},
		Status:         status,
		ResponseLength: responseLength,
		MimeType:       mimeType,
		Response: BurpData{
			Base64: true,
			Value:  base64.StdEncoding.EncodeToString([]byte(rawResponse)),
		},
		Comment: comment,
	}

	return item
}

// buildRawRequest builds a raw HTTP request string
func (r *BurpReporter) buildRawRequest(finding types.Finding) string {
	if finding.Evidence != nil && finding.Evidence.Request != nil {
		req := finding.Evidence.Request
		var sb strings.Builder

		// Parse URL for path and host
		parsedURL, err := url.Parse(req.URL)
		if err != nil {
			parsedURL = &url.URL{Path: "/"}
		}

		path := parsedURL.Path
		if parsedURL.RawQuery != "" {
			path += "?" + parsedURL.RawQuery
		}
		if path == "" {
			path = "/"
		}

		// Request line
		sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", req.Method, path))

		// Host header
		host := parsedURL.Host
		if host != "" {
			sb.WriteString(fmt.Sprintf("Host: %s\r\n", host))
		}

		// Other headers
		for name, value := range req.Headers {
			if strings.ToLower(name) == "host" {
				continue // Already added
			}
			sb.WriteString(fmt.Sprintf("%s: %s\r\n", name, value))
		}

		// Blank line and body
		sb.WriteString("\r\n")
		if req.Body != "" {
			sb.WriteString(req.Body)
		}

		return sb.String()
	}

	// Fallback: construct minimal request
	parsedURL, _ := url.Parse(finding.Endpoint)
	path := parsedURL.Path
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	}
	if path == "" {
		path = "/"
	}

	return fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		finding.Method,
		path,
		parsedURL.Host)
}

// buildRawResponse builds a raw HTTP response string
func (r *BurpReporter) buildRawResponse(finding types.Finding) string {
	if finding.Evidence != nil && finding.Evidence.Response != nil {
		resp := finding.Evidence.Response
		var sb strings.Builder

		// Status line
		status := resp.Status
		if status == "" {
			status = "OK"
		}
		sb.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", resp.StatusCode, status))

		// Headers
		for name, value := range resp.Headers {
			sb.WriteString(fmt.Sprintf("%s: %s\r\n", name, value))
		}

		// Blank line and body
		sb.WriteString("\r\n")
		if resp.Body != "" {
			sb.WriteString(resp.Body)
		}

		return sb.String()
	}

	// Fallback: minimal response
	return "HTTP/1.1 200 OK\r\n\r\n"
}
