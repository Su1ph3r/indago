package com.indago.burp.import_;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.sitemap.SiteMapFilter;

import com.indago.burp.model.IndagoFinding;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Implements Burp's AuditIssue interface for Indago findings.
 */
public class IndagoAuditIssue implements AuditIssue {

    private final IndagoFinding finding;
    private final MontoyaApi api;
    private final String baseUrl;
    private final HttpService httpService;

    public IndagoAuditIssue(IndagoFinding finding, MontoyaApi api) {
        this.finding = finding;
        this.api = api;

        // Parse endpoint URL to extract service details
        String endpoint = finding.getEndpoint();
        this.baseUrl = extractBaseUrl(endpoint);
        this.httpService = createHttpService(endpoint);
    }

    @Override
    public String name() {
        return "[Indago] " + finding.getTitle();
    }

    @Override
    public String detail() {
        StringBuilder detail = new StringBuilder();

        detail.append("<p><b>Description:</b></p>");
        detail.append("<p>").append(escapeHtml(finding.getDescription())).append("</p>");

        if (finding.getParameter() != null && !finding.getParameter().isEmpty()) {
            detail.append("<p><b>Parameter:</b> ").append(escapeHtml(finding.getParameter())).append("</p>");
        }

        if (finding.getPayload() != null && !finding.getPayload().isEmpty()) {
            detail.append("<p><b>Payload:</b> <code>").append(escapeHtml(finding.getPayload())).append("</code></p>");
        }

        if (finding.getCwe() != null && !finding.getCwe().isEmpty()) {
            detail.append("<p><b>CWE:</b> ").append(escapeHtml(finding.getCwe())).append("</p>");
        }

        if (finding.getCvss() > 0) {
            detail.append("<p><b>CVSS:</b> ").append(finding.getCvss()).append("</p>");
        }

        // Evidence section
        if (finding.getEvidence() != null) {
            IndagoFinding.Evidence evidence = finding.getEvidence();

            if (evidence.getMatchedData() != null && !evidence.getMatchedData().isEmpty()) {
                detail.append("<p><b>Matched Data:</b></p><ul>");
                for (String match : evidence.getMatchedData()) {
                    detail.append("<li>").append(escapeHtml(match)).append("</li>");
                }
                detail.append("</ul>");
            }

            if (evidence.getAnomalies() != null && !evidence.getAnomalies().isEmpty()) {
                detail.append("<p><b>Anomalies:</b></p><ul>");
                for (String anomaly : evidence.getAnomalies()) {
                    detail.append("<li>").append(escapeHtml(anomaly)).append("</li>");
                }
                detail.append("</ul>");
            }
        }

        // Curl command for reproduction
        if (finding.getCurlCommand() != null && !finding.getCurlCommand().isEmpty()) {
            detail.append("<p><b>Reproduce with:</b></p>");
            detail.append("<pre>").append(escapeHtml(finding.getCurlCommand())).append("</pre>");
        }

        // Replication steps
        if (finding.getReplicateSteps() != null && !finding.getReplicateSteps().isEmpty()) {
            detail.append("<p><b>Steps to Reproduce:</b></p><ol>");
            for (String step : finding.getReplicateSteps()) {
                detail.append("<li>").append(escapeHtml(step)).append("</li>");
            }
            detail.append("</ol>");
        }

        detail.append("<p><i>Found by Indago - AI-Powered API Security Fuzzer</i></p>");

        return detail.toString();
    }

    @Override
    public String remediation() {
        if (finding.getRemediation() != null && !finding.getRemediation().isEmpty()) {
            return finding.getRemediation();
        }
        return getDefaultRemediation(finding.getType());
    }

    @Override
    public HttpService httpService() {
        return httpService;
    }

    @Override
    public String baseUrl() {
        return baseUrl;
    }

    @Override
    public AuditIssueSeverity severity() {
        String burpSeverity = finding.getBurpSeverity();
        switch (burpSeverity) {
            case "HIGH":
                return AuditIssueSeverity.HIGH;
            case "MEDIUM":
                return AuditIssueSeverity.MEDIUM;
            case "LOW":
                return AuditIssueSeverity.LOW;
            case "INFORMATION":
            default:
                return AuditIssueSeverity.INFORMATION;
        }
    }

    @Override
    public AuditIssueConfidence confidence() {
        String burpConfidence = finding.getBurpConfidence();
        switch (burpConfidence) {
            case "CERTAIN":
                return AuditIssueConfidence.CERTAIN;
            case "FIRM":
                return AuditIssueConfidence.FIRM;
            case "TENTATIVE":
            default:
                return AuditIssueConfidence.TENTATIVE;
        }
    }

    @Override
    public List<HttpRequestResponse> requestResponses() {
        List<HttpRequestResponse> list = new ArrayList<>();

        if (finding.getEvidence() != null) {
            IndagoFinding.Evidence evidence = finding.getEvidence();
            IndagoFinding.Request req = evidence.getRequest();
            IndagoFinding.Response resp = evidence.getResponse();

            if (req != null) {
                try {
                    HttpRequest request = buildRequest(req);
                    HttpResponse response = resp != null ? buildResponse(resp) : null;
                    HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(request, response);
                    list.add(rr);
                } catch (Exception e) {
                    // Log but don't fail
                }
            }
        }

        return list;
    }

    @Override
    public List<Interaction> collaboratorInteractions() {
        return new ArrayList<>();
    }

    @Override
    public AuditIssueDefinition definition() {
        return AuditIssueDefinition.auditIssueDefinition(
                name(),
                finding.getDescription() != null ? finding.getDescription() : "",
                remediation(),
                severity()
        );
    }

    /**
     * Build an HttpRequest from the finding's evidence.
     */
    private HttpRequest buildRequest(IndagoFinding.Request req) {
        HttpRequest request = HttpRequest.httpRequest(httpService, req.getMethod() + " " + extractPath(req.getUrl()) + " HTTP/1.1\r\n");

        // Add headers
        if (req.getHeaders() != null) {
            for (Map.Entry<String, String> header : req.getHeaders().entrySet()) {
                request = request.withHeader(header.getKey(), header.getValue());
            }
        }

        // Add body
        if (req.getBody() != null && !req.getBody().isEmpty()) {
            request = request.withBody(req.getBody());
        }

        return request;
    }

    /**
     * Build an HttpResponse from the finding's evidence.
     */
    private HttpResponse buildResponse(IndagoFinding.Response resp) {
        StringBuilder rawResponse = new StringBuilder();
        rawResponse.append("HTTP/1.1 ").append(resp.getStatusCode()).append(" OK\r\n");

        if (resp.getHeaders() != null) {
            for (Map.Entry<String, String> header : resp.getHeaders().entrySet()) {
                rawResponse.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
            }
        }

        rawResponse.append("\r\n");

        if (resp.getBody() != null) {
            rawResponse.append(resp.getBody());
        }

        return HttpResponse.httpResponse(rawResponse.toString());
    }

    /**
     * Create HttpService from endpoint URL.
     */
    private HttpService createHttpService(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            int port = uri.getPort();
            boolean secure = "https".equalsIgnoreCase(uri.getScheme());

            if (port == -1) {
                port = secure ? 443 : 80;
            }

            return HttpService.httpService(host, port, secure);
        } catch (Exception e) {
            // Fallback
            return HttpService.httpService("localhost", 80, false);
        }
    }

    /**
     * Extract base URL from full URL.
     */
    private String extractBaseUrl(String url) {
        try {
            URI uri = new URI(url);
            int port = uri.getPort();
            boolean secure = "https".equalsIgnoreCase(uri.getScheme());

            if (port == -1) {
                port = secure ? 443 : 80;
            }

            // Only include port if non-standard
            if ((secure && port == 443) || (!secure && port == 80)) {
                return uri.getScheme() + "://" + uri.getHost();
            }
            return uri.getScheme() + "://" + uri.getHost() + ":" + port;
        } catch (Exception e) {
            return url;
        }
    }

    /**
     * Extract path from URL.
     */
    private String extractPath(String url) {
        try {
            URI uri = new URI(url);
            String path = uri.getPath();
            String query = uri.getQuery();
            if (query != null && !query.isEmpty()) {
                return path + "?" + query;
            }
            return path != null ? path : "/";
        } catch (Exception e) {
            return "/";
        }
    }

    /**
     * Escape HTML special characters.
     */
    private String escapeHtml(String text) {
        if (text == null) {
            return "";
        }
        return text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    /**
     * Get default remediation text based on vulnerability type.
     */
    private String getDefaultRemediation(String type) {
        if (type == null) {
            return "Review the identified vulnerability and apply appropriate security controls.";
        }

        switch (type.toLowerCase()) {
            case "sqli":
                return "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.";
            case "nosqli":
                return "Validate and sanitize all user input. Use parameterized queries for NoSQL databases.";
            case "xss":
                return "Encode output appropriately for the context. Use Content Security Policy headers.";
            case "command_injection":
                return "Avoid shell commands with user input. Use safe APIs and input validation.";
            case "idor":
            case "bola":
                return "Implement proper authorization checks. Verify the user has permission to access the requested resource.";
            case "bfla":
                return "Implement function-level access control. Verify user permissions before executing privileged operations.";
            case "ssrf":
                return "Validate and sanitize URLs. Use allowlists for permitted domains and protocols.";
            case "path_traversal":
                return "Validate and canonicalize file paths. Use allowlists and avoid user-controlled path components.";
            case "ssti":
                return "Avoid passing user input to template engines. Use logic-less templates when possible.";
            case "jwt_manipulation":
                return "Validate JWT signatures properly. Use strong algorithms and protect signing keys.";
            case "auth_bypass":
                return "Review authentication logic. Ensure all authentication checks are properly enforced.";
            case "mass_assignment":
                return "Use allowlists for accepted parameters. Never bind user input directly to internal objects.";
            default:
                return "Review the identified vulnerability and apply appropriate security controls based on the specific attack vector.";
        }
    }
}
