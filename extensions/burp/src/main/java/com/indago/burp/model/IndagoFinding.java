package com.indago.burp.model;

import com.google.gson.annotations.SerializedName;

import java.util.List;
import java.util.Map;

/**
 * Represents a finding from Indago's JSON output.
 * Matches the structure in internal/reporter/json.go.
 */
public class IndagoFinding {

    private String id;
    private String type;
    private String severity;
    private String confidence;
    private String title;
    private String description;
    private String endpoint;
    private String method;
    private String parameter;
    private String payload;
    private String cwe;
    private double cvss;
    private String remediation;
    private String timestamp;
    private Evidence evidence;

    @SerializedName("curl_command")
    private String curlCommand;

    @SerializedName("replicate_steps")
    private List<String> replicateSteps;

    /**
     * Evidence structure containing request/response data.
     */
    public static class Evidence {
        private Request request;
        private Response response;

        @SerializedName("matched_data")
        private List<String> matchedData;

        private List<String> anomalies;

        public Request getRequest() {
            return request;
        }

        public Response getResponse() {
            return response;
        }

        public List<String> getMatchedData() {
            return matchedData;
        }

        public List<String> getAnomalies() {
            return anomalies;
        }
    }

    /**
     * HTTP Request structure.
     */
    public static class Request {
        private String method;
        private String url;
        private Map<String, String> headers;
        private String body;

        public String getMethod() {
            return method;
        }

        public String getUrl() {
            return url;
        }

        public Map<String, String> getHeaders() {
            return headers;
        }

        public String getBody() {
            return body;
        }
    }

    /**
     * HTTP Response structure.
     */
    public static class Response {
        @SerializedName("status_code")
        private int statusCode;

        private Map<String, String> headers;
        private String body;

        public int getStatusCode() {
            return statusCode;
        }

        public Map<String, String> getHeaders() {
            return headers;
        }

        public String getBody() {
            return body;
        }
    }

    // Getters

    public String getId() {
        return id;
    }

    public String getType() {
        return type;
    }

    public String getSeverity() {
        return severity;
    }

    public String getConfidence() {
        return confidence;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public String getMethod() {
        return method;
    }

    public String getParameter() {
        return parameter;
    }

    public String getPayload() {
        return payload;
    }

    public String getCwe() {
        return cwe;
    }

    public double getCvss() {
        return cvss;
    }

    public String getRemediation() {
        return remediation;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public Evidence getEvidence() {
        return evidence;
    }

    public String getCurlCommand() {
        return curlCommand;
    }

    public List<String> getReplicateSteps() {
        return replicateSteps;
    }

    /**
     * Convert Indago severity to Burp AuditIssueSeverity string.
     * Indago uses: critical, high, medium, low, info
     * Burp uses: HIGH, MEDIUM, LOW, INFORMATION, FALSE_POSITIVE
     */
    public String getBurpSeverity() {
        if (severity == null) {
            return "INFORMATION";
        }
        switch (severity.toLowerCase()) {
            case "critical":
            case "high":
                return "HIGH";
            case "medium":
                return "MEDIUM";
            case "low":
                return "LOW";
            case "info":
            default:
                return "INFORMATION";
        }
    }

    /**
     * Convert Indago confidence to Burp AuditIssueConfidence string.
     * Indago uses: high, medium, low
     * Burp uses: CERTAIN, FIRM, TENTATIVE
     */
    public String getBurpConfidence() {
        if (confidence == null) {
            return "TENTATIVE";
        }
        switch (confidence.toLowerCase()) {
            case "high":
                return "CERTAIN";
            case "medium":
                return "FIRM";
            case "low":
            default:
                return "TENTATIVE";
        }
    }

    @Override
    public String toString() {
        return String.format("[%s] %s - %s %s", severity, title, method, endpoint);
    }
}
