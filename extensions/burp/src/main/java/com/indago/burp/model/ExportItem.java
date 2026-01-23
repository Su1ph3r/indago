package com.indago.burp.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Represents an item in the export queue.
 * Wraps a Burp HttpRequestResponse with metadata.
 */
public class ExportItem {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final HttpRequestResponse requestResponse;
    private final String method;
    private final String url;
    private final String host;
    private final int port;
    private final String protocol;
    private final String path;
    private final int statusCode;
    private final String timestamp;
    private String comment;

    public ExportItem(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;
        this.timestamp = LocalDateTime.now().format(FORMATTER);

        // Extract request details
        var request = requestResponse.request();
        this.method = request.method();
        this.url = request.url();

        var httpService = request.httpService();
        this.host = httpService.host();
        this.port = httpService.port();
        this.protocol = httpService.secure() ? "https" : "http";
        this.path = request.path();

        // Extract response status if available
        var response = requestResponse.response();
        this.statusCode = (response != null) ? response.statusCode() : 0;

        // Use any existing annotations as comment
        var annotations = requestResponse.annotations();
        this.comment = annotations.notes() != null ? annotations.notes() : "";
    }

    public HttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    public String getMethod() {
        return method;
    }

    public String getUrl() {
        return url;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getPath() {
        return path;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    @Override
    public String toString() {
        return method + " " + url + " [" + statusCode + "]";
    }
}
