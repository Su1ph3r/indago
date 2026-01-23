package com.indago.burp.export;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;

import com.indago.burp.model.ExportItem;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;

/**
 * Exports HTTP requests/responses to Burp XML format compatible with Indago.
 *
 * The format matches what Indago expects in internal/parser/burp.go:
 * <items burpVersion="2025.12">
 *   <item>
 *     <time>...</time>
 *     <url>https://example.com/api/users</url>
 *     <host>example.com</host>
 *     <port>443</port>
 *     <protocol>https</protocol>
 *     <method>GET</method>
 *     <path>/api/users</path>
 *     <request base64="true">...</request>
 *     <response base64="true">...</response>
 *     <status>200</status>
 *     <comment></comment>
 *   </item>
 * </items>
 */
public class BurpXmlExporter {

    private static final String BURP_VERSION = "2025.12";
    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("EEE MMM dd HH:mm:ss z yyyy");

    private final MontoyaApi api;
    private final Logging logging;

    public BurpXmlExporter(MontoyaApi api, Logging logging) {
        this.api = api;
        this.logging = logging;
    }

    /**
     * Export a list of ExportItems to Burp XML format.
     */
    public String export(List<ExportItem> items) {
        StringWriter writer = new StringWriter();

        writer.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        writer.append("<items burpVersion=\"").append(BURP_VERSION).append("\">\n");

        for (ExportItem item : items) {
            try {
                writer.append(exportItem(item));
            } catch (Exception e) {
                logging.logToError("Failed to export item: " + item.getUrl() + " - " + e.getMessage());
            }
        }

        writer.append("</items>\n");
        return writer.toString();
    }

    /**
     * Export a single HttpRequestResponse to Burp XML format.
     */
    public String exportSingle(HttpRequestResponse requestResponse) {
        ExportItem item = new ExportItem(requestResponse);
        return export(List.of(item));
    }

    /**
     * Export items to a file.
     */
    public void exportToFile(List<ExportItem> items, File file) throws IOException {
        String xml = export(items);
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(xml);
        }
        logging.logToOutput("Exported " + items.size() + " items to: " + file.getAbsolutePath());
    }

    /**
     * Export a single item to XML element.
     */
    private String exportItem(ExportItem item) {
        StringBuilder sb = new StringBuilder();
        HttpRequestResponse rr = item.getRequestResponse();

        sb.append("  <item>\n");

        // Time
        sb.append("    <time>").append(escapeXml(LocalDateTime.now().format(TIME_FORMATTER))).append("</time>\n");

        // URL
        sb.append("    <url>").append(escapeXml(item.getUrl())).append("</url>\n");

        // Host
        sb.append("    <host>").append(escapeXml(item.getHost())).append("</host>\n");

        // Port
        sb.append("    <port>").append(item.getPort()).append("</port>\n");

        // Protocol
        sb.append("    <protocol>").append(escapeXml(item.getProtocol())).append("</protocol>\n");

        // Method
        sb.append("    <method>").append(escapeXml(item.getMethod())).append("</method>\n");

        // Path
        sb.append("    <path>").append(escapeXml(item.getPath())).append("</path>\n");

        // Extension (file extension from path)
        String extension = extractExtension(item.getPath());
        sb.append("    <extension>").append(escapeXml(extension)).append("</extension>\n");

        // Request (base64 encoded)
        byte[] requestBytes = rr.request().toByteArray().getBytes();
        String requestBase64 = Base64.getEncoder().encodeToString(requestBytes);
        sb.append("    <request base64=\"true\">").append(requestBase64).append("</request>\n");

        // Response (base64 encoded) - may be null
        if (rr.response() != null) {
            byte[] responseBytes = rr.response().toByteArray().getBytes();
            String responseBase64 = Base64.getEncoder().encodeToString(responseBytes);
            sb.append("    <response base64=\"true\">").append(responseBase64).append("</response>\n");

            // Status code
            sb.append("    <status>").append(rr.response().statusCode()).append("</status>\n");

            // Response length
            sb.append("    <responselength>").append(responseBytes.length).append("</responselength>\n");

            // MIME type
            String mimeType = extractMimeType(rr.response());
            sb.append("    <mimetype>").append(escapeXml(mimeType)).append("</mimetype>\n");
        } else {
            sb.append("    <response base64=\"true\"></response>\n");
            sb.append("    <status>0</status>\n");
            sb.append("    <responselength>0</responselength>\n");
            sb.append("    <mimetype></mimetype>\n");
        }

        // Comment
        sb.append("    <comment>").append(escapeXml(item.getComment())).append("</comment>\n");

        sb.append("  </item>\n");

        return sb.toString();
    }

    /**
     * Extract file extension from path.
     */
    private String extractExtension(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        // Remove query string
        int queryIndex = path.indexOf('?');
        if (queryIndex > 0) {
            path = path.substring(0, queryIndex);
        }
        // Find last dot
        int dotIndex = path.lastIndexOf('.');
        int slashIndex = path.lastIndexOf('/');
        if (dotIndex > slashIndex && dotIndex < path.length() - 1) {
            return path.substring(dotIndex + 1);
        }
        return "";
    }

    /**
     * Extract MIME type from response.
     */
    private String extractMimeType(burp.api.montoya.http.message.responses.HttpResponse response) {
        if (response == null) {
            return "";
        }
        var contentType = response.headerValue("Content-Type");
        if (contentType != null) {
            // Extract just the MIME type, without charset etc.
            int semicolon = contentType.indexOf(';');
            if (semicolon > 0) {
                return contentType.substring(0, semicolon).trim();
            }
            return contentType.trim();
        }
        return "";
    }

    /**
     * Escape XML special characters.
     */
    private String escapeXml(String text) {
        if (text == null) {
            return "";
        }
        return text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }
}
