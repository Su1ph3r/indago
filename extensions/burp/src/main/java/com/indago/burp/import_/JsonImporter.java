package com.indago.burp.import_;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;

import com.indago.burp.config.IndagoConfig;
import com.indago.burp.model.IndagoFinding;

import java.io.File;
import java.io.FileReader;
import java.io.Reader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses Indago JSON output and converts findings to Burp audit issues.
 *
 * Expected JSON structure from internal/reporter/json.go:
 * {
 *   "scan_id": "...",
 *   "target": "...",
 *   "findings": [...]
 * }
 */
public class JsonImporter {

    private static final Gson GSON = new GsonBuilder().create();

    private final MontoyaApi api;
    private final Logging logging;
    private final IndagoConfig config;

    public JsonImporter(MontoyaApi api, Logging logging, IndagoConfig config) {
        this.api = api;
        this.logging = logging;
        this.config = config;
    }

    /**
     * Parse Indago JSON output from a file.
     */
    public IndagoScanResult parseFile(File file) throws Exception {
        try (FileReader reader = new FileReader(file)) {
            return parse(reader);
        }
    }

    /**
     * Parse Indago JSON output from a string.
     */
    public IndagoScanResult parseString(String json) throws Exception {
        try (StringReader reader = new StringReader(json)) {
            return parse(reader);
        }
    }

    /**
     * Parse Indago JSON output from a reader.
     */
    public IndagoScanResult parse(Reader reader) throws Exception {
        return GSON.fromJson(reader, IndagoScanResult.class);
    }

    /**
     * Import findings into Burp's scanner issue list.
     */
    public int importFindings(IndagoScanResult result) {
        if (result == null || result.getFindings() == null || result.getFindings().isEmpty()) {
            logging.logToOutput("No findings to import");
            return 0;
        }

        int imported = 0;
        for (IndagoFinding finding : result.getFindings()) {
            try {
                AuditIssue issue = new IndagoAuditIssue(finding, api);
                api.siteMap().add(issue);
                imported++;
            } catch (Exception e) {
                logging.logToError("Failed to import finding: " + finding.getTitle() + " - " + e.getMessage());
            }
        }

        logging.logToOutput("Imported " + imported + " findings into Burp issue list");
        return imported;
    }

    /**
     * Import findings from a file into Burp.
     */
    public int importFromFile(File file) throws Exception {
        IndagoScanResult result = parseFile(file);
        return importFindings(result);
    }

    /**
     * Convert findings to a list without importing.
     */
    public List<IndagoFinding> getFindingsFromFile(File file) throws Exception {
        IndagoScanResult result = parseFile(file);
        return result != null ? result.getFindings() : new ArrayList<>();
    }

    /**
     * Represents the full Indago scan result JSON structure.
     */
    public static class IndagoScanResult {
        @SerializedName("scan_id")
        private String scanId;

        private String target;

        @SerializedName("start_time")
        private String startTime;

        @SerializedName("end_time")
        private String endTime;

        private String duration;
        private Summary summary;
        private List<IndagoFinding> findings;

        @SerializedName("endpoints_scanned")
        private int endpointsScanned;

        @SerializedName("requests_made")
        private int requestsMade;

        public String getScanId() {
            return scanId;
        }

        public String getTarget() {
            return target;
        }

        public String getStartTime() {
            return startTime;
        }

        public String getEndTime() {
            return endTime;
        }

        public String getDuration() {
            return duration;
        }

        public Summary getSummary() {
            return summary;
        }

        public List<IndagoFinding> getFindings() {
            return findings != null ? findings : new ArrayList<>();
        }

        public int getEndpointsScanned() {
            return endpointsScanned;
        }

        public int getRequestsMade() {
            return requestsMade;
        }
    }

    /**
     * Scan summary structure.
     */
    public static class Summary {
        @SerializedName("total_findings")
        private int totalFindings;

        @SerializedName("critical_findings")
        private int criticalFindings;

        @SerializedName("high_findings")
        private int highFindings;

        @SerializedName("medium_findings")
        private int mediumFindings;

        @SerializedName("low_findings")
        private int lowFindings;

        @SerializedName("info_findings")
        private int infoFindings;

        public int getTotalFindings() {
            return totalFindings;
        }

        public int getCriticalFindings() {
            return criticalFindings;
        }

        public int getHighFindings() {
            return highFindings;
        }

        public int getMediumFindings() {
            return mediumFindings;
        }

        public int getLowFindings() {
            return lowFindings;
        }

        public int getInfoFindings() {
            return infoFindings;
        }
    }
}
