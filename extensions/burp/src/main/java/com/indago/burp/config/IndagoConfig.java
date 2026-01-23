package com.indago.burp.config;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * Configuration for the Indago extension.
 * Contains all settings needed to run Indago scans.
 */
public class IndagoConfig {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    // Indago binary settings
    private String indagoPath = "";

    // LLM Provider settings
    private String llmProvider = "";  // openai, anthropic, ollama, lmstudio
    private String llmModel = "";
    private String apiKey = "";
    private String llmUrl = "";

    // Scan settings
    private int concurrency = 10;
    private double rateLimit = 10.0;
    private int timeout = 30;  // seconds
    private boolean useLlmPayloads = false;
    private int llmConcurrency = 8;
    private boolean verifySSL = true;

    // Output settings
    private String outputFormat = "json";  // json or burp
    private boolean autoImport = true;

    // Proxy settings (for Indago to use Burp as proxy)
    private boolean useProxy = false;
    private String proxyHost = "127.0.0.1";
    private int proxyPort = 8080;

    public IndagoConfig() {
    }

    /**
     * Check if the configuration is valid (at minimum, Indago path must be set).
     */
    public boolean isValid() {
        return indagoPath != null && !indagoPath.trim().isEmpty();
    }

    /**
     * Serialize to JSON.
     */
    public String toJson() {
        return GSON.toJson(this);
    }

    /**
     * Deserialize from JSON.
     */
    public static IndagoConfig fromJson(String json) {
        if (json == null || json.trim().isEmpty()) {
            return new IndagoConfig();
        }
        try {
            return GSON.fromJson(json, IndagoConfig.class);
        } catch (Exception e) {
            return new IndagoConfig();
        }
    }

    // Getters and Setters

    public String getIndagoPath() {
        return indagoPath;
    }

    public void setIndagoPath(String indagoPath) {
        this.indagoPath = indagoPath;
    }

    public String getLlmProvider() {
        return llmProvider;
    }

    public void setLlmProvider(String llmProvider) {
        this.llmProvider = llmProvider;
    }

    public String getLlmModel() {
        return llmModel;
    }

    public void setLlmModel(String llmModel) {
        this.llmModel = llmModel;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public String getLlmUrl() {
        return llmUrl;
    }

    public void setLlmUrl(String llmUrl) {
        this.llmUrl = llmUrl;
    }

    /**
     * Validate that the LLM URL is a valid URL with http/https protocol.
     * Returns null if valid, or an error message if invalid.
     */
    public String validateLlmUrl() {
        if (llmUrl == null || llmUrl.trim().isEmpty()) {
            return null; // Empty URL is valid (not required)
        }

        try {
            URL url = new URL(llmUrl);
            String protocol = url.getProtocol().toLowerCase();
            if (!protocol.equals("http") && !protocol.equals("https")) {
                return "LLM URL must use http or https protocol";
            }
            if (url.getHost() == null || url.getHost().isEmpty()) {
                return "LLM URL must have a valid host";
            }
            return null; // Valid
        } catch (MalformedURLException e) {
            return "Invalid LLM URL format: " + e.getMessage();
        }
    }

    /**
     * Validate that the Indago path doesn't contain dangerous characters.
     * Returns null if valid, or an error message if invalid.
     */
    public String validateIndagoPath() {
        if (indagoPath == null || indagoPath.trim().isEmpty()) {
            return "Indago path is required";
        }

        // Check for command injection characters
        if (indagoPath.contains(";") || indagoPath.contains("|") ||
            indagoPath.contains("&") || indagoPath.contains("`") ||
            indagoPath.contains("$") || indagoPath.contains("$(")) {
            return "Indago path contains invalid characters";
        }

        return null; // Valid
    }

    public int getConcurrency() {
        return concurrency;
    }

    public void setConcurrency(int concurrency) {
        this.concurrency = concurrency;
    }

    public double getRateLimit() {
        return rateLimit;
    }

    public void setRateLimit(double rateLimit) {
        this.rateLimit = rateLimit;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    public boolean isUseLlmPayloads() {
        return useLlmPayloads;
    }

    public void setUseLlmPayloads(boolean useLlmPayloads) {
        this.useLlmPayloads = useLlmPayloads;
    }

    public int getLlmConcurrency() {
        return llmConcurrency;
    }

    public void setLlmConcurrency(int llmConcurrency) {
        this.llmConcurrency = llmConcurrency;
    }

    public boolean isVerifySSL() {
        return verifySSL;
    }

    public void setVerifySSL(boolean verifySSL) {
        this.verifySSL = verifySSL;
    }

    public String getOutputFormat() {
        return outputFormat;
    }

    public void setOutputFormat(String outputFormat) {
        this.outputFormat = outputFormat;
    }

    public boolean isAutoImport() {
        return autoImport;
    }

    public void setAutoImport(boolean autoImport) {
        this.autoImport = autoImport;
    }

    public boolean isUseProxy() {
        return useProxy;
    }

    public void setUseProxy(boolean useProxy) {
        this.useProxy = useProxy;
    }

    public String getProxyHost() {
        return proxyHost;
    }

    public void setProxyHost(String proxyHost) {
        this.proxyHost = proxyHost;
    }

    public int getProxyPort() {
        return proxyPort;
    }

    public void setProxyPort(int proxyPort) {
        this.proxyPort = proxyPort;
    }
}
