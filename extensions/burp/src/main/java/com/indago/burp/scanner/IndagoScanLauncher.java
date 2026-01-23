package com.indago.burp.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import com.indago.burp.config.IndagoConfig;
import com.indago.burp.import_.JsonImporter;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Launches and manages Indago scan processes.
 */
public class IndagoScanLauncher {

    private final MontoyaApi api;
    private final Logging logging;
    private final IndagoConfig config;
    private ProcessManager processManager;
    private File tempInputFile;
    private File tempOutputFile;
    private Consumer<String> outputCallback;
    private Runnable completionCallback;

    public IndagoScanLauncher(MontoyaApi api, Logging logging, IndagoConfig config) {
        this.api = api;
        this.logging = logging;
        this.config = config;
        this.processManager = new ProcessManager(logging);
    }

    /**
     * Launch an Indago scan with the given Burp XML input.
     *
     * @param burpXml           The Burp XML content to scan
     * @param outputCallback    Callback for scan output lines
     * @param completionCallback Callback when scan completes
     * @return true if scan started successfully
     */
    public boolean launchScan(String burpXml, Consumer<String> outputCallback, Runnable completionCallback) {
        if (!config.isValid()) {
            logging.logToError("Indago path not configured");
            return false;
        }

        if (isRunning()) {
            logging.logToError("A scan is already running");
            return false;
        }

        this.outputCallback = outputCallback;
        this.completionCallback = completionCallback;

        try {
            // Create temp input file
            tempInputFile = File.createTempFile("indago-input-", ".xml");
            tempInputFile.deleteOnExit();
            Files.writeString(tempInputFile.toPath(), burpXml);

            // Create temp output file
            tempOutputFile = File.createTempFile("indago-output-", ".json");
            tempOutputFile.deleteOnExit();

            // Build command
            List<String> command = buildCommand(tempInputFile, tempOutputFile);

            // Start process
            boolean started = processManager.start(
                    command,
                    null,
                    this::handleOutput,
                    this::handleError
            );

            if (started) {
                // Start completion monitor thread
                Thread monitor = new Thread(this::monitorProcess, "Indago-monitor");
                monitor.setDaemon(true);
                monitor.start();
            }

            return started;

        } catch (IOException e) {
            logging.logToError("Failed to create temp files: " + e.getMessage());
            cleanup();
            return false;
        }
    }

    /**
     * Build the Indago command line arguments.
     */
    private List<String> buildCommand(File inputFile, File outputFile) {
        List<String> cmd = new ArrayList<>();
        cmd.add(config.getIndagoPath());
        cmd.add("scan");

        // Input file
        cmd.add("--burp");
        cmd.add(inputFile.getAbsolutePath());

        // Output file and format
        cmd.add("--output");
        cmd.add(outputFile.getAbsolutePath());
        cmd.add("--format");
        cmd.add("json");

        // LLM settings
        if (config.getLlmProvider() != null && !config.getLlmProvider().isEmpty()) {
            cmd.add("--provider");
            cmd.add(config.getLlmProvider());

            if (config.getApiKey() != null && !config.getApiKey().isEmpty()) {
                cmd.add("--api-key");
                cmd.add(config.getApiKey());
            }

            if (config.getLlmModel() != null && !config.getLlmModel().isEmpty()) {
                cmd.add("--model");
                cmd.add(config.getLlmModel());
            }

            if (config.getLlmUrl() != null && !config.getLlmUrl().isEmpty()) {
                cmd.add("--llm-url");
                cmd.add(config.getLlmUrl());
            }

            if (config.isUseLlmPayloads()) {
                cmd.add("--use-llm-payloads");
                cmd.add("--llm-concurrency");
                cmd.add(String.valueOf(config.getLlmConcurrency()));
            }
        }

        // Scan settings
        cmd.add("--concurrency");
        cmd.add(String.valueOf(config.getConcurrency()));

        cmd.add("--rate-limit");
        cmd.add(String.valueOf(config.getRateLimit()));

        cmd.add("--timeout");
        cmd.add(config.getTimeout() + "s");

        if (!config.isVerifySSL()) {
            cmd.add("--no-ssl-verify");
        }

        // Proxy settings
        if (config.isUseProxy()) {
            cmd.add("--proxy");
            cmd.add("http://" + config.getProxyHost() + ":" + config.getProxyPort());
        }

        // Verbose output
        cmd.add("--verbose");

        return cmd;
    }

    /**
     * Handle stdout from the process.
     */
    private void handleOutput(String line) {
        logging.logToOutput("[Indago] " + line);
        if (outputCallback != null) {
            outputCallback.accept(line);
        }
    }

    /**
     * Handle stderr from the process.
     */
    private void handleError(String line) {
        logging.logToError("[Indago] " + line);
        if (outputCallback != null) {
            outputCallback.accept("[ERROR] " + line);
        }
    }

    /**
     * Monitor the process for completion.
     */
    private void monitorProcess() {
        int exitCode = processManager.waitFor();

        logging.logToOutput("Indago scan completed with exit code: " + exitCode);

        // Auto-import results if enabled
        if (exitCode == 0 && config.isAutoImport() && tempOutputFile != null && tempOutputFile.exists()) {
            try {
                JsonImporter importer = new JsonImporter(api, logging, config);
                int imported = importer.importFromFile(tempOutputFile);
                handleOutput("Imported " + imported + " findings into Burp");
            } catch (Exception e) {
                logging.logToError("Failed to auto-import results: " + e.getMessage());
            }
        }

        // Cleanup temp files
        cleanup();

        // Notify completion
        if (completionCallback != null) {
            completionCallback.run();
        }
    }

    /**
     * Stop a running scan.
     */
    public void stopScan() {
        if (processManager != null) {
            processManager.stop();
        }
        cleanup();
    }

    /**
     * Check if a scan is currently running.
     */
    public boolean isRunning() {
        return processManager != null && processManager.isRunning();
    }

    /**
     * Get the output file path (for manual import).
     */
    public File getOutputFile() {
        return tempOutputFile;
    }

    /**
     * Clean up temp files.
     */
    private void cleanup() {
        // Keep output file for manual import, but mark for deletion on exit
        if (tempInputFile != null) {
            try {
                Files.deleteIfExists(tempInputFile.toPath());
            } catch (IOException e) {
                // Ignore
            }
            tempInputFile = null;
        }
    }

    /**
     * Validate that Indago is installed and accessible.
     */
    public boolean validateInstallation() {
        if (!config.isValid()) {
            return false;
        }

        File indago = new File(config.getIndagoPath());
        if (!indago.exists()) {
            logging.logToError("Indago binary not found: " + config.getIndagoPath());
            return false;
        }

        if (!indago.canExecute()) {
            logging.logToError("Indago binary is not executable: " + config.getIndagoPath());
            return false;
        }

        // Try running indago --version
        try {
            ProcessBuilder pb = new ProcessBuilder(config.getIndagoPath(), "--version");
            Process p = pb.start();
            boolean completed = p.waitFor(5, TimeUnit.SECONDS);
            if (completed && p.exitValue() == 0) {
                logging.logToOutput("Indago installation validated");
                return true;
            }
        } catch (Exception e) {
            logging.logToError("Failed to validate Indago: " + e.getMessage());
        }

        return false;
    }
}
