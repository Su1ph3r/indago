package com.indago.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import com.indago.burp.config.ConfigStore;
import com.indago.burp.config.IndagoConfig;
import com.indago.burp.export.BurpXmlExporter;
import com.indago.burp.import_.JsonImporter;
import com.indago.burp.menu.IndagoContextMenuProvider;
import com.indago.burp.model.ExportItem;
import com.indago.burp.scanner.IndagoScanLauncher;
import com.indago.burp.ui.IndagoTab;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Main entry point for the Indago Burp Suite extension.
 * Provides seamless integration between Burp Suite Professional and Indago,
 * the AI-powered API security fuzzer.
 */
public class IndagoExtension implements BurpExtension {

    public static final String EXTENSION_NAME = "Indago";
    public static final String VERSION = "1.0.0";

    private MontoyaApi api;
    private Logging logging;
    private IndagoConfig config;
    private ConfigStore configStore;
    private BurpXmlExporter exporter;
    private JsonImporter importer;
    private IndagoScanLauncher scanLauncher;
    private IndagoTab mainTab;
    private IndagoContextMenuProvider contextMenuProvider;

    // Export queue - thread-safe list of items to export
    private final List<ExportItem> exportQueue = Collections.synchronizedList(new ArrayList<>());

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();

        // Set extension name
        api.extension().setName(EXTENSION_NAME);

        logging.logToOutput("Initializing " + EXTENSION_NAME + " v" + VERSION);

        try {
            // Initialize configuration
            this.configStore = new ConfigStore(api);
            this.config = configStore.load();

            // Initialize components
            this.exporter = new BurpXmlExporter(api, logging);
            this.importer = new JsonImporter(api, logging, config);
            this.scanLauncher = new IndagoScanLauncher(api, logging, config);

            // Initialize UI
            this.mainTab = new IndagoTab(api, this);
            api.userInterface().registerSuiteTab(EXTENSION_NAME, mainTab);

            // Register context menu
            this.contextMenuProvider = new IndagoContextMenuProvider(api, this);
            api.userInterface().registerContextMenuItemsProvider(contextMenuProvider);

            // Register shutdown handler
            api.extension().registerUnloadingHandler(this::onUnload);

            logging.logToOutput(EXTENSION_NAME + " initialized successfully");

            // Validate config on startup
            if (!config.isValid()) {
                logging.logToOutput("Warning: Indago path not configured. Please set it in the Settings tab.");
            }

        } catch (Exception e) {
            logging.logToError("Failed to initialize " + EXTENSION_NAME + ": " + e.getMessage());
            throw new RuntimeException("Extension initialization failed", e);
        }
    }

    /**
     * Called when the extension is being unloaded.
     */
    private void onUnload() {
        logging.logToOutput("Unloading " + EXTENSION_NAME);

        // Save configuration
        try {
            configStore.save(config);
        } catch (Exception e) {
            logging.logToError("Failed to save configuration: " + e.getMessage());
        }

        // Stop any running scans
        if (scanLauncher != null) {
            scanLauncher.stopScan();
        }

        logging.logToOutput(EXTENSION_NAME + " unloaded");
    }

    // Accessors for components

    public MontoyaApi getApi() {
        return api;
    }

    public Logging getLogging() {
        return logging;
    }

    public IndagoConfig getConfig() {
        return config;
    }

    public ConfigStore getConfigStore() {
        return configStore;
    }

    public BurpXmlExporter getExporter() {
        return exporter;
    }

    public JsonImporter getImporter() {
        return importer;
    }

    public IndagoScanLauncher getScanLauncher() {
        return scanLauncher;
    }

    public IndagoTab getMainTab() {
        return mainTab;
    }

    public List<ExportItem> getExportQueue() {
        return exportQueue;
    }

    /**
     * Add an item to the export queue.
     */
    public void addToExportQueue(ExportItem item) {
        exportQueue.add(item);
        if (mainTab != null) {
            mainTab.refreshExportQueue();
        }
        logging.logToOutput("Added to export queue: " + item.getMethod() + " " + item.getUrl());
    }

    /**
     * Clear the export queue.
     */
    public void clearExportQueue() {
        exportQueue.clear();
        if (mainTab != null) {
            mainTab.refreshExportQueue();
        }
        logging.logToOutput("Export queue cleared");
    }

    /**
     * Remove items from the export queue by indices.
     */
    public void removeFromExportQueue(int[] indices) {
        // Sort in reverse order to avoid index shifting issues
        java.util.Arrays.sort(indices);
        for (int i = indices.length - 1; i >= 0; i--) {
            if (indices[i] >= 0 && indices[i] < exportQueue.size()) {
                exportQueue.remove(indices[i]);
            }
        }
        if (mainTab != null) {
            mainTab.refreshExportQueue();
        }
    }

    /**
     * Save the current configuration.
     */
    public void saveConfig() {
        try {
            configStore.save(config);
            logging.logToOutput("Configuration saved");
        } catch (Exception e) {
            logging.logToError("Failed to save configuration: " + e.getMessage());
        }
    }
}
