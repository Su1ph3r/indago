package com.indago.burp.config;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;

/**
 * Handles persistence of IndagoConfig using Burp's preferences API.
 */
public class ConfigStore {

    private static final String CONFIG_KEY = "indago_config";

    private final MontoyaApi api;
    private final Persistence persistence;

    public ConfigStore(MontoyaApi api) {
        this.api = api;
        this.persistence = api.persistence();
    }

    /**
     * Load configuration from Burp preferences.
     */
    public IndagoConfig load() {
        try {
            PersistedObject extensionData = persistence.extensionData();
            String json = extensionData.getString(CONFIG_KEY);
            if (json != null && !json.trim().isEmpty()) {
                return IndagoConfig.fromJson(json);
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to load configuration: " + e.getMessage());
        }
        return new IndagoConfig();
    }

    /**
     * Save configuration to Burp preferences.
     */
    public void save(IndagoConfig config) {
        try {
            PersistedObject extensionData = persistence.extensionData();
            extensionData.setString(CONFIG_KEY, config.toJson());
        } catch (Exception e) {
            api.logging().logToError("Failed to save configuration: " + e.getMessage());
            throw new RuntimeException("Failed to save configuration", e);
        }
    }

    /**
     * Clear stored configuration.
     */
    public void clear() {
        try {
            PersistedObject extensionData = persistence.extensionData();
            extensionData.deleteString(CONFIG_KEY);
        } catch (Exception e) {
            api.logging().logToError("Failed to clear configuration: " + e.getMessage());
        }
    }
}
