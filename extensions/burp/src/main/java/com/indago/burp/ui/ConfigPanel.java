package com.indago.burp.ui;

import com.indago.burp.IndagoExtension;
import com.indago.burp.config.IndagoConfig;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.File;

/**
 * Settings panel for configuring Indago options.
 */
public class ConfigPanel extends JPanel {

    private final IndagoExtension extension;
    private final IndagoConfig config;

    // Indago settings
    private JTextField indagoPathField;
    private JButton browseButton;
    private JButton validateButton;

    // LLM settings
    private JComboBox<String> providerCombo;
    private JTextField modelField;
    private JPasswordField apiKeyField;
    private JTextField llmUrlField;
    private JCheckBox useLlmPayloadsCheck;
    private JSpinner llmConcurrencySpinner;

    // Scan settings
    private JSpinner concurrencySpinner;
    private JSpinner rateLimitSpinner;
    private JSpinner timeoutSpinner;
    private JCheckBox verifySSLCheck;

    // Proxy settings
    private JCheckBox useProxyCheck;
    private JTextField proxyHostField;
    private JSpinner proxyPortSpinner;

    // Output settings
    private JCheckBox autoImportCheck;

    public ConfigPanel(IndagoExtension extension) {
        this.extension = extension;
        this.config = extension.getConfig();

        setLayout(new BorderLayout());
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Create main panel with scroll
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        mainPanel.add(createIndagoPanel());
        mainPanel.add(Box.createVerticalStrut(10));
        mainPanel.add(createLLMPanel());
        mainPanel.add(Box.createVerticalStrut(10));
        mainPanel.add(createScanPanel());
        mainPanel.add(Box.createVerticalStrut(10));
        mainPanel.add(createProxyPanel());
        mainPanel.add(Box.createVerticalStrut(10));
        mainPanel.add(createOutputPanel());
        mainPanel.add(Box.createVerticalStrut(10));
        mainPanel.add(createButtonPanel());
        mainPanel.add(Box.createVerticalGlue());

        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setBorder(null);
        add(scrollPane, BorderLayout.CENTER);

        // Load current config values
        loadConfig();
    }

    private JPanel createIndagoPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new TitledBorder("Indago Binary"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // Indago path
        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(new JLabel("Indago Path:"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        indagoPathField = new JTextField(30);
        panel.add(indagoPathField, gbc);

        gbc.gridx = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        browseButton = new JButton("Browse...");
        browseButton.addActionListener(e -> browseForIndago());
        panel.add(browseButton, gbc);

        gbc.gridx = 3;
        validateButton = new JButton("Validate");
        validateButton.addActionListener(e -> validateIndago());
        panel.add(validateButton, gbc);

        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, panel.getPreferredSize().height));
        return panel;
    }

    private JPanel createLLMPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new TitledBorder("LLM Provider"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // Provider
        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(new JLabel("Provider:"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        providerCombo = new JComboBox<>(new String[]{"", "openai", "anthropic", "ollama", "lmstudio"});
        panel.add(providerCombo, gbc);

        // Model
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.fill = GridBagConstraints.NONE;
        panel.add(new JLabel("Model:"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        modelField = new JTextField(20);
        panel.add(modelField, gbc);

        // API Key
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.fill = GridBagConstraints.NONE;
        panel.add(new JLabel("API Key:"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        apiKeyField = new JPasswordField(20);
        panel.add(apiKeyField, gbc);

        // LLM URL
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.fill = GridBagConstraints.NONE;
        panel.add(new JLabel("LLM URL:"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        llmUrlField = new JTextField(20);
        llmUrlField.setToolTipText("Base URL for local LLM (ollama/lmstudio)");
        panel.add(llmUrlField, gbc);

        // Use LLM Payloads
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 2;
        useLlmPayloadsCheck = new JCheckBox("Use LLM-generated payloads");
        panel.add(useLlmPayloadsCheck, gbc);

        // LLM Concurrency
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.gridwidth = 1;
        panel.add(new JLabel("LLM Concurrency:"), gbc);

        gbc.gridx = 1;
        llmConcurrencySpinner = new JSpinner(new SpinnerNumberModel(8, 1, 32, 1));
        panel.add(llmConcurrencySpinner, gbc);

        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, panel.getPreferredSize().height));
        return panel;
    }

    private JPanel createScanPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new TitledBorder("Scan Settings"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // Concurrency
        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(new JLabel("Concurrency:"), gbc);

        gbc.gridx = 1;
        concurrencySpinner = new JSpinner(new SpinnerNumberModel(10, 1, 100, 1));
        panel.add(concurrencySpinner, gbc);

        // Rate Limit
        gbc.gridx = 0;
        gbc.gridy = 1;
        panel.add(new JLabel("Rate Limit (req/s):"), gbc);

        gbc.gridx = 1;
        rateLimitSpinner = new JSpinner(new SpinnerNumberModel(10.0, 0.1, 1000.0, 1.0));
        panel.add(rateLimitSpinner, gbc);

        // Timeout
        gbc.gridx = 0;
        gbc.gridy = 2;
        panel.add(new JLabel("Timeout (seconds):"), gbc);

        gbc.gridx = 1;
        timeoutSpinner = new JSpinner(new SpinnerNumberModel(30, 1, 300, 1));
        panel.add(timeoutSpinner, gbc);

        // SSL Verification
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 2;
        verifySSLCheck = new JCheckBox("Verify SSL certificates");
        panel.add(verifySSLCheck, gbc);

        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, panel.getPreferredSize().height));
        return panel;
    }

    private JPanel createProxyPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new TitledBorder("Proxy Settings (route Indago through Burp)"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // Use Proxy
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        useProxyCheck = new JCheckBox("Use proxy");
        panel.add(useProxyCheck, gbc);

        // Proxy Host
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        panel.add(new JLabel("Host:"), gbc);

        gbc.gridx = 1;
        proxyHostField = new JTextField("127.0.0.1", 15);
        panel.add(proxyHostField, gbc);

        // Proxy Port
        gbc.gridx = 0;
        gbc.gridy = 2;
        panel.add(new JLabel("Port:"), gbc);

        gbc.gridx = 1;
        proxyPortSpinner = new JSpinner(new SpinnerNumberModel(8080, 1, 65535, 1));
        panel.add(proxyPortSpinner, gbc);

        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, panel.getPreferredSize().height));
        return panel;
    }

    private JPanel createOutputPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new TitledBorder("Output Settings"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // Auto Import
        gbc.gridx = 0;
        gbc.gridy = 0;
        autoImportCheck = new JCheckBox("Auto-import findings to Burp issue list");
        panel.add(autoImportCheck, gbc);

        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, panel.getPreferredSize().height));
        return panel;
    }

    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton saveButton = new JButton("Save Configuration");
        saveButton.addActionListener(e -> saveConfig());
        panel.add(saveButton);

        JButton resetButton = new JButton("Reset to Defaults");
        resetButton.addActionListener(e -> resetConfig());
        panel.add(resetButton);

        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, panel.getPreferredSize().height));
        return panel;
    }

    private void browseForIndago() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select Indago Binary");
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);

        int result = chooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            indagoPathField.setText(file.getAbsolutePath());
        }
    }

    private void validateIndago() {
        String path = indagoPathField.getText().trim();
        if (path.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Please enter the Indago path first.",
                    "Validation",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Temporarily set the path for validation
        String oldPath = config.getIndagoPath();
        config.setIndagoPath(path);

        boolean valid = extension.getScanLauncher().validateInstallation();

        if (valid) {
            JOptionPane.showMessageDialog(this,
                    "Indago installation validated successfully!",
                    "Validation Successful",
                    JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this,
                    "Failed to validate Indago installation.\n" +
                            "Please check the path and ensure Indago is installed correctly.",
                    "Validation Failed",
                    JOptionPane.ERROR_MESSAGE);
            config.setIndagoPath(oldPath);
        }
    }

    private void loadConfig() {
        indagoPathField.setText(config.getIndagoPath());
        providerCombo.setSelectedItem(config.getLlmProvider());
        modelField.setText(config.getLlmModel());
        apiKeyField.setText(config.getApiKey());
        llmUrlField.setText(config.getLlmUrl());
        useLlmPayloadsCheck.setSelected(config.isUseLlmPayloads());
        llmConcurrencySpinner.setValue(config.getLlmConcurrency());
        concurrencySpinner.setValue(config.getConcurrency());
        rateLimitSpinner.setValue(config.getRateLimit());
        timeoutSpinner.setValue(config.getTimeout());
        verifySSLCheck.setSelected(config.isVerifySSL());
        useProxyCheck.setSelected(config.isUseProxy());
        proxyHostField.setText(config.getProxyHost());
        proxyPortSpinner.setValue(config.getProxyPort());
        autoImportCheck.setSelected(config.isAutoImport());
    }

    private void saveConfig() {
        config.setIndagoPath(indagoPathField.getText().trim());
        config.setLlmProvider((String) providerCombo.getSelectedItem());
        config.setLlmModel(modelField.getText().trim());
        config.setApiKey(new String(apiKeyField.getPassword()));
        config.setLlmUrl(llmUrlField.getText().trim());
        config.setUseLlmPayloads(useLlmPayloadsCheck.isSelected());
        config.setLlmConcurrency((Integer) llmConcurrencySpinner.getValue());
        config.setConcurrency((Integer) concurrencySpinner.getValue());
        config.setRateLimit((Double) rateLimitSpinner.getValue());
        config.setTimeout((Integer) timeoutSpinner.getValue());
        config.setVerifySSL(verifySSLCheck.isSelected());
        config.setUseProxy(useProxyCheck.isSelected());
        config.setProxyHost(proxyHostField.getText().trim());
        config.setProxyPort((Integer) proxyPortSpinner.getValue());
        config.setAutoImport(autoImportCheck.isSelected());

        extension.saveConfig();

        JOptionPane.showMessageDialog(this,
                "Configuration saved successfully.",
                "Configuration Saved",
                JOptionPane.INFORMATION_MESSAGE);
    }

    private void resetConfig() {
        int result = JOptionPane.showConfirmDialog(this,
                "Reset all settings to defaults?",
                "Reset Configuration",
                JOptionPane.YES_NO_OPTION);

        if (result == JOptionPane.YES_OPTION) {
            IndagoConfig defaultConfig = new IndagoConfig();
            config.setIndagoPath(defaultConfig.getIndagoPath());
            config.setLlmProvider(defaultConfig.getLlmProvider());
            config.setLlmModel(defaultConfig.getLlmModel());
            config.setApiKey(defaultConfig.getApiKey());
            config.setLlmUrl(defaultConfig.getLlmUrl());
            config.setUseLlmPayloads(defaultConfig.isUseLlmPayloads());
            config.setLlmConcurrency(defaultConfig.getLlmConcurrency());
            config.setConcurrency(defaultConfig.getConcurrency());
            config.setRateLimit(defaultConfig.getRateLimit());
            config.setTimeout(defaultConfig.getTimeout());
            config.setVerifySSL(defaultConfig.isVerifySSL());
            config.setUseProxy(defaultConfig.isUseProxy());
            config.setProxyHost(defaultConfig.getProxyHost());
            config.setProxyPort(defaultConfig.getProxyPort());
            config.setAutoImport(defaultConfig.isAutoImport());

            loadConfig();
            extension.saveConfig();
        }
    }
}
