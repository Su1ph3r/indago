package com.indago.burp.menu;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import com.indago.burp.IndagoExtension;
import com.indago.burp.model.ExportItem;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Provides context menu items for the Indago extension.
 * Adds "Send to Indago", "Scan with Indago Now", and "Export as Burp XML" options.
 */
public class IndagoContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final IndagoExtension extension;

    public IndagoContextMenuProvider(MontoyaApi api, IndagoExtension extension) {
        this.api = api;
        this.extension = extension;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // Get selected request/responses
        List<HttpRequestResponse> selectedItems = event.selectedRequestResponses();
        if (selectedItems.isEmpty()) {
            return menuItems;
        }

        // Create main Indago menu
        JMenu indagoMenu = new JMenu("Indago");

        // Send to Indago (add to export queue)
        JMenuItem sendToIndago = new JMenuItem("Send to Indago");
        sendToIndago.addActionListener(e -> sendToQueue(selectedItems));
        indagoMenu.add(sendToIndago);

        // Scan with Indago Now (immediate scan)
        JMenuItem scanNow = new JMenuItem("Scan with Indago Now");
        scanNow.addActionListener(e -> scanNow(selectedItems));
        indagoMenu.add(scanNow);

        indagoMenu.addSeparator();

        // Export as Burp XML (save to file)
        JMenuItem exportXml = new JMenuItem("Export as Burp XML...");
        exportXml.addActionListener(e -> exportToFile(selectedItems));
        indagoMenu.add(exportXml);

        menuItems.add(indagoMenu);
        return menuItems;
    }

    /**
     * Add selected items to the export queue.
     */
    private void sendToQueue(List<HttpRequestResponse> items) {
        int count = 0;
        for (HttpRequestResponse item : items) {
            // Skip items without responses (they haven't been sent yet)
            if (item.request() == null) {
                continue;
            }

            ExportItem exportItem = new ExportItem(item);
            extension.addToExportQueue(exportItem);
            count++;
        }

        final int added = count;
        extension.getLogging().logToOutput("Added " + added + " items to Indago export queue");

        // Show notification
        if (added > 0) {
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(
                        null,
                        added + " request(s) added to Indago export queue.\n" +
                                "Go to the Indago tab to manage exports.",
                        "Indago",
                        JOptionPane.INFORMATION_MESSAGE
                );
            });
        }
    }

    /**
     * Immediately scan the selected items with Indago.
     */
    private void scanNow(List<HttpRequestResponse> items) {
        // Check if Indago is configured
        if (!extension.getConfig().isValid()) {
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(
                        null,
                        "Indago path not configured.\n" +
                                "Please configure Indago in the Settings tab.",
                        "Indago - Configuration Required",
                        JOptionPane.WARNING_MESSAGE
                );
            });
            return;
        }

        // Check if a scan is already running
        if (extension.getScanLauncher().isRunning()) {
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(
                        null,
                        "A scan is already running.\n" +
                                "Please wait for it to complete or stop it first.",
                        "Indago - Scan In Progress",
                        JOptionPane.WARNING_MESSAGE
                );
            });
            return;
        }

        // Convert to export items and generate XML
        List<ExportItem> exportItems = new ArrayList<>();
        for (HttpRequestResponse item : items) {
            if (item.request() != null) {
                exportItems.add(new ExportItem(item));
            }
        }

        if (exportItems.isEmpty()) {
            return;
        }

        // Generate XML
        String xml = extension.getExporter().export(exportItems);

        // Launch scan
        extension.getScanLauncher().launchScan(
                xml,
                line -> extension.getMainTab().appendScanOutput(line),
                () -> extension.getMainTab().onScanComplete()
        );

        // Switch to scan tab
        extension.getMainTab().selectScanTab();

        extension.getLogging().logToOutput("Started Indago scan on " + exportItems.size() + " requests");
    }

    /**
     * Export selected items to a Burp XML file.
     */
    private void exportToFile(List<HttpRequestResponse> items) {
        // Convert to export items
        List<ExportItem> exportItems = new ArrayList<>();
        for (HttpRequestResponse item : items) {
            if (item.request() != null) {
                exportItems.add(new ExportItem(item));
            }
        }

        if (exportItems.isEmpty()) {
            return;
        }

        // Show file chooser
        SwingUtilities.invokeLater(() -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Export to Burp XML");
            fileChooser.setSelectedFile(new File("indago-export.xml"));

            int result = fileChooser.showSaveDialog(null);
            if (result == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();

                // Add .xml extension if missing
                if (!file.getName().toLowerCase().endsWith(".xml")) {
                    file = new File(file.getAbsolutePath() + ".xml");
                }

                try {
                    extension.getExporter().exportToFile(exportItems, file);

                    JOptionPane.showMessageDialog(
                            null,
                            "Exported " + exportItems.size() + " requests to:\n" + file.getAbsolutePath(),
                            "Indago - Export Complete",
                            JOptionPane.INFORMATION_MESSAGE
                    );
                } catch (Exception e) {
                    extension.getLogging().logToError("Export failed: " + e.getMessage());

                    JOptionPane.showMessageDialog(
                            null,
                            "Failed to export: " + e.getMessage(),
                            "Indago - Export Failed",
                            JOptionPane.ERROR_MESSAGE
                    );
                }
            }
        });
    }
}
