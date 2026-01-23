package com.indago.burp.ui;

import com.indago.burp.IndagoExtension;

import javax.swing.*;
import java.awt.*;

/**
 * Panel for controlling and monitoring Indago scans.
 */
public class ScanPanel extends JPanel {

    private final IndagoExtension extension;
    private final JTextArea outputArea;
    private final JButton startButton;
    private final JButton stopButton;
    private final JButton clearButton;
    private final JLabel statusLabel;

    public ScanPanel(IndagoExtension extension) {
        this.extension = extension;

        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Control panel at top
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        startButton = new JButton("Start Scan");
        startButton.addActionListener(e -> startScan());
        controlPanel.add(startButton);

        stopButton = new JButton("Stop Scan");
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopScan());
        controlPanel.add(stopButton);

        clearButton = new JButton("Clear Output");
        clearButton.addActionListener(e -> clearOutput());
        controlPanel.add(clearButton);

        controlPanel.add(Box.createHorizontalStrut(20));

        statusLabel = new JLabel("Ready");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD));
        controlPanel.add(statusLabel);

        add(controlPanel, BorderLayout.NORTH);

        // Output area
        outputArea = new JTextArea();
        outputArea.setEditable(false);
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        outputArea.setLineWrap(true);
        outputArea.setWrapStyleWord(true);

        JScrollPane scrollPane = new JScrollPane(outputArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        add(scrollPane, BorderLayout.CENTER);

        // Info panel at bottom
        JPanel infoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        infoPanel.add(new JLabel(
                "<html><i>Tip: You can also start scans from the Export tab or via context menu.</i></html>"
        ));
        add(infoPanel, BorderLayout.SOUTH);
    }

    /**
     * Append a line to the output area.
     */
    public void appendOutput(String line) {
        SwingUtilities.invokeLater(() -> {
            outputArea.append(line + "\n");
            // Auto-scroll to bottom
            outputArea.setCaretPosition(outputArea.getDocument().getLength());
        });
    }

    /**
     * Called when a scan starts.
     */
    public void onScanStart() {
        SwingUtilities.invokeLater(() -> {
            startButton.setEnabled(false);
            stopButton.setEnabled(true);
            statusLabel.setText("Scanning...");
            statusLabel.setForeground(new Color(0, 100, 0)); // Dark green
        });
    }

    /**
     * Called when a scan completes.
     */
    public void onScanComplete() {
        SwingUtilities.invokeLater(() -> {
            startButton.setEnabled(true);
            stopButton.setEnabled(false);
            statusLabel.setText("Scan Complete");
            statusLabel.setForeground(Color.BLUE);

            appendOutput("\n=== Scan Complete ===\n");
        });
    }

    private void startScan() {
        if (!extension.getConfig().isValid()) {
            JOptionPane.showMessageDialog(this,
                    "Indago path not configured.\n" +
                            "Please configure Indago in the Settings tab.",
                    "Configuration Required",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (extension.getExportQueue().isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Export queue is empty.\n" +
                            "Add requests using the context menu: right-click > Indago > Send to Indago",
                    "No Requests",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (extension.getScanLauncher().isRunning()) {
            JOptionPane.showMessageDialog(this,
                    "A scan is already running.",
                    "Scan In Progress",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Clear output
        outputArea.setText("");

        // Generate XML from queue
        String xml = extension.getExporter().export(extension.getExportQueue());

        appendOutput("Starting Indago scan with " + extension.getExportQueue().size() + " requests...\n");
        appendOutput("=====================================\n");

        onScanStart();

        // Launch scan
        boolean started = extension.getScanLauncher().launchScan(
                xml,
                this::appendOutput,
                this::onScanComplete
        );

        if (!started) {
            onScanComplete();
            appendOutput("Failed to start scan. Check the Burp extension output for details.\n");
        }
    }

    private void stopScan() {
        if (extension.getScanLauncher().isRunning()) {
            appendOutput("\nStopping scan...\n");
            extension.getScanLauncher().stopScan();
            onScanComplete();
            statusLabel.setText("Scan Stopped");
            statusLabel.setForeground(Color.RED);
        }
    }

    private void clearOutput() {
        outputArea.setText("");
        statusLabel.setText("Ready");
        statusLabel.setForeground(Color.BLACK);
    }
}
