package com.indago.burp.ui;

import com.indago.burp.IndagoExtension;

import javax.swing.*;
import java.awt.*;

/**
 * Main tab container for the Indago extension.
 * Contains sub-tabs for Export, Scan, Findings, and Settings.
 */
public class IndagoTab extends JPanel {

    private final IndagoExtension extension;
    private final JTabbedPane tabbedPane;
    private final ExportPanel exportPanel;
    private final ScanPanel scanPanel;
    private final FindingsPanel findingsPanel;
    private final ConfigPanel configPanel;

    public IndagoTab(burp.api.montoya.MontoyaApi api, IndagoExtension extension) {
        this.extension = extension;

        setLayout(new BorderLayout());

        // Header panel
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));

        JLabel titleLabel = new JLabel("Indago - AI-Powered API Security Fuzzer");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 16f));
        headerPanel.add(titleLabel, BorderLayout.WEST);

        JLabel versionLabel = new JLabel("v" + IndagoExtension.VERSION);
        versionLabel.setForeground(Color.GRAY);
        headerPanel.add(versionLabel, BorderLayout.EAST);

        add(headerPanel, BorderLayout.NORTH);

        // Tabbed pane
        tabbedPane = new JTabbedPane();

        // Export tab
        exportPanel = new ExportPanel(extension);
        tabbedPane.addTab("Export Queue", createTabIcon("queue"), exportPanel,
                "Manage requests to scan with Indago");

        // Scan tab
        scanPanel = new ScanPanel(extension);
        tabbedPane.addTab("Scan", createTabIcon("scan"), scanPanel,
                "Control and monitor Indago scans");

        // Findings tab
        findingsPanel = new FindingsPanel(extension);
        tabbedPane.addTab("Findings", createTabIcon("findings"), findingsPanel,
                "View and manage scan findings");

        // Settings tab
        configPanel = new ConfigPanel(extension);
        tabbedPane.addTab("Settings", createTabIcon("settings"), configPanel,
                "Configure Indago settings");

        add(tabbedPane, BorderLayout.CENTER);

        // Footer panel with links
        JPanel footerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        footerPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10));

        JLabel footerLabel = new JLabel("<html><i>Indago: AI-powered context-aware API security testing</i></html>");
        footerLabel.setForeground(Color.GRAY);
        footerPanel.add(footerLabel);

        add(footerPanel, BorderLayout.SOUTH);
    }

    /**
     * Create a simple colored icon for tabs (since we don't have actual icons).
     */
    private Icon createTabIcon(String type) {
        return new Icon() {
            @Override
            public void paintIcon(Component c, Graphics g, int x, int y) {
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

                Color color;
                switch (type) {
                    case "queue":
                        color = new Color(70, 130, 180); // Steel blue
                        break;
                    case "scan":
                        color = new Color(46, 139, 87);  // Sea green
                        break;
                    case "findings":
                        color = new Color(178, 34, 34);  // Fire brick
                        break;
                    case "settings":
                        color = new Color(105, 105, 105); // Dim gray
                        break;
                    default:
                        color = Color.GRAY;
                }

                g2d.setColor(color);
                g2d.fillOval(x, y, 12, 12);
            }

            @Override
            public int getIconWidth() {
                return 12;
            }

            @Override
            public int getIconHeight() {
                return 12;
            }
        };
    }

    /**
     * Refresh the export queue display.
     */
    public void refreshExportQueue() {
        SwingUtilities.invokeLater(() -> exportPanel.refresh());
    }

    /**
     * Append output to the scan panel.
     */
    public void appendScanOutput(String line) {
        scanPanel.appendOutput(line);
    }

    /**
     * Called when a scan completes.
     */
    public void onScanComplete() {
        scanPanel.onScanComplete();
    }

    /**
     * Select the scan tab.
     */
    public void selectScanTab() {
        SwingUtilities.invokeLater(() -> {
            tabbedPane.setSelectedComponent(scanPanel);
            scanPanel.onScanStart();
        });
    }

    /**
     * Select the findings tab.
     */
    public void selectFindingsTab() {
        SwingUtilities.invokeLater(() -> tabbedPane.setSelectedComponent(findingsPanel));
    }

    /**
     * Get the findings panel.
     */
    public FindingsPanel getFindingsPanel() {
        return findingsPanel;
    }
}
