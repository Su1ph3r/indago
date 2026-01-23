package com.indago.burp.ui;

import com.indago.burp.IndagoExtension;
import com.indago.burp.import_.JsonImporter;
import com.indago.burp.model.IndagoFinding;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Panel for displaying and managing Indago findings.
 */
public class FindingsPanel extends JPanel {

    private final IndagoExtension extension;
    private final JTable table;
    private final FindingsTableModel tableModel;
    private final JTextArea detailsArea;
    private final JTextArea requestArea;
    private final JTextArea responseArea;

    private final List<IndagoFinding> findings = new ArrayList<>();

    public FindingsPanel(IndagoExtension extension) {
        this.extension = extension;

        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Split pane - top for table, bottom for details
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.5);

        // Top panel with table and buttons
        JPanel topPanel = new JPanel(new BorderLayout(5, 5));

        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton importButton = new JButton("Import JSON Results...");
        importButton.addActionListener(e -> importResults());
        buttonPanel.add(importButton);

        JButton addToBurpButton = new JButton("Add Selected to Burp Issues");
        addToBurpButton.addActionListener(e -> addSelectedToBurp());
        buttonPanel.add(addToBurpButton);

        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> clearFindings());
        buttonPanel.add(clearButton);

        topPanel.add(buttonPanel, BorderLayout.NORTH);

        // Table
        tableModel = new FindingsTableModel(findings);
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelectedFinding();
            }
        });

        // Set column widths
        table.getColumnModel().getColumn(0).setPreferredWidth(70);  // Severity
        table.getColumnModel().getColumn(1).setPreferredWidth(80);  // Type
        table.getColumnModel().getColumn(2).setPreferredWidth(200); // Title
        table.getColumnModel().getColumn(3).setPreferredWidth(60);  // Method
        table.getColumnModel().getColumn(4).setPreferredWidth(200); // Endpoint
        table.getColumnModel().getColumn(5).setPreferredWidth(80);  // Confidence

        // Severity cell renderer for coloring
        table.getColumnModel().getColumn(0).setCellRenderer(new SeverityCellRenderer());

        JScrollPane tableScrollPane = new JScrollPane(table);
        topPanel.add(tableScrollPane, BorderLayout.CENTER);

        splitPane.setTopComponent(topPanel);

        // Bottom panel with details tabs
        JTabbedPane detailsTabs = new JTabbedPane();

        // Details tab
        detailsArea = new JTextArea();
        detailsArea.setEditable(false);
        detailsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailsArea.setLineWrap(true);
        detailsArea.setWrapStyleWord(true);
        JScrollPane detailsScrollPane = new JScrollPane(detailsArea);
        detailsTabs.addTab("Details", detailsScrollPane);

        // Request tab
        requestArea = new JTextArea();
        requestArea.setEditable(false);
        requestArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane requestScrollPane = new JScrollPane(requestArea);
        detailsTabs.addTab("Request", requestScrollPane);

        // Response tab
        responseArea = new JTextArea();
        responseArea.setEditable(false);
        responseArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane responseScrollPane = new JScrollPane(responseArea);
        detailsTabs.addTab("Response", responseScrollPane);

        splitPane.setBottomComponent(detailsTabs);

        add(splitPane, BorderLayout.CENTER);
    }

    /**
     * Add findings to the panel.
     */
    public void addFindings(List<IndagoFinding> newFindings) {
        findings.addAll(newFindings);
        tableModel.fireTableDataChanged();
    }

    /**
     * Clear all findings.
     */
    public void clearFindings() {
        findings.clear();
        tableModel.fireTableDataChanged();
        detailsArea.setText("");
        requestArea.setText("");
        responseArea.setText("");
    }

    private void importResults() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Import Indago JSON Results");
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("JSON files", "json"));

        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();

            try {
                JsonImporter importer = extension.getImporter();
                List<IndagoFinding> importedFindings = importer.getFindingsFromFile(file);

                if (importedFindings.isEmpty()) {
                    JOptionPane.showMessageDialog(this,
                            "No findings found in the selected file.",
                            "Import",
                            JOptionPane.INFORMATION_MESSAGE);
                    return;
                }

                addFindings(importedFindings);

                JOptionPane.showMessageDialog(this,
                        "Imported " + importedFindings.size() + " findings.",
                        "Import Complete",
                        JOptionPane.INFORMATION_MESSAGE);

            } catch (Exception e) {
                extension.getLogging().logToError("Failed to import: " + e.getMessage());
                JOptionPane.showMessageDialog(this,
                        "Failed to import: " + e.getMessage(),
                        "Import Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void addSelectedToBurp() {
        int[] selectedRows = table.getSelectedRows();
        if (selectedRows.length == 0) {
            JOptionPane.showMessageDialog(this,
                    "Please select findings to add to Burp.",
                    "No Selection",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        int added = 0;
        for (int viewRow : selectedRows) {
            // Convert view index to model index (handles sorting/filtering)
            int modelRow = table.convertRowIndexToModel(viewRow);
            if (modelRow >= 0 && modelRow < findings.size()) {
                IndagoFinding finding = findings.get(modelRow);
                try {
                    com.indago.burp.import_.IndagoAuditIssue issue =
                            new com.indago.burp.import_.IndagoAuditIssue(finding, extension.getApi());
                    extension.getApi().siteMap().add(issue);
                    added++;
                } catch (Exception e) {
                    extension.getLogging().logToError("Failed to add issue: " + e.getMessage());
                }
            }
        }

        JOptionPane.showMessageDialog(this,
                "Added " + added + " findings to Burp issue list.",
                "Complete",
                JOptionPane.INFORMATION_MESSAGE);
    }

    private void showSelectedFinding() {
        int selectedRow = table.getSelectedRow();
        if (selectedRow < 0) {
            detailsArea.setText("");
            requestArea.setText("");
            responseArea.setText("");
            return;
        }

        // Convert view index to model index (handles sorting/filtering)
        int modelRow = table.convertRowIndexToModel(selectedRow);
        if (modelRow < 0 || modelRow >= findings.size()) {
            detailsArea.setText("");
            requestArea.setText("");
            responseArea.setText("");
            return;
        }

        IndagoFinding finding = findings.get(modelRow);

        // Build details text
        StringBuilder details = new StringBuilder();
        details.append("Title: ").append(finding.getTitle()).append("\n");
        details.append("Type: ").append(finding.getType()).append("\n");
        details.append("Severity: ").append(finding.getSeverity()).append("\n");
        details.append("Confidence: ").append(finding.getConfidence()).append("\n");
        details.append("\n");
        details.append("Endpoint: ").append(finding.getMethod()).append(" ").append(finding.getEndpoint()).append("\n");
        if (finding.getParameter() != null && !finding.getParameter().isEmpty()) {
            details.append("Parameter: ").append(finding.getParameter()).append("\n");
        }
        if (finding.getPayload() != null && !finding.getPayload().isEmpty()) {
            details.append("Payload: ").append(finding.getPayload()).append("\n");
        }
        details.append("\n");
        details.append("Description:\n").append(finding.getDescription()).append("\n");
        if (finding.getCwe() != null && !finding.getCwe().isEmpty()) {
            details.append("\nCWE: ").append(finding.getCwe()).append("\n");
        }
        if (finding.getCvss() > 0) {
            details.append("CVSS: ").append(finding.getCvss()).append("\n");
        }
        if (finding.getRemediation() != null && !finding.getRemediation().isEmpty()) {
            details.append("\nRemediation:\n").append(finding.getRemediation()).append("\n");
        }
        if (finding.getCurlCommand() != null && !finding.getCurlCommand().isEmpty()) {
            details.append("\nCurl Command:\n").append(finding.getCurlCommand()).append("\n");
        }

        detailsArea.setText(details.toString());
        detailsArea.setCaretPosition(0);

        // Build request text
        StringBuilder requestText = new StringBuilder();
        if (finding.getEvidence() != null && finding.getEvidence().getRequest() != null) {
            IndagoFinding.Request req = finding.getEvidence().getRequest();
            requestText.append(req.getMethod()).append(" ").append(req.getUrl()).append(" HTTP/1.1\n");
            if (req.getHeaders() != null) {
                req.getHeaders().forEach((k, v) -> requestText.append(k).append(": ").append(v).append("\n"));
            }
            requestText.append("\n");
            if (req.getBody() != null && !req.getBody().isEmpty()) {
                requestText.append(req.getBody());
            }
        }
        requestArea.setText(requestText.toString());
        requestArea.setCaretPosition(0);

        // Build response text
        StringBuilder responseText = new StringBuilder();
        if (finding.getEvidence() != null && finding.getEvidence().getResponse() != null) {
            IndagoFinding.Response resp = finding.getEvidence().getResponse();
            responseText.append("HTTP/1.1 ").append(resp.getStatusCode()).append(" OK\n");
            if (resp.getHeaders() != null) {
                resp.getHeaders().forEach((k, v) -> responseText.append(k).append(": ").append(v).append("\n"));
            }
            responseText.append("\n");
            if (resp.getBody() != null && !resp.getBody().isEmpty()) {
                responseText.append(resp.getBody());
            }
        }
        responseArea.setText(responseText.toString());
        responseArea.setCaretPosition(0);
    }

    /**
     * Table model for findings.
     */
    private static class FindingsTableModel extends AbstractTableModel {
        private final List<IndagoFinding> findings;
        private final String[] columns = {"Severity", "Type", "Title", "Method", "Endpoint", "Confidence"};

        public FindingsTableModel(List<IndagoFinding> findings) {
            this.findings = findings;
        }

        @Override
        public int getRowCount() {
            return findings.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= findings.size()) {
                return null;
            }

            IndagoFinding finding = findings.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return finding.getSeverity();
                case 1:
                    return finding.getType();
                case 2:
                    return finding.getTitle();
                case 3:
                    return finding.getMethod();
                case 4:
                    return finding.getEndpoint();
                case 5:
                    return finding.getConfidence();
                default:
                    return null;
            }
        }
    }

    /**
     * Cell renderer for severity column with color coding.
     */
    private static class SeverityCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            // Always reset to defaults first to handle cell reuse
            if (isSelected) {
                // Use default selection colors
                c.setBackground(table.getSelectionBackground());
                c.setForeground(table.getSelectionForeground());
            } else if (value != null) {
                String severity = value.toString().toLowerCase();
                switch (severity) {
                    case "critical":
                        c.setBackground(new Color(139, 0, 0));  // Dark red
                        c.setForeground(Color.WHITE);
                        break;
                    case "high":
                        c.setBackground(new Color(255, 99, 71)); // Tomato
                        c.setForeground(Color.BLACK);
                        break;
                    case "medium":
                        c.setBackground(new Color(255, 165, 0)); // Orange
                        c.setForeground(Color.BLACK);
                        break;
                    case "low":
                        c.setBackground(new Color(255, 255, 0)); // Yellow
                        c.setForeground(Color.BLACK);
                        break;
                    case "info":
                        c.setBackground(new Color(173, 216, 230)); // Light blue
                        c.setForeground(Color.BLACK);
                        break;
                    default:
                        c.setBackground(table.getBackground());
                        c.setForeground(table.getForeground());
                }
            } else {
                // Reset to table defaults for null values
                c.setBackground(table.getBackground());
                c.setForeground(table.getForeground());
            }

            return c;
        }
    }
}
