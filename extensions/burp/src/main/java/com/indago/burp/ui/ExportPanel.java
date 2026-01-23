package com.indago.burp.ui;

import com.indago.burp.IndagoExtension;
import com.indago.burp.model.ExportItem;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.io.File;
import java.util.List;

/**
 * Panel for managing the export queue.
 */
public class ExportPanel extends JPanel {

    private final IndagoExtension extension;
    private final JTable table;
    private final ExportTableModel tableModel;

    public ExportPanel(IndagoExtension extension) {
        this.extension = extension;

        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Create table
        tableModel = new ExportTableModel(extension.getExportQueue());
        table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.getColumnModel().getColumn(0).setPreferredWidth(60);  // Method
        table.getColumnModel().getColumn(1).setPreferredWidth(300); // URL
        table.getColumnModel().getColumn(2).setPreferredWidth(50);  // Status
        table.getColumnModel().getColumn(3).setPreferredWidth(120); // Time

        JScrollPane scrollPane = new JScrollPane(table);
        add(scrollPane, BorderLayout.CENTER);

        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton removeButton = new JButton("Remove Selected");
        removeButton.addActionListener(e -> removeSelected());
        buttonPanel.add(removeButton);

        JButton clearButton = new JButton("Clear All");
        clearButton.addActionListener(e -> clearAll());
        buttonPanel.add(clearButton);

        buttonPanel.add(Box.createHorizontalStrut(20));

        JButton exportButton = new JButton("Export to File...");
        exportButton.addActionListener(e -> exportToFile());
        buttonPanel.add(exportButton);

        JButton scanButton = new JButton("Scan with Indago");
        scanButton.addActionListener(e -> scanWithIndago());
        buttonPanel.add(scanButton);

        add(buttonPanel, BorderLayout.SOUTH);

        // Info label
        JLabel infoLabel = new JLabel(
                "<html>Add requests here via context menu: right-click on any request and select " +
                        "<b>Indago > Send to Indago</b></html>"
        );
        infoLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
        add(infoLabel, BorderLayout.NORTH);
    }

    /**
     * Refresh the table model.
     */
    public void refresh() {
        tableModel.fireTableDataChanged();
    }

    private void removeSelected() {
        int[] selectedRows = table.getSelectedRows();
        if (selectedRows.length == 0) {
            return;
        }

        extension.removeFromExportQueue(selectedRows);
    }

    private void clearAll() {
        if (extension.getExportQueue().isEmpty()) {
            return;
        }

        int result = JOptionPane.showConfirmDialog(this,
                "Clear all " + extension.getExportQueue().size() + " items from the queue?",
                "Clear Export Queue",
                JOptionPane.YES_NO_OPTION);

        if (result == JOptionPane.YES_OPTION) {
            extension.clearExportQueue();
        }
    }

    private void exportToFile() {
        if (extension.getExportQueue().isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Export queue is empty.",
                    "Export",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export to Burp XML");
        fileChooser.setSelectedFile(new File("indago-export.xml"));

        int result = fileChooser.showSaveDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();

            // Add .xml extension if missing
            if (!file.getName().toLowerCase().endsWith(".xml")) {
                file = new File(file.getAbsolutePath() + ".xml");
            }

            try {
                extension.getExporter().exportToFile(extension.getExportQueue(), file);

                JOptionPane.showMessageDialog(this,
                        "Exported " + extension.getExportQueue().size() + " requests to:\n" +
                                file.getAbsolutePath(),
                        "Export Complete",
                        JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this,
                        "Export failed: " + e.getMessage(),
                        "Export Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void scanWithIndago() {
        if (extension.getExportQueue().isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Export queue is empty.",
                    "Scan",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (!extension.getConfig().isValid()) {
            JOptionPane.showMessageDialog(this,
                    "Indago path not configured.\n" +
                            "Please configure Indago in the Settings tab.",
                    "Configuration Required",
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

        // Generate XML from queue
        String xml = extension.getExporter().export(extension.getExportQueue());

        // Launch scan
        extension.getScanLauncher().launchScan(
                xml,
                line -> extension.getMainTab().appendScanOutput(line),
                () -> extension.getMainTab().onScanComplete()
        );

        // Switch to scan tab
        extension.getMainTab().selectScanTab();
    }

    /**
     * Table model for the export queue.
     */
    private static class ExportTableModel extends AbstractTableModel {
        private final List<ExportItem> items;
        private final String[] columns = {"Method", "URL", "Status", "Added"};

        public ExportTableModel(List<ExportItem> items) {
            this.items = items;
        }

        @Override
        public int getRowCount() {
            return items.size();
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
            if (rowIndex < 0 || rowIndex >= items.size()) {
                return null;
            }

            ExportItem item = items.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return item.getMethod();
                case 1:
                    return item.getUrl();
                case 2:
                    return item.getStatusCode() > 0 ? String.valueOf(item.getStatusCode()) : "";
                case 3:
                    return item.getTimestamp();
                default:
                    return null;
            }
        }
    }
}
