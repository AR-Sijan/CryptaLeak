package com.cryptaleak.ui;

import com.cryptaleak.crypto.CryptoService;
import com.cryptaleak.crypto.HashSplit;
import com.cryptaleak.engine.BulkCredentialSwingWorker;
import com.cryptaleak.engine.BulkVerificationSummary;
import com.cryptaleak.engine.CredentialVerificationEngine;
import com.cryptaleak.engine.CredentialVerificationResult;
import com.cryptaleak.engine.ScanProgressListener;
import com.cryptaleak.strategy.BreachResult;
import com.cryptaleak.strategy.KAnonymitySearchStrategy;

import javax.crypto.SecretKey;
import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * Project CryptaLeak - Employee Portal Frame
 * 
 * Features:
 * - Single credential inspection with client-side SHA-256 and K-Anonymity splitting
 * - Multi-threaded async bulk verification table (Target Prefix, Server Matches, Local Suffix Matches, Security Status)
 * - Raw cryptographic and network telemetry console
 * - E2EE field encryption demonstrations
 */
public class EmployeePortalFrame extends JFrame {

    private final UserSession userSession;
    private final CryptoService cryptoService;
    private final KAnonymitySearchStrategy searchStrategy;
    private final CredentialVerificationEngine verificationEngine;

    // Active worker handle for user cancellation
    private BulkCredentialSwingWorker currentWorker;

    // Single Inspection UI
    private JPasswordField txtSinglePassword;
    private JLabel lblSingleStatus;

    // Bulk Inspection UI
    private JTextArea txtBulkInput;
    private JTable tblBulkResults;
    private DefaultTableModel tableModel;
    private JProgressBar progressBar;
    private JButton btnStartBulk;
    private JButton btnCancelBulk;

    // Raw Crypto Console
    private JTextArea txtConsole;
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss.SSS");

    public EmployeePortalFrame(UserSession userSession) {
        this.userSession = userSession;
        this.cryptoService = new CryptoService();
        this.searchStrategy = new KAnonymitySearchStrategy();
        this.verificationEngine = new CredentialVerificationEngine();

        initComponents();
        logCrypto("Portal initialized for user: " + userSession.getEmail() + " [Role: " + userSession.getRole() + "]");
    }

    private void initComponents() {
        setTitle("Project CryptaLeak - Employee Credential Vault & Privacy Engine");
        setSize(1180, 840);
        setMinimumSize(new Dimension(1000, 700));
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        DarkTheme.applyThemeToFrame(this);

        JPanel mainPanel = new JPanel(new BorderLayout(12, 12));
        mainPanel.setBackground(DarkTheme.BG_DARKEST);
        mainPanel.setBorder(new EmptyBorder(16, 18, 16, 18));

        // 1. HEADER PANEL
        mainPanel.add(buildHeaderPanel(), BorderLayout.NORTH);

        // 2. CENTER CONTENT (Split into Left Inspection & Right Bulk/Console)
        JSplitPane horizontalSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        horizontalSplit.setBackground(DarkTheme.BG_DARKEST);
        horizontalSplit.setDividerLocation(420);
        horizontalSplit.setDividerSize(6);
        horizontalSplit.setBorder(null);

        // Left Panel: Single Credential Inspection & Bulk Input Area
        JPanel leftPanel = new JPanel(new BorderLayout(10, 10));
        leftPanel.setBackground(DarkTheme.BG_DARKEST);
        leftPanel.add(buildSingleInspectionCard(), BorderLayout.NORTH);
        leftPanel.add(buildBulkInputCard(), BorderLayout.CENTER);
        horizontalSplit.setLeftComponent(leftPanel);

        // Right Panel: Bulk Verification Table & Raw Crypto Log Console
        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightSplit.setBackground(DarkTheme.BG_DARKEST);
        rightSplit.setDividerLocation(340);
        rightSplit.setDividerSize(6);
        rightSplit.setBorder(null);
        rightSplit.setTopComponent(buildBulkTableCard());
        rightSplit.setBottomComponent(buildCryptoConsoleCard());

        horizontalSplit.setRightComponent(rightSplit);
        mainPanel.add(horizontalSplit, BorderLayout.CENTER);

        setContentPane(mainPanel);
    }

    // =========================================================================
    // SECTION BUILDERS
    // =========================================================================

    private JPanel buildHeaderPanel() {
        JPanel header = new JPanel(new BorderLayout(10, 10));
        header.setBackground(DarkTheme.BG_CARD);
        header.setBorder(new CompoundBorder(
                new LineBorder(DarkTheme.BORDER_COLOR, 1, true),
                new EmptyBorder(12, 16, 12, 16)
        ));

        // Left: Branding & Title
        JPanel titlePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        titlePanel.setBackground(DarkTheme.BG_CARD);

        JLabel lblIcon = new JLabel("🛡️");
        lblIcon.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 24));

        JPanel textPanel = new JPanel(new GridLayout(2, 1, 0, 2));
        textPanel.setBackground(DarkTheme.BG_CARD);
        JLabel lblTitle = new JLabel("PROJECT CRYPTALEAK");
        lblTitle.setFont(DarkTheme.FONT_TITLE);
        lblTitle.setForeground(DarkTheme.ACCENT_CYAN);

        JLabel lblSub = new JLabel("Zero-Knowledge K-Anonymity Credential Verification Engine");
        lblSub.setFont(DarkTheme.FONT_SMALL);
        lblSub.setForeground(DarkTheme.FG_MUTED);

        textPanel.add(lblTitle);
        textPanel.add(lblSub);
        titlePanel.add(lblIcon);
        titlePanel.add(textPanel);

        // Right: User badge & Navigation
        JPanel userNavPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        userNavPanel.setBackground(DarkTheme.BG_CARD);

        JLabel lblUserBadge = new JLabel(userSession.getEmail() + " (" + userSession.getRole() + ")");
        lblUserBadge.setFont(DarkTheme.FONT_BODY_BOLD);
        lblUserBadge.setForeground(userSession.isBlueTeam() ? DarkTheme.ACCENT_CYAN : DarkTheme.ACCENT_GREEN);

        JButton btnSwitchBlueTeam = DarkTheme.createButton("Blue Team Dashboard ➔", DarkTheme.BG_INPUT, DarkTheme.ACCENT_CYAN);
        btnSwitchBlueTeam.addActionListener(e -> attemptNavigateToBlueTeam());

        JButton btnLogout = DarkTheme.createButton("Logout", DarkTheme.BG_INPUT, DarkTheme.FG_MUTED);
        btnLogout.addActionListener(e -> {
            verificationEngine.shutdown();
            dispose();
            SwingUtilities.invokeLater(() -> new LoginFrame().setVisible(true));
        });

        userNavPanel.add(lblUserBadge);
        userNavPanel.add(btnSwitchBlueTeam);
        userNavPanel.add(btnLogout);

        header.add(titlePanel, BorderLayout.WEST);
        header.add(userNavPanel, BorderLayout.EAST);
        return header;
    }

    private JPanel buildSingleInspectionCard() {
        JPanel card = DarkTheme.createCardPanel();
        card.setLayout(new BorderLayout(8, 8));

        JLabel lblTitle = new JLabel("SINGLE CREDENTIAL INSPECTION");
        lblTitle.setFont(DarkTheme.FONT_BODY_BOLD);
        lblTitle.setForeground(DarkTheme.ACCENT_CYAN);
        card.add(lblTitle, BorderLayout.NORTH);

        JPanel inputRow = new JPanel(new BorderLayout(8, 8));
        inputRow.setBackground(DarkTheme.BG_CARD);

        txtSinglePassword = DarkTheme.createPasswordField(15);
        txtSinglePassword.setText("SecretEmployeePass#2026");

        JButton btnInspect = DarkTheme.createButton("Hash & Verify", DarkTheme.ACCENT_BLUE, DarkTheme.FG_PRIMARY);
        btnInspect.addActionListener(e -> executeSingleInspection());

        inputRow.add(txtSinglePassword, BorderLayout.CENTER);
        inputRow.add(btnInspect, BorderLayout.EAST);

        lblSingleStatus = new JLabel("Status: Awaiting input. Full hash never transmitted across network.");
        lblSingleStatus.setFont(DarkTheme.FONT_SMALL);
        lblSingleStatus.setForeground(DarkTheme.FG_MUTED);

        JPanel contentPanel = new JPanel(new BorderLayout(4, 6));
        contentPanel.setBackground(DarkTheme.BG_CARD);
        contentPanel.add(inputRow, BorderLayout.NORTH);
        contentPanel.add(lblSingleStatus, BorderLayout.SOUTH);

        card.add(contentPanel, BorderLayout.CENTER);
        return card;
    }

    private JPanel buildBulkInputCard() {
        JPanel card = DarkTheme.createCardPanel();
        card.setLayout(new BorderLayout(8, 8));

        JPanel titlePanel = new JPanel(new BorderLayout());
        titlePanel.setBackground(DarkTheme.BG_CARD);
        JLabel lblTitle = new JLabel("ASYNC BULK VERIFICATION INPUT");
        lblTitle.setFont(DarkTheme.FONT_BODY_BOLD);
        lblTitle.setForeground(DarkTheme.ACCENT_CYAN);

        JButton btnLoadDemo = DarkTheme.createButton("Load Sample Batch", DarkTheme.BG_INPUT, DarkTheme.FG_PRIMARY);
        btnLoadDemo.addActionListener(e -> loadSampleBatch());

        titlePanel.add(lblTitle, BorderLayout.WEST);
        titlePanel.add(btnLoadDemo, BorderLayout.EAST);
        card.add(titlePanel, BorderLayout.NORTH);

        txtBulkInput = new JTextArea();
        txtBulkInput.setBackground(DarkTheme.BG_INPUT);
        txtBulkInput.setForeground(DarkTheme.FG_PRIMARY);
        txtBulkInput.setFont(DarkTheme.FONT_MONO);
        txtBulkInput.setCaretColor(DarkTheme.ACCENT_CYAN);
        txtBulkInput.setBorder(new EmptyBorder(8, 8, 8, 8));
        txtBulkInput.setText("CyberSecWinter2026!\nP@ssword123!Secure\nAdminBackup#1099\nMyCleanPassword#992\nAnotherSafePassword#44\nLeakedPass_Admin#2026!\nCorporatePortalSecret#77");

        JScrollPane scrollPane = new JScrollPane(txtBulkInput);
        scrollPane.setBorder(new LineBorder(DarkTheme.BORDER_COLOR));
        card.add(scrollPane, BorderLayout.CENTER);

        // Control buttons
        JPanel buttonBar = new JPanel(new GridLayout(1, 2, 8, 0));
        buttonBar.setBackground(DarkTheme.BG_CARD);

        btnStartBulk = DarkTheme.createButton("▶ Start Asynchronous Scan", DarkTheme.ACCENT_BLUE, DarkTheme.FG_PRIMARY);
        btnStartBulk.addActionListener(e -> startAsyncBulkScan());

        btnCancelBulk = DarkTheme.createButton("⏹ Cancel Scan", DarkTheme.BG_INPUT, DarkTheme.ACCENT_RED);
        btnCancelBulk.setEnabled(false);
        btnCancelBulk.addActionListener(e -> cancelAsyncBulkScan());

        buttonBar.add(btnStartBulk);
        buttonBar.add(btnCancelBulk);
        card.add(buttonBar, BorderLayout.SOUTH);

        return card;
    }

    private JPanel buildBulkTableCard() {
        JPanel card = DarkTheme.createCardPanel();
        card.setLayout(new BorderLayout(8, 8));

        // Top: Title & Progress Bar
        JPanel topRow = new JPanel(new BorderLayout(8, 8));
        topRow.setBackground(DarkTheme.BG_CARD);

        JLabel lblTitle = new JLabel("BULK VERIFICATION STREAM (K-ANONYMITY BUCKETS)");
        lblTitle.setFont(DarkTheme.FONT_BODY_BOLD);
        lblTitle.setForeground(DarkTheme.ACCENT_CYAN);

        progressBar = new JProgressBar(0, 100);
        progressBar.setValue(0);
        progressBar.setStringPainted(true);
        progressBar.setBackground(DarkTheme.BG_INPUT);
        progressBar.setForeground(DarkTheme.ACCENT_BLUE);
        progressBar.setFont(DarkTheme.FONT_SMALL);

        topRow.add(lblTitle, BorderLayout.WEST);
        topRow.add(progressBar, BorderLayout.EAST);
        card.add(topRow, BorderLayout.NORTH);

        // Table Model: Target Prefix, Server Matches, Local Suffix Matches, Security Status
        String[] columns = {"Target Prefix", "Server Matches", "Local Suffix Matches", "Security Status"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        tblBulkResults = new JTable(tableModel);
        DarkTheme.styleTable(tblBulkResults);

        // Custom Cell Renderer to color-code Security Status
        tblBulkResults.getColumnModel().getColumn(3).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                setHorizontalAlignment(JLabel.CENTER);
                String val = (value != null) ? value.toString() : "";
                if (val.contains("COMPROMISED") || val.contains("BREACHED")) {
                    c.setForeground(DarkTheme.ACCENT_RED);
                    setFont(DarkTheme.FONT_BODY_BOLD);
                } else if (val.contains("SECURE") || val.contains("CLEAN")) {
                    c.setForeground(DarkTheme.ACCENT_GREEN);
                    setFont(DarkTheme.FONT_BODY_BOLD);
                } else if (val.contains("ERROR")) {
                    c.setForeground(DarkTheme.ACCENT_AMBER);
                    setFont(DarkTheme.FONT_BODY_BOLD);
                } else {
                    c.setForeground(DarkTheme.FG_PRIMARY);
                }
                c.setBackground(DarkTheme.BG_CARD);
                return c;
            }
        });

        JScrollPane tableScroll = new JScrollPane(tblBulkResults);
        tableScroll.setBorder(new LineBorder(DarkTheme.BORDER_COLOR));
        tableScroll.getViewport().setBackground(DarkTheme.BG_CARD);

        card.add(tableScroll, BorderLayout.CENTER);
        return card;
    }

    private JPanel buildCryptoConsoleCard() {
        JPanel card = DarkTheme.createCardPanel();
        card.setLayout(new BorderLayout(6, 6));

        JPanel topBar = new JPanel(new BorderLayout());
        topBar.setBackground(DarkTheme.BG_CARD);

        JLabel lblTitle = new JLabel("RAW CRYPTOGRAPHIC & NETWORK TELEMETRY LOGS");
        lblTitle.setFont(DarkTheme.FONT_BODY_BOLD);
        lblTitle.setForeground(DarkTheme.ACCENT_CYAN);

        JButton btnClear = DarkTheme.createButton("Clear", DarkTheme.BG_INPUT, DarkTheme.FG_MUTED);
        btnClear.addActionListener(e -> txtConsole.setText(""));

        topBar.add(lblTitle, BorderLayout.WEST);
        topBar.add(btnClear, BorderLayout.EAST);
        card.add(topBar, BorderLayout.NORTH);

        txtConsole = DarkTheme.createConsoleArea();
        JScrollPane consoleScroll = new JScrollPane(txtConsole);
        consoleScroll.setBorder(new LineBorder(DarkTheme.BORDER_COLOR));

        card.add(consoleScroll, BorderLayout.CENTER);
        return card;
    }

    // =========================================================================
    // EXECUTION HANDLERS
    // =========================================================================

    private void executeSingleInspection() {
        String input = new String(txtSinglePassword.getPassword()).trim();
        if (input.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a credential to verify.", "Empty Input", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            // Client-side computation
            HashSplit split = cryptoService.splitCredential(input);
            logCrypto(String.format("[CLIENT-SHA256] Hashed credential locally -> %s", split.getFullHash()));
            logCrypto(String.format("[K-ANONYMITY] Prefix extracted: [%s] (Suffix withheld client-side: %s...)",
                    split.getPrefix(), split.getSuffix().substring(0, 8)));

            // E2EE Field demonstration
            SecretKey sessionKey = cryptoService.generateAESKey();
            String e2eePayload = cryptoService.encryptPayload("{\"target_prefix\":\"" + split.getPrefix() + "\",\"audit_user\":\"" + userSession.getEmail() + "\"}", sessionKey);
            logCrypto(String.format("[E2EE-AES-GCM] Encrypted Audit Payload (256-bit): %s", e2eePayload.substring(0, 45) + "..."));

            // Zero-knowledge server lookup
            BreachResult result = searchStrategy.checkCredential(input);

            if (result.isCompromised()) {
                lblSingleStatus.setText(String.format("Status: ⚠️ COMPROMISED in %s! Server Candidates: %d",
                        result.getBreachSource(), result.getTotalCandidatesReceived()));
                lblSingleStatus.setForeground(DarkTheme.ACCENT_RED);
                logCrypto(String.format("[ALERT] Suffix match confirmed against bucket %s! Source: %s",
                        split.getPrefix(), result.getBreachSource()));
            } else {
                lblSingleStatus.setText(String.format("Status: ✔️ SECURE! Zero matches across %d bucket candidates.",
                        result.getTotalCandidatesReceived()));
                lblSingleStatus.setForeground(DarkTheme.ACCENT_GREEN);
                logCrypto(String.format("[SUCCESS] Zero matches in bucket %s. Credential verified secure.", split.getPrefix()));
            }

        } catch (Exception ex) {
            lblSingleStatus.setText("Status: Error during inspection - " + ex.getMessage());
            lblSingleStatus.setForeground(DarkTheme.ACCENT_AMBER);
            logCrypto("[ERROR] Inspection failed: " + ex.getMessage());
        }
    }

    private void startAsyncBulkScan() {
        String rawText = txtBulkInput.getText().trim();
        if (rawText.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Bulk input is empty. Paste credentials or click 'Load Sample Batch'.", "Empty Batch", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String[] lines = rawText.split("\\r?\\n");
        List<String> list = new ArrayList<>();
        for (String line : lines) {
            if (!line.trim().isEmpty()) {
                list.add(line.trim());
            }
        }

        if (list.isEmpty()) return;

        // Reset Table & Progress
        tableModel.setRowCount(0);
        progressBar.setValue(0);
        progressBar.setMaximum(list.size());
        btnStartBulk.setEnabled(false);
        btnCancelBulk.setEnabled(true);

        logCrypto(String.format("[ASYNC ENGINE] Starting multi-threaded verification of %d items...", list.size()));

        // Submit to asynchronous processing engine
        currentWorker = verificationEngine.submitBulkScan(list, new ScanProgressListener() {
            @Override
            public void onProgressUpdate(int processedCount, int totalCount, CredentialVerificationResult result) {
                progressBar.setValue(processedCount);
                progressBar.setString(String.format("%d / %d (%d%%)", processedCount, totalCount, (int)((double)processedCount / totalCount * 100)));

                String suffixMatchStr = result.isCompromised() ? "MATCH CONFIRMED (" + result.getBreachSource() + ")" : "Zero Match (Clean)";
                String statusStr = result.getStatus().name();

                tableModel.addRow(new Object[]{
                        result.getHashPrefix(),
                        result.getBucketCandidatesExamined(),
                        suffixMatchStr,
                        statusStr
                });

                logCrypto(String.format("[EDT-STREAM #%02d] Prefix: %s | Server Candidates: %d | Status: %s (%dms)",
                        processedCount, result.getHashPrefix(), result.getBucketCandidatesExamined(),
                        result.getStatus(), result.getProcessingTimeMs()));
            }

            @Override
            public void onScanCompleted(BulkVerificationSummary summary) {
                btnStartBulk.setEnabled(true);
                btnCancelBulk.setEnabled(false);
                logCrypto(String.format("[BATCH COMPLETED] Total: %d, Compromised: %d (%.1f%%), Secure: %d, Errors: %d in %dms",
                        summary.getTotalProcessed(), summary.getTotalCompromised(),
                        summary.getCompromiseRatePercentage(), summary.getTotalSecure(),
                        summary.getTotalErrors(), summary.getTotalDurationMs()));

                JOptionPane.showMessageDialog(EmployeePortalFrame.this,
                        String.format("Bulk Verification Complete!\n\nTotal Processed: %d\nCompromised Leaks: %d\nSecure Clean: %d\nDuration: %d ms",
                                summary.getTotalProcessed(), summary.getTotalCompromised(), summary.getTotalSecure(), summary.getTotalDurationMs()),
                        "Scan Summary", JOptionPane.INFORMATION_MESSAGE);
            }

            @Override
            public void onError(String userFriendlyMessage, Throwable cause) {
                btnStartBulk.setEnabled(true);
                btnCancelBulk.setEnabled(false);
                logCrypto("[PIPELINE ERROR] " + userFriendlyMessage);
                JOptionPane.showMessageDialog(EmployeePortalFrame.this, userFriendlyMessage, "Pipeline Warning", JOptionPane.WARNING_MESSAGE);
            }
        });
    }

    private void cancelAsyncBulkScan() {
        if (currentWorker != null && !currentWorker.isDone()) {
            currentWorker.cancel(true);
            btnStartBulk.setEnabled(true);
            btnCancelBulk.setEnabled(false);
            logCrypto("[ASYNC ENGINE] Scan cancelled by user.");
        }
    }

    private void attemptNavigateToBlueTeam() {
        // ENFORCE ACCESS CONTROL: Block standard employees from accessing Blue Team Dashboard
        if (userSession.isStandardEmployee()) {
            logCrypto("[SECURITY AUDIT] Unauthorized access attempt to Blue Team Dashboard blocked for " + userSession.getEmail());
            JOptionPane.showMessageDialog(this,
                    "⛔ ACCESS DENIED: Insufficient Security Clearance.\n\n" +
                    "Your role (" + userSession.getRole() + ") is not authorized to access Blue Team Incident Response telemetry.\n" +
                    "Only accounts with role ADMIN or SECOPS_ANALYST may view the Blue Team Dashboard.",
                    "Restricted Perimeter", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Navigate to Blue Team Dashboard
        dispose();
        SwingUtilities.invokeLater(() -> new BlueTeamDashboardFrame(userSession).setVisible(true));
    }

    private void loadSampleBatch() {
        txtBulkInput.setText(
                "CyberSecWinter2026!\n" +
                "P@ssword123!Secure\n" +
                "AdminBackup#1099\n" +
                "CleanStaffPassword#999\n" +
                "FinanceLead#Vault88\n" +
                "SafeUniqueCredential_902\n" +
                "DevOpsAccessKey_Alpha\n" +
                "UnbreachedSecureWord!2026"
        );
        logCrypto("[UI] Loaded sample credential batch into input area.");
    }

    private void logCrypto(String msg) {
        String entry = "[" + dateFormat.format(new Date()) + "] " + msg + "\n";
        if (SwingUtilities.isEventDispatchThread()) {
            txtConsole.append(entry);
            txtConsole.setCaretPosition(txtConsole.getDocument().getLength());
        } else {
            SwingUtilities.invokeLater(() -> {
                txtConsole.append(entry);
                txtConsole.setCaretPosition(txtConsole.getDocument().getLength());
            });
        }
    }
}