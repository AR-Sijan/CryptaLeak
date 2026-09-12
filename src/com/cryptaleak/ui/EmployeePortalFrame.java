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
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.geom.RoundRectangle2D;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Project CryptaLeak - Employee Credential Vault & Privacy Engine
 * 
 * Production-grade, high-usability employee interface featuring:
 * 1. Single Leak Check View: Centered, clean input field with real-time client-side SHA-256
 *    hashing and an interactive live terminal log explaining K-Anonymity breakdown.
 * 2. Async Bulk Vault Scanner: Multi-threaded credential verification using BulkCredentialSwingWorker,
 *    smooth JProgressBar, live metrics counter (Processed: X/Total, Compromised: Y, Safe: Z),
 *    and colored status badges (COMPROMISED in bold red, SECURE in neon green).
 * 3. 100% Non-Blocking EDT Architecture: Fluid typing and navigation with resilient database
 *    disconnection handling and contextual auto-dismissing toast notifications.
 */
public class EmployeePortalFrame extends JFrame {

    private static final String CARD_SINGLE = "SINGLE_CHECK_VIEW";
    private static final String CARD_BULK = "BULK_SCAN_VIEW";

    private final UserSession userSession;
    private final CryptoService cryptoService;
    private final KAnonymitySearchStrategy searchStrategy;
    private final CredentialVerificationEngine verificationEngine;

    // View Navigation
    private CardLayout cardLayout;
    private JPanel cardsContainer;
    private JButton btnNavSingle;
    private JButton btnNavBulk;

    // Active worker handle for user cancellation
    private BulkCredentialSwingWorker currentWorker;

    // --- Single Leak Check UI ---
    private JPasswordField txtSinglePassword;
    private JButton btnSingleVerify;
    private JLabel lblSingleBadge;
    private JTextArea txtSingleTerminal;

    // --- Async Bulk Scanner UI ---
    private JTextArea txtBulkInput;
    private JTable tblBulkResults;
    private DefaultTableModel tableModel;
    private JProgressBar progressBar;
    private JButton btnStartBulk;
    private JButton btnCancelBulk;

    // Live Metrics Counter Badges
    private MetricPillBadge metricProcessed;
    private MetricPillBadge metricCompromised;
    private MetricPillBadge metricSafe;

    private int liveProcessedCount = 0;
    private int liveCompromisedCount = 0;
    private int liveSafeCount = 0;

    // Raw Crypto Telemetry Console
    private JTextArea txtConsole;
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss.SSS");

    public EmployeePortalFrame(UserSession userSession) {
        this.userSession = userSession;
        this.cryptoService = new CryptoService();
        this.searchStrategy = new KAnonymitySearchStrategy();
        this.verificationEngine = new CredentialVerificationEngine();

        initComponents();
        logCrypto("Employee Vault session initialized for: " + userSession.getEmail() + " [" + userSession.getRole() + "]");
    }

    private void initComponents() {
        setTitle("Project CryptaLeak - Zero-Knowledge Employee Credential Vault");
        setSize(1320, 900);
        setMinimumSize(new Dimension(1120, 780));
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        DarkTheme.applyThemeToFrame(this);

        JPanel mainPanel = new JPanel(new BorderLayout(14, 14));
        mainPanel.setBackground(DarkTheme.BG_DARKEST);
        mainPanel.setBorder(new EmptyBorder(16, 20, 16, 20));

        // 1. TOP HEADER & VIEW NAVIGATION SWITCHER
        mainPanel.add(buildHeaderPanel(), BorderLayout.NORTH);

        // 2. CENTER CARDS CONTAINER (Single Leak Check vs Async Bulk Vault Scanner)
        cardLayout = new CardLayout();
        cardsContainer = new JPanel(cardLayout);
        cardsContainer.setOpaque(false);

        cardsContainer.add(buildSingleLeakCheckView(), CARD_SINGLE);
        cardsContainer.add(buildBulkScannerView(), CARD_BULK);

        mainPanel.add(cardsContainer, BorderLayout.CENTER);
        setContentPane(mainPanel);

        // Default to Single Check View
        switchToView(CARD_SINGLE);
    }

    // =========================================================================
    // HEADER & NAVIGATION SWITCHER
    // =========================================================================

    private JPanel buildHeaderPanel() {
        JPanel header = new JPanel(new BorderLayout(10, 10));
        header.setBackground(DarkTheme.BG_CARD);
        header.setBorder(new CompoundBorder(
                new LineBorder(DarkTheme.BORDER_COLOR, 1, true),
                new EmptyBorder(12, 16, 12, 16)
        ));

        // Left: Branding & Subtitle
        JPanel titlePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        titlePanel.setBackground(DarkTheme.BG_CARD);

        JLabel lblIcon = new JLabel("🛡️");
        lblIcon.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 28));

        JPanel textPanel = new JPanel();
        textPanel.setLayout(new BoxLayout(textPanel, BoxLayout.Y_AXIS));
        textPanel.setBackground(DarkTheme.BG_CARD);

        JLabel lblTitle = new JLabel("PROJECT CRYPTALEAK");
        lblTitle.setFont(DarkTheme.FONT_TITLE);
        lblTitle.setForeground(DarkTheme.ACCENT_CYAN);

        JLabel lblSub = new JLabel("Zero-Knowledge K-Anonymity Credential Vault & Privacy Engine");
        lblSub.setFont(DarkTheme.FONT_SMALL);
        lblSub.setForeground(DarkTheme.FG_MUTED);

        textPanel.add(lblTitle);
        textPanel.add(Box.createVerticalStrut(2));
        textPanel.add(lblSub);

        titlePanel.add(lblIcon);
        titlePanel.add(textPanel);

        // Center: Dual View Switcher Buttons
        JPanel switcherPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 8, 0));
        switcherPanel.setBackground(DarkTheme.BG_CARD);

        btnNavSingle = DarkTheme.createButton("🔍 Single Leak Check View", DarkTheme.BG_INPUT, DarkTheme.ACCENT_CYAN);
        btnNavSingle.setToolTipText("Interactive client-side SHA-256 inspection with real-time K-Anonymity breakdown");
        btnNavSingle.addActionListener(e -> switchToView(CARD_SINGLE));

        btnNavBulk = DarkTheme.createButton("⚡ Async Bulk Vault Scanner", DarkTheme.BG_INPUT, DarkTheme.FG_MUTED);
        btnNavBulk.setToolTipText("High-throughput background verification table with progress and live metric counters");
        btnNavBulk.addActionListener(e -> switchToView(CARD_BULK));

        switcherPanel.add(btnNavSingle);
        switcherPanel.add(btnNavBulk);

        // Right: User Clearance & Action Nav
        JPanel userNavPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        userNavPanel.setBackground(DarkTheme.BG_CARD);

        JLabel lblUserBadge = new JLabel(userSession.getEmail() + " (" + userSession.getRole() + ")");
        lblUserBadge.setFont(DarkTheme.FONT_BODY_BOLD);
        lblUserBadge.setForeground(userSession.isBlueTeam() ? DarkTheme.ACCENT_CYAN : DarkTheme.ACCENT_GREEN);

        JButton btnSwitchBlueTeam = DarkTheme.createButton("Blue Team SOC ➔", DarkTheme.BG_INPUT, DarkTheme.ACCENT_CYAN);
        btnSwitchBlueTeam.setToolTipText("Navigate to Blue Team Incident Response Dashboard (Admin/SecOps only)");
        btnSwitchBlueTeam.addActionListener(e -> attemptNavigateToBlueTeam());

        JButton btnLogout = DarkTheme.createButton("Logout", DarkTheme.BG_INPUT, DarkTheme.FG_MUTED);
        btnLogout.setToolTipText("End current session");
        btnLogout.addActionListener(e -> {
            verificationEngine.shutdown();
            dispose();
            SwingUtilities.invokeLater(() -> new LoginFrame().setVisible(true));
        });

        userNavPanel.add(lblUserBadge);
        userNavPanel.add(btnSwitchBlueTeam);
        userNavPanel.add(btnLogout);

        header.add(titlePanel, BorderLayout.WEST);
        header.add(switcherPanel, BorderLayout.CENTER);
        header.add(userNavPanel, BorderLayout.EAST);
        return header;
    }

    private void switchToView(String cardName) {
        cardLayout.show(cardsContainer, cardName);
        if (CARD_SINGLE.equals(cardName)) {
            btnNavSingle.setForeground(DarkTheme.ACCENT_CYAN);
            btnNavSingle.setFont(DarkTheme.FONT_BODY_BOLD);
            btnNavBulk.setForeground(DarkTheme.FG_MUTED);
            btnNavBulk.setFont(DarkTheme.FONT_BODY);
        } else {
            btnNavBulk.setForeground(DarkTheme.ACCENT_CYAN);
            btnNavBulk.setFont(DarkTheme.FONT_BODY_BOLD);
            btnNavSingle.setForeground(DarkTheme.FG_MUTED);
            btnNavSingle.setFont(DarkTheme.FONT_BODY);
        }
    }

    // =========================================================================
    // VIEW 1: SINGLE LEAK CHECK VIEW (CENTERED & REAL-TIME)
    // =========================================================================

    private JPanel buildSingleLeakCheckView() {
        JPanel view = new JPanel(new BorderLayout(14, 14));
        view.setOpaque(false);

        // Center wrapper with clean layout
        JPanel centerWrapper = new JPanel(new GridBagLayout());
        centerWrapper.setOpaque(false);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 40, 14, 40);

        // 1. Search & Input Card
        JPanel inputCard = DarkTheme.createCardPanel();
        inputCard.setLayout(new BoxLayout(inputCard, BoxLayout.Y_AXIS));
        inputCard.setBorder(new EmptyBorder(20, 24, 20, 24));

        JLabel lblSearchTitle = new JLabel("ZERO-KNOWLEDGE CREDENTIAL LEAK INSPECTION");
        lblSearchTitle.setFont(DarkTheme.FONT_HEADER);
        lblSearchTitle.setForeground(DarkTheme.ACCENT_CYAN);
        lblSearchTitle.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel lblSearchSub = new JLabel("Type or paste any password below. Local client-side SHA-256 is computed instantly in JVM memory.");
        lblSearchSub.setFont(DarkTheme.FONT_BODY);
        lblSearchSub.setForeground(DarkTheme.FG_MUTED);
        lblSearchSub.setAlignmentX(Component.CENTER_ALIGNMENT);

        // Search Field with Embedded Toggle Eye Icon
        JPanel searchBox = new JPanel(new BorderLayout(8, 0));
        searchBox.setOpaque(false);
        searchBox.setMaximumSize(new Dimension(800, 46));
        searchBox.setAlignmentX(Component.CENTER_ALIGNMENT);

        txtSinglePassword = DarkTheme.createPasswordField(30);
        txtSinglePassword.setText("SecretEmployeePass#2026");
        txtSinglePassword.setFont(new Font("Segoe UI", Font.PLAIN, 16));

        JButton btnToggleEye = new JButton("👁");
        btnToggleEye.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 16));
        btnToggleEye.setFocusPainted(false);
        btnToggleEye.setContentAreaFilled(false);
        btnToggleEye.setBorderPainted(false);
        btnToggleEye.setForeground(DarkTheme.FG_MUTED);
        btnToggleEye.setCursor(new Cursor(Cursor.HAND_CURSOR));
        btnToggleEye.setToolTipText("Toggle password visibility");

        final boolean[] passVisible = {false};
        btnToggleEye.addActionListener(e -> {
            passVisible[0] = !passVisible[0];
            if (passVisible[0]) {
                txtSinglePassword.setEchoChar((char) 0);
                btnToggleEye.setForeground(DarkTheme.ACCENT_CYAN);
            } else {
                txtSinglePassword.setEchoChar('•');
                btnToggleEye.setForeground(DarkTheme.FG_MUTED);
            }
        });

        searchBox.add(txtSinglePassword, BorderLayout.CENTER);
        searchBox.add(btnToggleEye, BorderLayout.EAST);

        // Action Buttons Row
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        actionRow.setOpaque(false);
        actionRow.setAlignmentX(Component.CENTER_ALIGNMENT);

        btnSingleVerify = DarkTheme.createButton("🔍 Verify Against Breach Vault", DarkTheme.ACCENT_BLUE, DarkTheme.FG_PRIMARY);
        btnSingleVerify.setFont(DarkTheme.FONT_BODY_BOLD);
        btnSingleVerify.setToolTipText("Query zero-knowledge 5-char prefix bucket against MySQL without sending full hash");
        btnSingleVerify.addActionListener(e -> executeSingleInspectionAsync());

        JButton btnSample = DarkTheme.createButton("🎲 Load Sample", DarkTheme.BG_INPUT, DarkTheme.FG_PRIMARY);
        btnSample.setToolTipText("Load a sample credential to test");
        btnSample.addActionListener(e -> {
            String[] samples = {"SecretEmployeePass#2026", "Password123!", "Admin#2026!Crypta", "MySuperCleanCredential#991"};
            String chosen = samples[(int) (Math.random() * samples.length)];
            txtSinglePassword.setText(chosen);
        });

        JButton btnClear = DarkTheme.createButton("🗑️ Clear", DarkTheme.BG_INPUT, DarkTheme.FG_MUTED);
        btnClear.setToolTipText("Clear search input");
        btnClear.addActionListener(e -> {
            txtSinglePassword.setText("");
            lblSingleBadge.setText("● Awaiting credential input");
            lblSingleBadge.setForeground(DarkTheme.FG_MUTED);
            txtSingleTerminal.setText("Awaiting credential input to compute local SHA-256 digest...");
        });

        actionRow.add(btnSingleVerify);
        actionRow.add(btnSample);
        actionRow.add(btnClear);

        // Live Status Badge
        lblSingleBadge = new JLabel("● Client-side SHA-256 hash ready for verification");
        lblSingleBadge.setFont(DarkTheme.FONT_BODY_BOLD);
        lblSingleBadge.setForeground(DarkTheme.ACCENT_CYAN);
        lblSingleBadge.setAlignmentX(Component.CENTER_ALIGNMENT);

        inputCard.add(lblSearchTitle);
        inputCard.add(Box.createVerticalStrut(4));
        inputCard.add(lblSearchSub);
        inputCard.add(Box.createVerticalStrut(18));
        inputCard.add(searchBox);
        inputCard.add(Box.createVerticalStrut(14));
        inputCard.add(actionRow);
        inputCard.add(Box.createVerticalStrut(12));
        inputCard.add(lblSingleBadge);

        centerWrapper.add(inputCard, gbc);

        // 2. Real-Time K-Anonymity Live Terminal Log Card
        gbc.gridy = 1;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;

        JPanel terminalCard = DarkTheme.createCardPanel();
        terminalCard.setLayout(new BorderLayout(8, 8));
        terminalCard.setBorder(new EmptyBorder(16, 20, 16, 20));

        JLabel lblTermTitle = new JLabel("REAL-TIME K-ANONYMITY CRYPTOGRAPHIC BREAKDOWN");
        lblTermTitle.setFont(DarkTheme.FONT_BODY_BOLD);
        lblTermTitle.setForeground(DarkTheme.ACCENT_CYAN);

        JLabel lblTermSub = new JLabel("Explains live prefix partitioning vs. suffix withheld on your machine without network exposure.");
        lblTermSub.setFont(DarkTheme.FONT_SMALL);
        lblTermSub.setForeground(DarkTheme.FG_MUTED);

        JPanel termHeader = new JPanel();
        termHeader.setLayout(new BoxLayout(termHeader, BoxLayout.Y_AXIS));
        termHeader.setOpaque(false);
        termHeader.add(lblTermTitle);
        termHeader.add(Box.createVerticalStrut(2));
        termHeader.add(lblTermSub);

        terminalCard.add(termHeader, BorderLayout.NORTH);

        txtSingleTerminal = DarkTheme.createConsoleArea();
        JScrollPane scrollTerminal = new JScrollPane(txtSingleTerminal);
        scrollTerminal.setBorder(new LineBorder(DarkTheme.BORDER_COLOR));
        terminalCard.add(scrollTerminal, BorderLayout.CENTER);

        centerWrapper.add(terminalCard, gbc);
        view.add(centerWrapper, BorderLayout.CENTER);

        // REAL-TIME DOCUMENT LISTENER: Triggers local SHA-256 and updates live breakdown on typing/pasting
        txtSinglePassword.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { updateRealtimeBreakdown(); }
            @Override
            public void removeUpdate(DocumentEvent e) { updateRealtimeBreakdown(); }
            @Override
            public void changedUpdate(DocumentEvent e) { updateRealtimeBreakdown(); }
        });

        // Enter key in password field triggers verification
        txtSinglePassword.addActionListener(e -> executeSingleInspectionAsync());

        // Initialize with default text
        updateRealtimeBreakdown();

        return view;
    }

    private void updateRealtimeBreakdown() {
        String input = new String(txtSinglePassword.getPassword()).trim();
        if (input.isEmpty()) {
            txtSingleTerminal.setText("Awaiting credential input...\nTyping or pasting will trigger real-time client-side SHA-256 hash partitioning.");
            lblSingleBadge.setText("● Awaiting credential input");
            lblSingleBadge.setForeground(DarkTheme.FG_MUTED);
            return;
        }

        // Sub-millisecond local in-memory computation (Zero network traffic)
        HashSplit split = cryptoService.splitCredential(input);
        String fullHash = split.getFullHash();
        String prefix = split.getPrefix();
        String suffix = split.getSuffix();

        // Prepare simulated E2EE Audit payload preview
        String e2eePayload = "{\"prefix\":\"" + prefix + "\",\"user\":\"" + userSession.getEmail() + "\",\"mode\":\"ZERO_KNOWLEDGE\"}";
        String encryptedSample = "SimulatedAESGCM_Ciphertext_Preview";
        try {
            SecretKey sessionKey = cryptoService.generateAESKey();
            encryptedSample = cryptoService.encryptPayload(e2eePayload, sessionKey);
        } catch (Exception ignored) {}

        StringBuilder sb = new StringBuilder();
        sb.append("╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
        sb.append("║           ZERO-KNOWLEDGE K-ANONYMITY REAL-TIME CRYPTOGRAPHIC PARTITIONING                         ║\n");
        sb.append("╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝\n");
        sb.append(String.format("Input Plaintext Length : %d characters | Input Mask: %s\n", input.length(), maskCredential(input)));
        sb.append(String.format("Local SHA-256 Digest   : %s\n", fullHash));
        sb.append("───────────────────────────────────────────────────────────────────────────────────────────────────\n");
        sb.append("K-ANONYMITY BUCKETING PARTITION (ZERO-TRUST PRIVACY MODEL):\n\n");
        sb.append(String.format("  ├── [TRANSMITTED TO VAULT] 5-Char Prefix   : [%s] ──────► (Sent over network to query hash bucket)\n", prefix));
        sb.append(String.format("  └── [WITHHELD CLIENT-SIDE] 59-Char Suffix  : [%s...]\n", suffix.substring(0, Math.min(32, suffix.length()))));
        sb.append("                                               (Retained strictly in local memory. NEVER transmitted!)\n\n");
        sb.append("───────────────────────────────────────────────────────────────────────────────────────────────────\n");
        sb.append("END-TO-END AUDIT PAYLOAD ENCRYPTION (256-bit AES-GCM):\n");
        sb.append(String.format("  Plaintext  : %s\n", e2eePayload));
        sb.append(String.format("  Ciphertext : %s\n\n", encryptedSample.substring(0, Math.min(64, encryptedSample.length())) + "..."));
        sb.append("───────────────────────────────────────────────────────────────────────────────────────────────────\n");
        sb.append("ZERO-KNOWLEDGE PRIVACY GUARANTEE:\n");
        sb.append("  • The database vault server NEVER learns your password or complete SHA-256 digest.\n");
        sb.append(String.format("  • The server queries its database solely for records starting with prefix '%s'.\n", prefix));
        sb.append("  • All candidate suffix comparisons are performed client-side using constant-time equality.\n");
        sb.append("───────────────────────────────────────────────────────────────────────────────────────────────────\n");
        sb.append("Press [Enter] or click 'Verify Against Breach Vault' to query bucket candidates from MySQL.\n");

        txtSingleTerminal.setText(sb.toString());
        txtSingleTerminal.setCaretPosition(0);

        lblSingleBadge.setText("● Local SHA-256 Ready: Prefix [" + prefix + "] | Suffix withheld locally");
        lblSingleBadge.setForeground(DarkTheme.ACCENT_CYAN);
    }

    private void executeSingleInspectionAsync() {
        String input = new String(txtSinglePassword.getPassword()).trim();
        if (input.isEmpty()) {
            DarkTheme.showToast(this, "⚠️ Please enter a credential to verify.", DarkTheme.ACCENT_AMBER);
            return;
        }

        btnSingleVerify.setEnabled(false);
        btnSingleVerify.setText("🔍 Querying Vault...");
        lblSingleBadge.setText("● Querying K-Anonymity bucket from MySQL...");
        lblSingleBadge.setForeground(DarkTheme.ACCENT_AMBER);

        SwingWorker<BreachResult, Void> worker = new SwingWorker<>() {
            private HashSplit split;

            @Override
            protected BreachResult doInBackground() throws Exception {
                split = cryptoService.splitCredential(input);
                return searchStrategy.checkCredential(input);
            }

            @Override
            protected void done() {
                btnSingleVerify.setEnabled(true);
                btnSingleVerify.setText("🔍 Verify Against Breach Vault");

                try {
                    BreachResult result = get();

                    StringBuilder sb = new StringBuilder(txtSingleTerminal.getText());
                    sb.append("\n===================================================================================================\n");
                    sb.append("LIVE DATABASE VERIFICATION TELEMETRY RESULTS:\n");
                    sb.append("===================================================================================================\n");
                    sb.append(String.format("Prefix Bucket Queried : %s\n", split.getPrefix()));
                    sb.append(String.format("Candidates Examined   : %d bucket candidates returned by MySQL\n", result.getTotalCandidatesReceived()));

                    if (result.isCompromised()) {
                        sb.append(String.format("Security Status       : ⚠️ COMPROMISED (Found in dataset: '%s')\n", result.getBreachSource()));
                        sb.append("Mitigation Advisory   : This credential was identified in leaked breach vaults! Change immediately.\n");

                        lblSingleBadge.setText("⚠️ COMPROMISED: Leaked in " + result.getBreachSource() + " (" + result.getTotalCandidatesReceived() + " candidates)");
                        lblSingleBadge.setForeground(DarkTheme.ACCENT_RED);

                        DarkTheme.showToast(EmployeePortalFrame.this,
                                "⚠️ CRITICAL: Password found in breached dataset (" + result.getBreachSource() + ")!", DarkTheme.ACCENT_RED);
                    } else {
                        sb.append("Security Status       : ✔️ SECURE (Zero suffix matches found in bucket)\n");
                        sb.append("Verification Summary  : Your credential is safe from known compromised credential dumps.\n");

                        lblSingleBadge.setText("✔️ SECURE: Zero matches across " + result.getTotalCandidatesReceived() + " bucket candidates");
                        lblSingleBadge.setForeground(DarkTheme.ACCENT_GREEN);

                        DarkTheme.showToast(EmployeePortalFrame.this,
                                "✔️ Verified Clean: Zero matches in bucket " + split.getPrefix(), DarkTheme.ACCENT_GREEN);
                    }
                    sb.append("===================================================================================================\n");

                    txtSingleTerminal.setText(sb.toString());
                    txtSingleTerminal.setCaretPosition(txtSingleTerminal.getDocument().getLength());

                } catch (Exception ex) {
                    Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                    lblSingleBadge.setText("❌ Verification Error: " + cause.getMessage());
                    lblSingleBadge.setForeground(DarkTheme.ACCENT_RED);

                    if (cause instanceof SQLException) {
                        DarkTheme.showToast(EmployeePortalFrame.this,
                                "⚠️ Database Disconnect: Unable to query MySQL vault. Check localhost:3306.", DarkTheme.ACCENT_RED);
                    } else {
                        DarkTheme.showToast(EmployeePortalFrame.this, "❌ Error: " + cause.getMessage(), DarkTheme.ACCENT_RED);
                    }
                }
            }
        };

        worker.execute();
    }

    // =========================================================================
    // VIEW 2: ASYNC BULK VAULT SCANNER VIEW (RESPONSIVE & MULTI-THREADED)
    // =========================================================================

    private JPanel buildBulkScannerView() {
        JPanel view = new JPanel(new BorderLayout(12, 12));
        view.setOpaque(false);

        // Split between Left Input Card & Right Stream/Table Card
        JSplitPane bulkSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        bulkSplit.setBackground(DarkTheme.BG_DARKEST);
        bulkSplit.setDividerLocation(460);
        bulkSplit.setDividerSize(8);
        bulkSplit.setBorder(null);

        // Left Panel: Input Configuration
        bulkSplit.setLeftComponent(buildBulkInputCard());

        // Right Panel: Results Table, Progress, Live Metrics & Raw Telemetry
        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightSplit.setBackground(DarkTheme.BG_DARKEST);
        rightSplit.setDividerLocation(420);
        rightSplit.setDividerSize(8);
        rightSplit.setBorder(null);

        rightSplit.setTopComponent(buildBulkTableCard());
        rightSplit.setBottomComponent(buildCryptoConsoleCard());

        bulkSplit.setRightComponent(rightSplit);
        view.add(bulkSplit, BorderLayout.CENTER);

        return view;
    }

    private JPanel buildBulkInputCard() {
        JPanel card = DarkTheme.createCardPanel();
        card.setLayout(new BorderLayout(10, 10));

        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));
        headerPanel.setOpaque(false);

        JLabel lblTitle = new JLabel("ASYNC BULK VAULT SCANNER");
        lblTitle.setFont(DarkTheme.FONT_BODY_BOLD);
        lblTitle.setForeground(DarkTheme.ACCENT_CYAN);
        lblTitle.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel lblSub = new JLabel("Paste multiple credentials (one per line) or load simulated batch.");
        lblSub.setFont(DarkTheme.FONT_SMALL);
        lblSub.setForeground(DarkTheme.FG_MUTED);
        lblSub.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        actionRow.setOpaque(false);
        actionRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        JButton btnLoadDemo = DarkTheme.createButton("📋 Load Sample Batch", DarkTheme.BG_INPUT, DarkTheme.FG_PRIMARY);
        btnLoadDemo.setToolTipText("Populate input with sample passwords");
        btnLoadDemo.addActionListener(e -> loadSampleBatch());

        JButton btnClearInput = DarkTheme.createButton("🗑️ Clear", DarkTheme.BG_INPUT, DarkTheme.FG_MUTED);
        btnClearInput.setToolTipText("Clear all inputs");
        btnClearInput.addActionListener(e -> txtBulkInput.setText(""));

        actionRow.add(btnLoadDemo);
        actionRow.add(btnClearInput);

        headerPanel.add(lblTitle);
        headerPanel.add(Box.createVerticalStrut(2));
        headerPanel.add(lblSub);
        headerPanel.add(Box.createVerticalStrut(8));
        headerPanel.add(actionRow);

        card.add(headerPanel, BorderLayout.NORTH);

        txtBulkInput = new JTextArea();
        txtBulkInput.setBackground(DarkTheme.BG_INPUT);
        txtBulkInput.setForeground(DarkTheme.FG_PRIMARY);
        txtBulkInput.setFont(DarkTheme.FONT_MONO);
        txtBulkInput.setCaretColor(DarkTheme.ACCENT_CYAN);
        txtBulkInput.setBorder(new EmptyBorder(8, 8, 8, 8));
        loadSampleBatch();

        JScrollPane scrollPane = new JScrollPane(txtBulkInput);
        scrollPane.setBorder(new LineBorder(DarkTheme.BORDER_COLOR));
        card.add(scrollPane, BorderLayout.CENTER);

        // Control buttons
        JPanel buttonBar = new JPanel(new GridLayout(1, 2, 8, 0));
        buttonBar.setOpaque(false);

        btnStartBulk = DarkTheme.createButton("▶ Start Asynchronous Scan", DarkTheme.ACCENT_BLUE, DarkTheme.FG_PRIMARY);
        btnStartBulk.setToolTipText("Submit batch to background thread pool for concurrent K-Anonymity verification");
        btnStartBulk.addActionListener(e -> startAsyncBulkScan());

        btnCancelBulk = DarkTheme.createButton("⏹ Cancel Scan", DarkTheme.BG_INPUT, DarkTheme.ACCENT_RED);
        btnCancelBulk.setToolTipText("Cancel active worker execution");
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

        // Top: Title, Live Metrics Counter Bar & Smooth JProgressBar
        JPanel topRow = new JPanel();
        topRow.setLayout(new BoxLayout(topRow, BoxLayout.Y_AXIS));
        topRow.setOpaque(false);

        JLabel lblTitle = new JLabel("CONCURRENT VERIFICATION STREAM (K-ANONYMITY BUCKETS)");
        lblTitle.setFont(DarkTheme.FONT_BODY_BOLD);
        lblTitle.setForeground(DarkTheme.ACCENT_CYAN);
        lblTitle.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel lblSub = new JLabel("Worker threads execute concurrent prefix queries & local constant-time suffix comparisons.");
        lblSub.setFont(DarkTheme.FONT_SMALL);
        lblSub.setForeground(DarkTheme.FG_MUTED);
        lblSub.setAlignmentX(Component.LEFT_ALIGNMENT);

        // LIVE METRICS COUNTER BAR: Processed, Compromised, Safe
        JPanel metricsBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        metricsBar.setOpaque(false);
        metricsBar.setAlignmentX(Component.LEFT_ALIGNMENT);

        metricProcessed = new MetricPillBadge("Processed: 0/0 (0%)", DarkTheme.ACCENT_CYAN);
        metricCompromised = new MetricPillBadge("Compromised: 0", DarkTheme.ACCENT_RED);
        metricSafe = new MetricPillBadge("Safe: 0", DarkTheme.ACCENT_GREEN);

        metricsBar.add(metricProcessed);
        metricsBar.add(metricCompromised);
        metricsBar.add(metricSafe);

        // Smooth Styled JProgressBar
        progressBar = new JProgressBar(0, 100);
        progressBar.setValue(0);
        progressBar.setStringPainted(true);
        progressBar.setString("Awaiting batch execution...");
        progressBar.setBackground(DarkTheme.BG_INPUT);
        progressBar.setForeground(DarkTheme.ACCENT_BLUE);
        progressBar.setFont(DarkTheme.FONT_SMALL);
        progressBar.setAlignmentX(Component.LEFT_ALIGNMENT);
        progressBar.setMaximumSize(new Dimension(Short.MAX_VALUE, 22));

        topRow.add(lblTitle);
        topRow.add(Box.createVerticalStrut(2));
        topRow.add(lblSub);
        topRow.add(Box.createVerticalStrut(8));
        topRow.add(metricsBar);
        topRow.add(Box.createVerticalStrut(8));
        topRow.add(progressBar);
        topRow.add(Box.createVerticalStrut(6));

        card.add(topRow, BorderLayout.NORTH);

        // Table Model
        String[] columns = {"Target Prefix", "Server Candidates", "Suffix Verification Details", "Security Status"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };

        tblBulkResults = new JTable(tableModel);
        DarkTheme.styleTable(tblBulkResults);

        // Custom Cell Renderer to render status badges (COMPROMISED in bold red, SECURE in neon green)
        tblBulkResults.getColumnModel().getColumn(3).setCellRenderer(new SecurityStatusBadgeRenderer());

        JScrollPane tableScroll = new JScrollPane(tblBulkResults);
        tableScroll.setBorder(new LineBorder(DarkTheme.BORDER_COLOR));
        tableScroll.getViewport().setBackground(DarkTheme.BG_CARD);

        card.add(tableScroll, BorderLayout.CENTER);
        return card;
    }

    private JPanel buildCryptoConsoleCard() {
        JPanel card = DarkTheme.createCardPanel();
        card.setLayout(new BorderLayout(6, 6));

        JPanel topBar = new JPanel(new BorderLayout(8, 0));
        topBar.setOpaque(false);

        JPanel titlePanel = new JPanel();
        titlePanel.setLayout(new BoxLayout(titlePanel, BoxLayout.Y_AXIS));
        titlePanel.setOpaque(false);

        JLabel lblTitle = new JLabel("RAW CRYPTOGRAPHIC & NETWORK TELEMETRY LOGS");
        lblTitle.setFont(DarkTheme.FONT_BODY_BOLD);
        lblTitle.setForeground(DarkTheme.ACCENT_CYAN);
        lblTitle.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel lblSub = new JLabel("Real-time worker thread event stream, suffix verification latency, and AES audit records.");
        lblSub.setFont(DarkTheme.FONT_SMALL);
        lblSub.setForeground(DarkTheme.FG_MUTED);
        lblSub.setAlignmentX(Component.LEFT_ALIGNMENT);

        titlePanel.add(lblTitle);
        titlePanel.add(Box.createVerticalStrut(2));
        titlePanel.add(lblSub);

        JButton btnClear = DarkTheme.createButton("Clear", DarkTheme.BG_INPUT, DarkTheme.FG_MUTED);
        btnClear.setToolTipText("Clear cryptographic logs");
        btnClear.addActionListener(e -> txtConsole.setText(""));

        topBar.add(titlePanel, BorderLayout.CENTER);
        topBar.add(btnClear, BorderLayout.EAST);
        card.add(topBar, BorderLayout.NORTH);

        txtConsole = DarkTheme.createConsoleArea();
        JScrollPane consoleScroll = new JScrollPane(txtConsole);
        consoleScroll.setBorder(new LineBorder(DarkTheme.BORDER_COLOR));

        card.add(consoleScroll, BorderLayout.CENTER);
        return card;
    }

    // =========================================================================
    // ASYNC BULK WORKER EXECUTION & RESILIENCE
    // =========================================================================

    private void startAsyncBulkScan() {
        String rawText = txtBulkInput.getText().trim();
        if (rawText.isEmpty()) {
            DarkTheme.showToast(this, "⚠️ Bulk input is empty. Paste credentials or load a sample batch.", DarkTheme.ACCENT_AMBER);
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

        // Reset Table, Progress & Live Counters
        tableModel.setRowCount(0);
        liveProcessedCount = 0;
        liveCompromisedCount = 0;
        liveSafeCount = 0;

        progressBar.setValue(0);
        progressBar.setMaximum(list.size());
        progressBar.setString(String.format("Scanning 0 / %d (0%%)...", list.size()));

        metricProcessed.setText(String.format("Processed: 0/%d (0%%)", list.size()));
        metricCompromised.setText("Compromised: 0");
        metricSafe.setText("Safe: 0");

        btnStartBulk.setEnabled(false);
        btnCancelBulk.setEnabled(true);

        logCrypto(String.format("[ASYNC PIPELINE] Submitting %d credentials to ExecutorService thread pool...", list.size()));
        DarkTheme.showToast(this, "▶ Asynchronous bulk scan started for " + list.size() + " items.", DarkTheme.ACCENT_CYAN);

        // Submit to asynchronous processing engine (backed by BulkCredentialSwingWorker)
        currentWorker = verificationEngine.submitBulkScan(list, new ScanProgressListener() {
            @Override
            public void onProgressUpdate(int processedCount, int totalCount, CredentialVerificationResult result) {
                // Guaranteed to run on the EDT via BulkCredentialSwingWorker.process()
                liveProcessedCount = processedCount;
                int percent = (int) ((double) processedCount / totalCount * 100);

                progressBar.setValue(processedCount);
                progressBar.setString(String.format("%d / %d (%d%%)", processedCount, totalCount, percent));
                metricProcessed.setText(String.format("Processed: %d/%d (%d%%)", processedCount, totalCount, percent));

                if (result.isCompromised()) {
                    liveCompromisedCount++;
                    metricCompromised.setText("Compromised: " + liveCompromisedCount);
                } else if (result.getStatus() == CredentialVerificationResult.Status.SECURE) {
                    liveSafeCount++;
                    metricSafe.setText("Safe: " + liveSafeCount);
                }

                String suffixDetails = result.isCompromised()
                        ? "MATCH CONFIRMED (" + result.getBreachSource() + ")"
                        : "Zero Suffix Match (Clean)";

                tableModel.addRow(new Object[]{
                        result.getHashPrefix(),
                        result.getBucketCandidatesExamined(),
                        suffixDetails,
                        result.getStatus().name()
                });

                logCrypto(String.format("[EDT-STREAM #%02d] Prefix: %s | Server Candidates: %d | Status: %s (%dms)",
                        processedCount, result.getHashPrefix(), result.getBucketCandidatesExamined(),
                        result.getStatus(), result.getProcessingTimeMs()));
            }

            @Override
            public void onScanCompleted(BulkVerificationSummary summary) {
                // Guaranteed on EDT
                btnStartBulk.setEnabled(true);
                btnCancelBulk.setEnabled(false);
                progressBar.setString(String.format("Done! %d verified (%d ms)", summary.getTotalProcessed(), summary.getTotalDurationMs()));

                logCrypto(String.format("[BATCH COMPLETED] Total: %d | Compromised: %d (%.1f%%) | Safe: %d | Errors: %d in %dms",
                        summary.getTotalProcessed(), summary.getTotalCompromised(),
                        summary.getCompromiseRatePercentage(), summary.getTotalSecure(),
                        summary.getTotalErrors(), summary.getTotalDurationMs()));

                Color toastColor = summary.getTotalCompromised() > 0 ? DarkTheme.ACCENT_RED : DarkTheme.ACCENT_GREEN;
                DarkTheme.showToast(EmployeePortalFrame.this,
                        String.format("✔️ Batch Finished: %d processed | %d compromised | %d safe (%dms)",
                                summary.getTotalProcessed(), summary.getTotalCompromised(), summary.getTotalSecure(), summary.getTotalDurationMs()),
                        toastColor);
            }

            @Override
            public void onError(String userFriendlyMessage, Throwable cause) {
                // Guaranteed on EDT
                btnStartBulk.setEnabled(true);
                btnCancelBulk.setEnabled(false);
                logCrypto("[PIPELINE ERROR] " + userFriendlyMessage);

                if (cause instanceof SQLException) {
                    DarkTheme.showToast(EmployeePortalFrame.this,
                            "⚠️ Database Disconnect: Unable to query MySQL vault. Check port 3306.", DarkTheme.ACCENT_RED);
                } else {
                    DarkTheme.showToast(EmployeePortalFrame.this, "⚠️ " + userFriendlyMessage, DarkTheme.ACCENT_AMBER);
                }
            }
        });
    }

    private void cancelAsyncBulkScan() {
        if (currentWorker != null && !currentWorker.isDone()) {
            currentWorker.cancel(true);
            btnStartBulk.setEnabled(true);
            btnCancelBulk.setEnabled(false);
            progressBar.setString("Scan cancelled by user.");
            logCrypto("[ASYNC ENGINE] Bulk verification cancelled by user.");
            DarkTheme.showToast(this, "⏹ Asynchronous scan cancelled.", DarkTheme.ACCENT_AMBER);
        }
    }

    private void attemptNavigateToBlueTeam() {
        // ENFORCE RBAC ACCESS CONTROL: Block standard employees from accessing Blue Team Dashboard
        if (userSession.isStandardEmployee()) {
            logCrypto("[SECURITY AUDIT] Unauthorized access attempt to Blue Team Dashboard blocked for " + userSession.getEmail());
            DarkTheme.showToast(this, "⛔ Access Denied: Role '" + userSession.getRole() + "' cannot access Blue Team SOC.", DarkTheme.ACCENT_RED);
            return;
        }

        // Navigate to Blue Team Dashboard
        verificationEngine.shutdown();
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
                "UnbreachedSecureWord!2026\n" +
                "LeakedPass_Admin#2026!\n" +
                "SecretEmployeePass#2026"
        );
        logCrypto("[UI] Loaded sample batch of 10 credentials.");
    }

    private String maskCredential(String raw) {
        if (raw == null || raw.length() <= 4) return "****";
        return raw.substring(0, 2) + "•".repeat(Math.min(12, raw.length() - 4)) + raw.substring(raw.length() - 2);
    }

    private void logCrypto(String msg) {
        String entry = "[" + dateFormat.format(new Date()) + "] " + msg + "\n";
        if (SwingUtilities.isEventDispatchThread()) {
            if (txtConsole != null) {
                txtConsole.append(entry);
                txtConsole.setCaretPosition(txtConsole.getDocument().getLength());
            }
        } else {
            SwingUtilities.invokeLater(() -> {
                if (txtConsole != null) {
                    txtConsole.append(entry);
                    txtConsole.setCaretPosition(txtConsole.getDocument().getLength());
                }
            });
        }
    }

    // =========================================================================
    // CUSTOM UI WIDGETS: METRIC PILL BADGE & STATUS BADGE RENDERER
    // =========================================================================

    /**
     * Modern pill badge for live counters (Processed, Compromised, Safe)
     */
    public static class MetricPillBadge extends JPanel {
        private String text;
        private final Color accentColor;

        public MetricPillBadge(String initialText, Color accentColor) {
            this.text = initialText;
            this.accentColor = accentColor;
            setOpaque(false);
            setPreferredSize(new Dimension(170, 30));
        }

        public void setText(String text) {
            this.text = text;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

            int w = getWidth();
            int h = getHeight();

            // Background translucent pill
            Color tint = new Color(accentColor.getRed(), accentColor.getGreen(), accentColor.getBlue(), 35);
            g2.setColor(tint);
            g2.fill(new RoundRectangle2D.Float(1, 1, w - 3, h - 3, h - 2, h - 2));

            // Outer border
            g2.setColor(accentColor);
            g2.setStroke(new BasicStroke(1.2f));
            g2.draw(new RoundRectangle2D.Float(1, 1, w - 3, h - 3, h - 2, h - 2));

            // Centered Text
            g2.setColor(accentColor);
            g2.setFont(new Font("Segoe UI", Font.BOLD, 12));
            FontMetrics fm = g2.getFontMetrics();
            int textX = (w - fm.stringWidth(text)) / 2;
            int textY = ((h - fm.getHeight()) / 2) + fm.getAscent();
            g2.drawString(text, textX, textY);

            g2.dispose();
        }
    }

    /**
     * Custom cell renderer for Bulk Verification Status:
     * - COMPROMISED in bold red badge
     * - SECURE in neon green badge
     * - ERROR in warning amber badge
     */
    public static class SecurityStatusBadgeRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
            JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
            label.setHorizontalAlignment(JLabel.CENTER);
            String val = (value != null) ? value.toString() : "";

            if (val.contains("COMPROMISED") || val.contains("BREACHED")) {
                label.setText("⚠️ COMPROMISED");
                label.setForeground(DarkTheme.ACCENT_RED);
                label.setFont(DarkTheme.FONT_BODY_BOLD);
            } else if (val.contains("SECURE") || val.contains("CLEAN")) {
                label.setText("✔️ SECURE");
                label.setForeground(DarkTheme.ACCENT_GREEN);
                label.setFont(DarkTheme.FONT_BODY_BOLD);
            } else if (val.contains("ERROR")) {
                label.setText("❌ ERROR");
                label.setForeground(DarkTheme.ACCENT_AMBER);
                label.setFont(DarkTheme.FONT_BODY_BOLD);
            } else {
                label.setText(val);
                label.setForeground(DarkTheme.FG_PRIMARY);
            }
            label.setBackground(DarkTheme.BG_CARD);
            return label;
        }
    }
}