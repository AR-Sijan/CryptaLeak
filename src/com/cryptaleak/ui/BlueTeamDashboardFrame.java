package com.cryptaleak.ui;

import com.cryptaleak.alert.AlertSubject;
import com.cryptaleak.alert.IncidentResponseObserver;
import com.cryptaleak.alert.SecurityAlert;
import com.cryptaleak.db.DatabaseConnection;
import com.cryptaleak.graph.BlastRadiusResult;
import com.cryptaleak.graph.IdentityGraph;
import com.cryptaleak.graph.Node;
import com.cryptaleak.honeytoken.Honeytoken;
import com.cryptaleak.honeytoken.HoneytokenGenerator;
import com.cryptaleak.honeytoken.ThreatIntelFeedScraper;

import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Project CryptaLeak - Blue Team Cyber Incident Response Dashboard
 * 
 * High-privilege SOC console strictly accessible only to ADMIN, SECOPS_ANALYST, and AUDITOR roles.
 * Standard employees are cryptographically and logically blocked from accessing this interface.
 */
public class BlueTeamDashboardFrame extends JFrame implements IncidentResponseObserver {

    private static final Logger LOGGER = Logger.getLogger(BlueTeamDashboardFrame.class.getName());

    private final UserSession userSession;
    private final DatabaseConnection db;
    private final IdentityGraph identityGraph;
    private final HoneytokenGenerator honeytokenGenerator;
    private final ThreatIntelFeedScraper scraper;
    private final AlertSubject alertSubject;

    // KPI Badges
    private JLabel lblRiskScoreValue;
    private JLabel lblNodeCountValue;
    private JLabel lblCanaryCountValue;
    private JLabel lblAlertCountValue;

    // Topology Matrix Components
    private JComboBox<String> cmbEmployeeSelector;
    private JTextArea txtTopologyConsole;

    // Honeytoken Logs Table
    private JTable tblHoneytokens;
    private DefaultTableModel honeytokenTableModel;

    private final SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss.SSS");

    public BlueTeamDashboardFrame(UserSession userSession) {
        this.userSession = userSession;

        // ENFORCE RBAC ACCESS CONTROL
        if (userSession.isStandardEmployee()) {
            throw new SecurityException("ACCESS DENIED: Role '" + userSession.getRole() + "' is not authorized for Blue Team telemetry.");
        }

        this.db = DatabaseConnection.getInstance();
        this.identityGraph = new IdentityGraph();
        this.honeytokenGenerator = new HoneytokenGenerator();
        this.alertSubject = AlertSubject.getInstance();
        this.scraper = new ThreatIntelFeedScraper(honeytokenGenerator, alertSubject);

        // Register this frame as an Observer
        alertSubject.registerObserver(this);

        initComponents();
        loadInitialData();
    }

    private void initComponents() {
        setTitle("Project CryptaLeak - Blue Team Incident Response & Attack Surface Dashboard");
        setSize(1280, 880);
        setMinimumSize(new Dimension(1100, 750));
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        DarkTheme.applyThemeToFrame(this);

        JPanel mainPanel = new JPanel(new BorderLayout(14, 14));
        mainPanel.setBackground(DarkTheme.BG_DARKEST);
        mainPanel.setBorder(new EmptyBorder(16, 20, 16, 20));

        // 1. TOP SECTION: Header & KPI Metric Badges
        JPanel topSection = new JPanel(new BorderLayout(0, 12));
        topSection.setBackground(DarkTheme.BG_DARKEST);
        topSection.add(buildHeaderPanel(), BorderLayout.NORTH);
        topSection.add(buildKpiMetricsPanel(), BorderLayout.CENTER);
        mainPanel.add(topSection, BorderLayout.NORTH);

        // 2. CENTER SECTION: Split between Topology Matrix & Honeytoken Logs Table
        JSplitPane centerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        centerSplit.setBackground(DarkTheme.BG_DARKEST);
        centerSplit.setDividerLocation(580);
        centerSplit.setDividerSize(8);
        centerSplit.setBorder(null);

        centerSplit.setLeftComponent(buildTopologyMatrixCard());
        centerSplit.setRightComponent(buildHoneytokenLogsCard());

        mainPanel.add(centerSplit, BorderLayout.CENTER);
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

        // Left Branding
        JPanel titlePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        titlePanel.setBackground(DarkTheme.BG_CARD);

        JLabel lblBadge = new JLabel("● LIVE DEFENSE");
        lblBadge.setFont(DarkTheme.FONT_SMALL);
        lblBadge.setForeground(DarkTheme.ACCENT_GREEN);

        JLabel lblTitle = new JLabel("BLUE TEAM THREAT SURFACE OPERATIONS");
        lblTitle.setFont(DarkTheme.FONT_HEADER);
        lblTitle.setForeground(DarkTheme.ACCENT_CYAN);

        JPanel titles = new JPanel(new GridLayout(2, 1, 0, 2));
        titles.setBackground(DarkTheme.BG_CARD);
        titles.add(lblTitle);
        titles.add(lblBadge);

        titlePanel.add(new JLabel("🛡️"));
        titlePanel.add(titles);

        // Right Nav & User
        JPanel navPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        navPanel.setBackground(DarkTheme.BG_CARD);

        JLabel lblUser = new JLabel(userSession.getEmail() + " [" + userSession.getRole() + "]");
        lblUser.setFont(DarkTheme.FONT_BODY_BOLD);
        lblUser.setForeground(DarkTheme.ACCENT_CYAN);

        JButton btnPortal = DarkTheme.createButton("Employee Vault Portal ➔", DarkTheme.BG_INPUT, DarkTheme.FG_PRIMARY);
        btnPortal.addActionListener(e -> {
            alertSubject.removeObserver(this);
            dispose();
            SwingUtilities.invokeLater(() -> new EmployeePortalFrame(userSession).setVisible(true));
        });

        JButton btnLogout = DarkTheme.createButton("Logout", DarkTheme.BG_INPUT, DarkTheme.FG_MUTED);
        btnLogout.addActionListener(e -> {
            alertSubject.removeObserver(this);
            dispose();
            SwingUtilities.invokeLater(() -> new LoginFrame().setVisible(true));
        });

        navPanel.add(lblUser);
        navPanel.add(btnPortal);
        navPanel.add(btnLogout);

        header.add(titlePanel, BorderLayout.WEST);
        header.add(navPanel, BorderLayout.EAST);
        return header;
    }

    private JPanel buildKpiMetricsPanel() {
        JPanel kpiPanel = new JPanel(new GridLayout(1, 4, 12, 0));
        kpiPanel.setBackground(DarkTheme.BG_DARKEST);

        // 1. Systemic Risk Index
        JPanel cardRisk = DarkTheme.createCardPanel();
        cardRisk.setLayout(new BorderLayout(4, 4));
        JLabel lblRiskTitle = new JLabel("SYSTEMIC RISK INDEX");
        lblRiskTitle.setFont(DarkTheme.FONT_SMALL);
        lblRiskTitle.setForeground(DarkTheme.FG_MUTED);
        lblRiskScoreValue = new JLabel("0.00% [NORMAL]");
        lblRiskScoreValue.setFont(new Font("Segoe UI", Font.BOLD, 22));
        lblRiskScoreValue.setForeground(DarkTheme.ACCENT_GREEN);
        cardRisk.add(lblRiskTitle, BorderLayout.NORTH);
        cardRisk.add(lblRiskScoreValue, BorderLayout.CENTER);

        // 2. Identity Graph Nodes
        JPanel cardNodes = DarkTheme.createCardPanel();
        cardNodes.setLayout(new BorderLayout(4, 4));
        JLabel lblNodesTitle = new JLabel("IDENTITY GRAPH TOPOLOGY");
        lblNodesTitle.setFont(DarkTheme.FONT_SMALL);
        lblNodesTitle.setForeground(DarkTheme.FG_MUTED);
        lblNodeCountValue = new JLabel("0 Nodes | 0 Vectors");
        lblNodeCountValue.setFont(new Font("Segoe UI", Font.BOLD, 22));
        lblNodeCountValue.setForeground(DarkTheme.ACCENT_CYAN);
        cardNodes.add(lblNodesTitle, BorderLayout.NORTH);
        cardNodes.add(lblNodeCountValue, BorderLayout.CENTER);

        // 3. Active Canary Tokens
        JPanel cardCanaries = DarkTheme.createCardPanel();
        cardCanaries.setLayout(new BorderLayout(4, 4));
        JLabel lblCanariesTitle = new JLabel("ACTIVE HONEYTOKENS");
        lblCanariesTitle.setFont(DarkTheme.FONT_SMALL);
        lblCanariesTitle.setForeground(DarkTheme.FG_MUTED);
        lblCanaryCountValue = new JLabel("0 Active Decoys");
        lblCanaryCountValue.setFont(new Font("Segoe UI", Font.BOLD, 22));
        lblCanaryCountValue.setForeground(DarkTheme.ACCENT_PURPLE);
        cardCanaries.add(lblCanariesTitle, BorderLayout.NORTH);
        cardCanaries.add(lblCanaryCountValue, BorderLayout.CENTER);

        // 4. Critical Blast Alerts
        JPanel cardAlerts = DarkTheme.createCardPanel();
        cardAlerts.setLayout(new BorderLayout(4, 4));
        JLabel lblAlertsTitle = new JLabel("RECORDED BLAST ALERTS");
        lblAlertsTitle.setFont(DarkTheme.FONT_SMALL);
        lblAlertsTitle.setForeground(DarkTheme.FG_MUTED);
        lblAlertCountValue = new JLabel("0 Alerts");
        lblAlertCountValue.setFont(new Font("Segoe UI", Font.BOLD, 22));
        lblAlertCountValue.setForeground(DarkTheme.ACCENT_AMBER);
        cardAlerts.add(lblAlertsTitle, BorderLayout.NORTH);
        cardAlerts.add(lblAlertCountValue, BorderLayout.CENTER);

        kpiPanel.add(cardRisk);
        kpiPanel.add(cardNodes);
        kpiPanel.add(cardCanaries);
        kpiPanel.add(cardAlerts);
        return kpiPanel;
    }

    private JPanel buildTopologyMatrixCard() {
        JPanel card = DarkTheme.createCardPanel();
        card.setLayout(new BorderLayout(10, 10));

        // Header & Controls
        JPanel topRow = new JPanel(new BorderLayout(0, 8));
        topRow.setOpaque(false);

        JLabel lblTitle = new JLabel("THREAT RELATIONSHIP TOPOLOGY MATRIX");
        lblTitle.setFont(DarkTheme.FONT_BODY_BOLD);
        lblTitle.setForeground(DarkTheme.ACCENT_CYAN);
        topRow.add(lblTitle, BorderLayout.NORTH);

        JPanel controls = new JPanel(new BorderLayout(8, 0));
        controls.setOpaque(false);

        JPanel comboPanel = new JPanel(new BorderLayout(4, 0));
        comboPanel.setOpaque(false);
        JLabel lblOrigin = new JLabel("Origin:");
        lblOrigin.setForeground(DarkTheme.FG_MUTED);
        comboPanel.add(lblOrigin, BorderLayout.WEST);

        cmbEmployeeSelector = new JComboBox<>();
        cmbEmployeeSelector.setBackground(DarkTheme.BG_INPUT);
        cmbEmployeeSelector.setForeground(DarkTheme.FG_PRIMARY);
        cmbEmployeeSelector.setFont(DarkTheme.FONT_BODY);
        comboPanel.add(cmbEmployeeSelector, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        buttonPanel.setOpaque(false);

        JButton btnRunBfs = DarkTheme.createButton("⚡ Run BFS Traversal", DarkTheme.ACCENT_BLUE, DarkTheme.FG_PRIMARY);
        btnRunBfs.addActionListener(e -> executeBfsTraversal());

        JButton btnQuarantine = DarkTheme.createButton("🛑 Quarantine Node", DarkTheme.BG_INPUT, DarkTheme.ACCENT_RED);
        btnQuarantine.addActionListener(e -> quarantineSelectedNode());

        buttonPanel.add(btnRunBfs);
        buttonPanel.add(btnQuarantine);

        controls.add(comboPanel, BorderLayout.CENTER);
        controls.add(buttonPanel, BorderLayout.EAST);

        topRow.add(controls, BorderLayout.CENTER);
        card.add(topRow, BorderLayout.NORTH);

        // Console Output
        txtTopologyConsole = DarkTheme.createConsoleArea();
        JScrollPane scrollPane = new JScrollPane(txtTopologyConsole);
        scrollPane.setBorder(new LineBorder(DarkTheme.BORDER_COLOR));
        card.add(scrollPane, BorderLayout.CENTER);

        return card;
    }

    private JPanel buildHoneytokenLogsCard() {
        JPanel card = DarkTheme.createCardPanel();
        card.setLayout(new BorderLayout(10, 10));

        // Header & Actions
        JPanel topRow = new JPanel(new BorderLayout(0, 8));
        topRow.setOpaque(false);

        JLabel lblTitle = new JLabel("ACTIVE HONEYTOKEN LOGS & CANARIES");
        lblTitle.setFont(DarkTheme.FONT_BODY_BOLD);
        lblTitle.setForeground(DarkTheme.ACCENT_PURPLE);
        topRow.add(lblTitle, BorderLayout.NORTH);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        actions.setOpaque(false);

        JButton btnNewCanary = DarkTheme.createButton("+ Deploy Canary", DarkTheme.BG_INPUT, DarkTheme.ACCENT_PURPLE);
        btnNewCanary.addActionListener(e -> promptDeployCanary());

        JButton btnSimulateScrape = DarkTheme.createButton("📡 Simulate Threat Scrape", DarkTheme.ACCENT_BLUE, DarkTheme.FG_PRIMARY);
        btnSimulateScrape.addActionListener(e -> triggerSimulatedScrape());

        JButton btnRefresh = DarkTheme.createButton("🔄 Refresh", DarkTheme.BG_INPUT, DarkTheme.FG_MUTED);
        btnRefresh.addActionListener(e -> loadInitialData());

        actions.add(btnNewCanary);
        actions.add(btnSimulateScrape);
        actions.add(btnRefresh);

        topRow.add(actions, BorderLayout.CENTER);
        card.add(topRow, BorderLayout.NORTH);

        // Table
        String[] columns = {"Canary ID", "Token Type", "Planted Location", "Hash Prefix", "Status"};
        honeytokenTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };

        tblHoneytokens = new JTable(honeytokenTableModel);
        DarkTheme.styleTable(tblHoneytokens);

        tblHoneytokens.getColumnModel().getColumn(4).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
                setHorizontalAlignment(JLabel.CENTER);
                String val = (value != null) ? value.toString() : "";
                if (val.contains("BREACHED") || val.contains("COMPROMISED") || val.contains("TRIGGERED")) {
                    c.setForeground(DarkTheme.ACCENT_RED);
                    setFont(DarkTheme.FONT_BODY_BOLD);
                } else {
                    c.setForeground(DarkTheme.ACCENT_GREEN);
                }
                c.setBackground(DarkTheme.BG_CARD);
                return c;
            }
        });

        JScrollPane scrollTable = new JScrollPane(tblHoneytokens);
        scrollTable.setBorder(new LineBorder(DarkTheme.BORDER_COLOR));
        scrollTable.getViewport().setBackground(DarkTheme.BG_CARD);
        card.add(scrollTable, BorderLayout.CENTER);

        return card;
    }

    // =========================================================================
    // DATA LOADING & REFRESH
    // =========================================================================

    private void loadInitialData() {
        try {
            // 1. Load Topology Graph from MySQL
            identityGraph.loadFromDatabase(db);
            lblNodeCountValue.setText(String.format("%d Nodes | %d Vectors",
                    identityGraph.getNodeCount(), identityGraph.getEdgeCount()));

            // Populate Employee selector
            cmbEmployeeSelector.removeAllItems();
            for (Node node : identityGraph.getAllNodes()) {
                if ("DOMAIN_USER".equalsIgnoreCase(node.getSpecificType()) || node.getNodeId().startsWith("EMP")) {
                    cmbEmployeeSelector.addItem(node.getNodeId() + " - " + node.getName());
                }
            }

            // 2. Deploy sample canaries if none in memory
            if (honeytokenGenerator.getActiveCanaries().isEmpty()) {
                honeytokenGenerator.generateAndRecordHoneytoken(Honeytoken.TokenType.AWS_ACCESS_KEY, "deploy/aws-credentials.staging");
                honeytokenGenerator.generateAndRecordHoneytoken(Honeytoken.TokenType.DATABASE_PASSWORD, "backups/prod-db-2025.sql");
                honeytokenGenerator.generateAndRecordHoneytoken(Honeytoken.TokenType.API_TOKEN, "src/secrets/auth_token.env");
            }

            refreshHoneytokensTable();

            // 3. Count Recorded Blast Alerts
            db.executeQuery("SELECT COUNT(*) FROM blast_alerts", rs -> {
                if (rs.next()) {
                    int count = rs.getInt(1);
                    lblAlertCountValue.setText(count + " Alerts");
                    if (count > 0) lblAlertCountValue.setForeground(DarkTheme.ACCENT_RED);
                }
                return null;
            });

            logTopology("[TOPOLOGY] Identity graph refreshed from MySQL. Ready for threat matrix analysis.");

        } catch (SQLException ex) {
            logTopology("[DATABASE ERROR] Failed to load telemetry: " + ex.getMessage());
            LOGGER.log(Level.SEVERE, "Database load error", ex);
        }
    }

    private void refreshHoneytokensTable() {
        honeytokenTableModel.setRowCount(0);
        List<Honeytoken> canaries = honeytokenGenerator.getActiveCanaries();
        lblCanaryCountValue.setText(canaries.size() + " Active Decoys");

        for (Honeytoken canary : canaries) {
            String status = canary.isTriggered() ? "⚠️ TRIGGERED / LEAKED" : "✔️ ARMED & MONITORING";
            honeytokenTableModel.addRow(new Object[]{
                    canary.getCanaryId(),
                    canary.getTokenType(),
                    canary.getPlantedLocation(),
                    canary.getHashPrefix(),
                    status
            });
        }
    }

    // =========================================================================
    // BLUE TEAM OPERATIONS
    // =========================================================================

    private void executeBfsTraversal() {
        String selected = (String) cmbEmployeeSelector.getSelectedItem();
        if (selected == null) return;
        String nodeId = selected.split(" - ")[0].trim();

        try {
            logTopology("\n[BFS TRAVERSAL] Executing attack propagation calculation from origin: " + nodeId);
            BlastRadiusResult result = identityGraph.calculateBlastRadius(nodeId);

            // Update Systemic Risk Index KPI Badge
            double score = result.getSystemicRiskScore();
            lblRiskScoreValue.setText(String.format("%.2f%% [%s]", score, result.getRiskSeverity()));

            if (score >= 80.0) {
                lblRiskScoreValue.setForeground(DarkTheme.ACCENT_RED);
            } else if (score >= 50.0) {
                lblRiskScoreValue.setForeground(DarkTheme.ACCENT_AMBER);
            } else {
                lblRiskScoreValue.setForeground(DarkTheme.ACCENT_GREEN);
            }

            // Output full report to matrix console
            logTopology(result.generateSecurityReport());

            // Check if alert threshold exceeded (triggers Observer pattern)
            scraper.evaluateBlastRadiusThreshold(result);

        } catch (Exception ex) {
            logTopology("[BFS ERROR] Failed to execute traversal: " + ex.getMessage());
        }
    }

    private void quarantineSelectedNode() {
        String selected = (String) cmbEmployeeSelector.getSelectedItem();
        if (selected == null) return;
        String nodeId = selected.split(" - ")[0].trim();

        Node node = identityGraph.getNode(nodeId);
        if (node != null) {
            boolean newState = !node.isQuarantined();
            node.setQuarantined(newState);

            logTopology(String.format("[INCIDENT RESPONSE] Node %s quarantine state toggled to: %b", nodeId, newState));
            try {
                db.executeUpdate("UPDATE identity_nodes SET is_quarantined = ? WHERE node_id = ?", newState, nodeId);
            } catch (SQLException ignored) {}

            executeBfsTraversal(); // Re-evaluate blast radius
        }
    }

    private void promptDeployCanary() {
        Honeytoken.TokenType[] types = Honeytoken.TokenType.values();
        Honeytoken.TokenType selectedType = (Honeytoken.TokenType) JOptionPane.showInputDialog(
                this, "Select Decoy Honeytoken Type to Generate:",
                "Deploy Canary", JOptionPane.QUESTION_MESSAGE, null, types, types[0]
        );

        if (selectedType == null) return;

        String location = JOptionPane.showInputDialog(
                this, "Enter Strategic Planting Location (e.g. '.env.dev', 's3://internal-dump'):",
                "infra/ci-cd-keys.yaml"
        );

        if (location == null || location.trim().isEmpty()) return;

        try {
            Honeytoken canary = honeytokenGenerator.generateAndRecordHoneytoken(selectedType, location.trim());
            refreshHoneytokensTable();
            logTopology(String.format("[CANARY DEPLOYED] Created %s [%s] at '%s'. Hash Prefix: %s",
                    canary.getCanaryId(), canary.getTokenType(), canary.getPlantedLocation(), canary.getHashPrefix()));
            JOptionPane.showMessageDialog(this, "Canary Honeytoken generated and recorded in MySQL successfully!", "Canary Deployed", JOptionPane.INFORMATION_MESSAGE);
        } catch (SQLException ex) {
            JOptionPane.showMessageDialog(this, "Failed to record canary in database: " + ex.getMessage(), "Database Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void triggerSimulatedScrape() {
        List<Honeytoken> canaries = honeytokenGenerator.getActiveCanaries();
        if (canaries.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No active canaries deployed. Deploy one first!", "Empty Canaries", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Simulate dark web threat feed containing the first active canary
        Honeytoken targetCanary = canaries.get(0);
        List<String> leakedSecrets = Arrays.asList(
                "corp_unrelated_password_2026",
                targetCanary.getSecretValue(), // The canary leak!
                "admin_shadow_credential#99"
        );

        ThreatIntelFeedScraper.MockBreachDump dump = new ThreatIntelFeedScraper.MockBreachDump(
                "TorMarket_BreachForums_DarkWeb_Dump_#9901",
                leakedSecrets
        );

        logTopology(String.format("\n[SCRAPER TRIGGER] Simulating dark web ingest from '%s'...", dump.feedSource()));
        List<SecurityAlert> alerts = scraper.scanThreatIntelDump(dump);
        refreshHoneytokensTable();

        // Update recorded alerts badge
        try {
            db.executeQuery("SELECT COUNT(*) FROM blast_alerts", rs -> {
                if (rs.next()) lblAlertCountValue.setText(rs.getInt(1) + " Alerts");
                return null;
            });
        } catch (SQLException ignored) {}
    }

    /**
     * Observer Pattern Implementation: Triggered when AlertSubject broadcasts an alert.
     */
    @Override
    public void onSecurityAlert(SecurityAlert alert) {
        SwingUtilities.invokeLater(() -> {
            logTopology(String.format("\n>>> [OBSERVER DISPATCH: %s] Alert ID: %s | Source: %s | Risk: %.2f%%",
                    alert.getSeverity(), alert.getAlertId(), alert.getCompromisedSource(), alert.getSystemicRiskScore()));

            // Highlight Risk score if critical
            if (alert.getSystemicRiskScore() >= 80.0) {
                lblRiskScoreValue.setText(String.format("%.2f%% [CRITICAL]", alert.getSystemicRiskScore()));
                lblRiskScoreValue.setForeground(DarkTheme.ACCENT_RED);
            }

            refreshHoneytokensTable();
        });
    }

    private void logTopology(String msg) {
        String entry = "[" + dateFormat.format(new Date()) + "] " + msg + "\n";
        txtTopologyConsole.append(entry);
        txtTopologyConsole.setCaretPosition(txtTopologyConsole.getDocument().getLength());
    }
}