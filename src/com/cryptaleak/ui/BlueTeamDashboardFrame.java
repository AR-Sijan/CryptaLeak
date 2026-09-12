package com.cryptaleak.ui;

import com.cryptaleak.alert.AlertSubject;
import com.cryptaleak.alert.IncidentResponseObserver;
import com.cryptaleak.alert.SecurityAlert;
import com.cryptaleak.db.DatabaseConnection;
import com.cryptaleak.graph.AssetNode;
import com.cryptaleak.graph.BlastRadiusResult;
import com.cryptaleak.graph.Edge;
import com.cryptaleak.graph.EmployeeNode;
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
import java.awt.geom.RoundRectangle2D;
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
 * Interactive, responsive, production-grade SOC console strictly accessible only to ADMIN, SECOPS_ANALYST, and AUDITOR roles.
 * Features:
 * - Card-based KPI widgets with circular/pill risk-colored badges
 * - Interactive Threat Topology Explorer with asynchronous BFS attack radius computation
 * - Clean, formatted ASCII/tree lateral hierarchy path visualization
 * - Dynamic one-click Quarantine Node button with instant mitigated score recalculation
 * - Honeytoken & Live Alert Center with status tags (ACTIVE, TRIGGERED, CONTAINED)
 * - Multi-threaded async triggers for Canary Deployment and Dark Web Feed Simulation on the EDT
 */
public class BlueTeamDashboardFrame extends JFrame implements IncidentResponseObserver {

    private static final Logger LOGGER = Logger.getLogger(BlueTeamDashboardFrame.class.getName());

    private final UserSession userSession;
    private final DatabaseConnection db;
    private final IdentityGraph identityGraph;
    private final HoneytokenGenerator honeytokenGenerator;
    private final ThreatIntelFeedScraper scraper;
    private final AlertSubject alertSubject;

    // KPI Badges & Widgets
    private RiskPillBadge riskPillBadge;
    private JLabel lblNodeCountValue;
    private JLabel lblCanaryCountValue;
    private JLabel lblAlertCountValue;

    // Topology Matrix Explorer Components
    private JComboBox<String> cmbEmployeeSelector;
    private JButton btnRunBfs;
    private JButton btnQuarantine;
    private JTextArea txtTopologyConsole;

    // Honeytoken & Alert Center Components
    private JTable tblHoneytokens;
    private DefaultTableModel honeytokenTableModel;
    private JButton btnNewCanary;
    private JButton btnSimulateScrape;
    private JButton btnContainCanaries;
    private JButton btnRefresh;

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
        loadInitialDataAsync();
    }

    private void initComponents() {
        setTitle("Project CryptaLeak - Blue Team Incident Response & Attack Surface Operations");
        setSize(1320, 900);
        setMinimumSize(new Dimension(1120, 780));
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        DarkTheme.applyThemeToFrame(this);

        JPanel mainPanel = new JPanel(new BorderLayout(14, 14));
        mainPanel.setBackground(DarkTheme.BG_DARKEST);
        mainPanel.setBorder(new EmptyBorder(16, 20, 16, 20));

        // 1. TOP SECTION: Header & Modern KPI Metric Cards
        JPanel topSection = new JPanel(new BorderLayout(0, 12));
        topSection.setBackground(DarkTheme.BG_DARKEST);
        topSection.add(buildHeaderPanel(), BorderLayout.NORTH);
        topSection.add(buildKpiMetricsPanel(), BorderLayout.CENTER);
        mainPanel.add(topSection, BorderLayout.NORTH);

        // 2. CENTER SECTION: Split between Topology Explorer & Honeytoken Alert Center
        JSplitPane centerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        centerSplit.setBackground(DarkTheme.BG_DARKEST);
        centerSplit.setDividerLocation(620);
        centerSplit.setDividerSize(8);
        centerSplit.setBorder(null);

        centerSplit.setLeftComponent(buildTopologyMatrixCard());
        centerSplit.setRightComponent(buildHoneytokenLogsCard());

        mainPanel.add(centerSplit, BorderLayout.CENTER);
        setContentPane(mainPanel);
    }

    // =========================================================================
    // SECTION BUILDERS: HEADER & KPI CARDS
    // =========================================================================

    private JPanel buildHeaderPanel() {
        JPanel header = new JPanel(new BorderLayout(10, 10));
        header.setBackground(DarkTheme.BG_CARD);
        header.setBorder(new CompoundBorder(
                new LineBorder(DarkTheme.BORDER_COLOR, 1, true),
                new EmptyBorder(12, 16, 12, 16)
        ));

        // Left Branding
        JPanel titlePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        titlePanel.setBackground(DarkTheme.BG_CARD);

        JLabel lblShield = new JLabel("🛡️");
        lblShield.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 28));

        JPanel titles = new JPanel();
        titles.setLayout(new BoxLayout(titles, BoxLayout.Y_AXIS));
        titles.setBackground(DarkTheme.BG_CARD);

        JLabel lblTitle = new JLabel("BLUE TEAM THREAT SURFACE OPERATIONS");
        lblTitle.setFont(DarkTheme.FONT_HEADER);
        lblTitle.setForeground(DarkTheme.ACCENT_CYAN);

        JLabel lblBadge = new JLabel("● LIVE DEFENSE  |  Zero-Trust Graph Topology & Deception Console");
        lblBadge.setFont(DarkTheme.FONT_SMALL);
        lblBadge.setForeground(DarkTheme.ACCENT_GREEN);

        titles.add(lblTitle);
        titles.add(Box.createVerticalStrut(2));
        titles.add(lblBadge);

        titlePanel.add(lblShield);
        titlePanel.add(titles);

        // Right Nav & User Clearance
        JPanel navPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        navPanel.setBackground(DarkTheme.BG_CARD);

        JLabel lblUser = new JLabel(userSession.getEmail() + " [" + userSession.getRole() + "]");
        lblUser.setFont(DarkTheme.FONT_BODY_BOLD);
        lblUser.setForeground(DarkTheme.ACCENT_CYAN);

        JButton btnPortal = DarkTheme.createButton("Employee Vault Portal ➔", DarkTheme.BG_INPUT, DarkTheme.FG_PRIMARY);
        btnPortal.setToolTipText("Switch view to Employee Credential Vault");
        btnPortal.addActionListener(e -> {
            alertSubject.removeObserver(this);
            dispose();
            SwingUtilities.invokeLater(() -> new EmployeePortalFrame(userSession).setVisible(true));
        });

        JButton btnLogout = DarkTheme.createButton("Logout", DarkTheme.BG_INPUT, DarkTheme.FG_MUTED);
        btnLogout.setToolTipText("Terminate active session");
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
        JPanel kpiPanel = new JPanel(new GridLayout(1, 4, 14, 0));
        kpiPanel.setBackground(DarkTheme.BG_DARKEST);

        // 1. Systemic Risk Index Widget (with Circular / Pill Risk Badge)
        JPanel cardRisk = DarkTheme.createCardPanel();
        cardRisk.setLayout(new BorderLayout(6, 6));
        JLabel lblRiskTitle = new JLabel("SYSTEMIC RISK INDEX");
        lblRiskTitle.setFont(DarkTheme.FONT_SMALL);
        lblRiskTitle.setForeground(DarkTheme.FG_MUTED);

        riskPillBadge = new RiskPillBadge();
        riskPillBadge.updateScore(0.00, "NORMAL");

        JLabel lblRiskSub = new JLabel("Highest breach propagation radius");
        lblRiskSub.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        lblRiskSub.setForeground(DarkTheme.FG_SUBTLE);

        cardRisk.add(lblRiskTitle, BorderLayout.NORTH);
        cardRisk.add(riskPillBadge, BorderLayout.CENTER);
        cardRisk.add(lblRiskSub, BorderLayout.SOUTH);

        // 2. Identity Graph Topology Widget
        JPanel cardNodes = DarkTheme.createCardPanel();
        cardNodes.setLayout(new BorderLayout(6, 6));
        JLabel lblNodesTitle = new JLabel("IDENTITY GRAPH TOPOLOGY");
        lblNodesTitle.setFont(DarkTheme.FONT_SMALL);
        lblNodesTitle.setForeground(DarkTheme.FG_MUTED);

        lblNodeCountValue = new JLabel("0 Nodes | 0 Vectors");
        lblNodeCountValue.setFont(new Font("Segoe UI", Font.BOLD, 20));
        lblNodeCountValue.setForeground(DarkTheme.ACCENT_CYAN);

        JLabel lblNodesSub = new JLabel("AD corporate nodes & cloud assets");
        lblNodesSub.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        lblNodesSub.setForeground(DarkTheme.FG_SUBTLE);

        cardNodes.add(lblNodesTitle, BorderLayout.NORTH);
        cardNodes.add(lblNodeCountValue, BorderLayout.CENTER);
        cardNodes.add(lblNodesSub, BorderLayout.SOUTH);

        // 3. Active Honeytokens Widget
        JPanel cardCanaries = DarkTheme.createCardPanel();
        cardCanaries.setLayout(new BorderLayout(6, 6));
        JLabel lblCanariesTitle = new JLabel("ACTIVE HONEYTOKENS");
        lblCanariesTitle.setFont(DarkTheme.FONT_SMALL);
        lblCanariesTitle.setForeground(DarkTheme.FG_MUTED);

        lblCanaryCountValue = new JLabel("0 Active Decoys");
        lblCanaryCountValue.setFont(new Font("Segoe UI", Font.BOLD, 20));
        lblCanaryCountValue.setForeground(DarkTheme.ACCENT_PURPLE);

        JLabel lblCanariesSub = new JLabel("Strategic deception traps armed");
        lblCanariesSub.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        lblCanariesSub.setForeground(DarkTheme.FG_SUBTLE);

        cardCanaries.add(lblCanariesTitle, BorderLayout.NORTH);
        cardCanaries.add(lblCanaryCountValue, BorderLayout.CENTER);
        cardCanaries.add(lblCanariesSub, BorderLayout.SOUTH);

        // 4. Critical Blast Alerts Widget
        JPanel cardAlerts = DarkTheme.createCardPanel();
        cardAlerts.setLayout(new BorderLayout(6, 6));
        JLabel lblAlertsTitle = new JLabel("RECORDED BLAST ALERTS");
        lblAlertsTitle.setFont(DarkTheme.FONT_SMALL);
        lblAlertsTitle.setForeground(DarkTheme.FG_MUTED);

        lblAlertCountValue = new JLabel("0 Alerts");
        lblAlertCountValue.setFont(new Font("Segoe UI", Font.BOLD, 20));
        lblAlertCountValue.setForeground(DarkTheme.ACCENT_AMBER);

        JLabel lblAlertsSub = new JLabel("Triggered intrusion events");
        lblAlertsSub.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        lblAlertsSub.setForeground(DarkTheme.FG_SUBTLE);

        cardAlerts.add(lblAlertsTitle, BorderLayout.NORTH);
        cardAlerts.add(lblAlertCountValue, BorderLayout.CENTER);
        cardAlerts.add(lblAlertsSub, BorderLayout.SOUTH);

        kpiPanel.add(cardRisk);
        kpiPanel.add(cardNodes);
        kpiPanel.add(cardCanaries);
        kpiPanel.add(cardAlerts);
        return kpiPanel;
    }

    // =========================================================================
    // INTERACTIVE THREAT TOPOLOGY EXPLORER (LEFT CARD)
    // =========================================================================

    private JPanel buildTopologyMatrixCard() {
        JPanel card = DarkTheme.createCardPanel();
        card.setLayout(new BorderLayout(10, 10));

        // Header Panel: Title, Description, Origin Combo, and Action Buttons in clean stack
        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));
        headerPanel.setOpaque(false);

        JLabel lblTitle = new JLabel("INTERACTIVE THREAT TOPOLOGY EXPLORER");
        lblTitle.setFont(DarkTheme.FONT_BODY_BOLD);
        lblTitle.setForeground(DarkTheme.ACCENT_CYAN);
        lblTitle.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel lblSub = new JLabel("Select an employee breach root to compute lateral movement blast radius via BFS.");
        lblSub.setFont(DarkTheme.FONT_SMALL);
        lblSub.setForeground(DarkTheme.FG_MUTED);
        lblSub.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Origin Node Selector
        JPanel originRow = new JPanel(new BorderLayout(8, 0));
        originRow.setOpaque(false);
        originRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        originRow.setMaximumSize(new Dimension(Short.MAX_VALUE, 32));

        JLabel lblOrigin = new JLabel("Breach Root Node:");
        lblOrigin.setFont(DarkTheme.FONT_BODY_BOLD);
        lblOrigin.setForeground(DarkTheme.FG_PRIMARY);

        cmbEmployeeSelector = new JComboBox<>();
        cmbEmployeeSelector.setBackground(DarkTheme.BG_INPUT);
        cmbEmployeeSelector.setForeground(DarkTheme.FG_PRIMARY);
        cmbEmployeeSelector.setFont(DarkTheme.FONT_BODY);
        cmbEmployeeSelector.setToolTipText("Select employee account assumed to be compromised");
        cmbEmployeeSelector.addActionListener(e -> updateQuarantineButtonState());

        originRow.add(lblOrigin, BorderLayout.WEST);
        originRow.add(cmbEmployeeSelector, BorderLayout.CENTER);

        // Action Buttons Row
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        buttonRow.setOpaque(false);
        buttonRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        btnRunBfs = DarkTheme.createButton("⚡ Compute Blast Radius", DarkTheme.ACCENT_BLUE, DarkTheme.FG_PRIMARY);
        btnRunBfs.setToolTipText("Run multi-hop BFS traversal asynchronously and display full attack tree");
        btnRunBfs.addActionListener(e -> computeBlastRadiusAsync());

        btnQuarantine = DarkTheme.createButton("🛑 Quarantine Node", DarkTheme.BG_INPUT, DarkTheme.ACCENT_RED);
        btnQuarantine.setToolTipText("Sever all lateral movement vectors and instantly recalculate mitigated risk");
        btnQuarantine.addActionListener(e -> quarantineSelectedNodeAsync());

        JButton btnClearConsole = DarkTheme.createButton("🗑️ Clear", DarkTheme.BG_INPUT, DarkTheme.FG_MUTED);
        btnClearConsole.setToolTipText("Clear console display");
        btnClearConsole.addActionListener(e -> txtTopologyConsole.setText(""));

        buttonRow.add(btnRunBfs);
        buttonRow.add(btnQuarantine);
        buttonRow.add(btnClearConsole);

        headerPanel.add(lblTitle);
        headerPanel.add(Box.createVerticalStrut(2));
        headerPanel.add(lblSub);
        headerPanel.add(Box.createVerticalStrut(10));
        headerPanel.add(originRow);
        headerPanel.add(Box.createVerticalStrut(8));
        headerPanel.add(buttonRow);
        headerPanel.add(Box.createVerticalStrut(6));

        card.add(headerPanel, BorderLayout.NORTH);

        // Monospace Console Output for Clean ASCII Attack Tree
        txtTopologyConsole = DarkTheme.createConsoleArea();
        JScrollPane scrollPane = new JScrollPane(txtTopologyConsole);
        scrollPane.setBorder(new LineBorder(DarkTheme.BORDER_COLOR));
        card.add(scrollPane, BorderLayout.CENTER);

        return card;
    }

    // =========================================================================
    // HONEYTOKEN & LIVE ALERT CENTER (RIGHT CARD)
    // =========================================================================

    private JPanel buildHoneytokenLogsCard() {
        JPanel card = DarkTheme.createCardPanel();
        card.setLayout(new BorderLayout(10, 10));

        // Header Panel: Title, Description, and Action Buttons
        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));
        headerPanel.setOpaque(false);

        JLabel lblTitle = new JLabel("HONEYTOKEN & LIVE ALERT CENTER");
        lblTitle.setFont(DarkTheme.FONT_BODY_BOLD);
        lblTitle.setForeground(DarkTheme.ACCENT_PURPLE);
        lblTitle.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel lblSub = new JLabel("Active decoy credentials planted in codebases & live dark web breach scraper feed.");
        lblSub.setFont(DarkTheme.FONT_SMALL);
        lblSub.setForeground(DarkTheme.FG_MUTED);
        lblSub.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Action Buttons Row
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        buttonRow.setOpaque(false);
        buttonRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        btnNewCanary = DarkTheme.createButton("+ Deploy Decoy Canary", DarkTheme.BG_INPUT, DarkTheme.ACCENT_PURPLE);
        btnNewCanary.setToolTipText("Generate and strategically record a new decoy canary in MySQL");
        btnNewCanary.addActionListener(e -> deployCanaryAsync());

        btnSimulateScrape = DarkTheme.createButton("📡 Simulate Dark Web Leak Feed", DarkTheme.ACCENT_BLUE, DarkTheme.FG_PRIMARY);
        btnSimulateScrape.setToolTipText("Ingest simulated leak dump containing a decoy token without freezing UI");
        btnSimulateScrape.addActionListener(e -> simulateDarkWebLeakFeedAsync());

        btnContainCanaries = DarkTheme.createButton("🛡️ Contain Leaks", DarkTheme.BG_INPUT, DarkTheme.ACCENT_CYAN);
        btnContainCanaries.setToolTipText("Mark triggered honeytokens as revoked and contained");
        btnContainCanaries.addActionListener(e -> containTriggeredTokens());

        btnRefresh = DarkTheme.createButton("🔄 Refresh", DarkTheme.BG_INPUT, DarkTheme.FG_MUTED);
        btnRefresh.setToolTipText("Reload graph topology and canary states from MySQL");
        btnRefresh.addActionListener(e -> loadInitialDataAsync());

        buttonRow.add(btnNewCanary);
        buttonRow.add(btnSimulateScrape);
        buttonRow.add(btnContainCanaries);
        buttonRow.add(btnRefresh);

        headerPanel.add(lblTitle);
        headerPanel.add(Box.createVerticalStrut(2));
        headerPanel.add(lblSub);
        headerPanel.add(Box.createVerticalStrut(10));
        headerPanel.add(buttonRow);
        headerPanel.add(Box.createVerticalStrut(6));

        card.add(headerPanel, BorderLayout.NORTH);

        // Table with Status Tags (ACTIVE, TRIGGERED, CONTAINED)
        String[] columns = {"Canary ID", "Token Type", "Planted Strategic Location", "Hash Prefix", "Status Tag"};
        honeytokenTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };

        tblHoneytokens = new JTable(honeytokenTableModel);
        DarkTheme.styleTable(tblHoneytokens);

        // Custom Cell Renderer to render status pill tags
        tblHoneytokens.getColumnModel().getColumn(4).setCellRenderer(new StatusTagRenderer());

        JScrollPane scrollTable = new JScrollPane(tblHoneytokens);
        scrollTable.setBorder(new LineBorder(DarkTheme.BORDER_COLOR));
        scrollTable.getViewport().setBackground(DarkTheme.BG_CARD);
        card.add(scrollTable, BorderLayout.CENTER);

        return card;
    }

    // =========================================================================
    // ASYNC TELEMETRY & DATA LOADING
    // =========================================================================

    private void loadInitialDataAsync() {
        btnRefresh.setEnabled(false);
        logTopology("[INITIALIZATION] Connecting to MySQL and loading identity graph topology...");

        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            private int nodeCount = 0;
            private int edgeCount = 0;
            private int alertCount = 0;
            private final List<String> employeeItems = new ArrayList<>();

            @Override
            protected Void doInBackground() throws Exception {
                // 1. Load Topology Graph from MySQL
                identityGraph.loadFromDatabase(db);
                nodeCount = identityGraph.getNodeCount();
                edgeCount = identityGraph.getEdgeCount();

                for (Node node : identityGraph.getAllNodes()) {
                    if ("DOMAIN_USER".equalsIgnoreCase(node.getSpecificType()) || node.getNodeId().startsWith("EMP")) {
                        String quarantinedTag = node.isQuarantined() ? " [QUARANTINED]" : "";
                        employeeItems.add(node.getNodeId() + " - " + node.getName() + quarantinedTag);
                    }
                }

                // 2. Deploy sample canaries if none in memory
                if (honeytokenGenerator.getActiveCanaries().isEmpty()) {
                    honeytokenGenerator.generateAndRecordHoneytoken(Honeytoken.TokenType.AWS_ACCESS_KEY, "deploy/aws-credentials.staging");
                    honeytokenGenerator.generateAndRecordHoneytoken(Honeytoken.TokenType.DATABASE_PASSWORD, "backups/prod-db-2025.sql");
                    honeytokenGenerator.generateAndRecordHoneytoken(Honeytoken.TokenType.API_TOKEN, "src/secrets/auth_token.env");
                }

                // 3. Count Recorded Blast Alerts
                db.executeQuery("SELECT COUNT(*) FROM blast_alerts", rs -> {
                    if (rs.next()) alertCount = rs.getInt(1);
                    return null;
                });

                return null;
            }

            @Override
            protected void done() {
                btnRefresh.setEnabled(true);
                try {
                    get();
                    lblNodeCountValue.setText(String.format("%d Nodes | %d Vectors", nodeCount, edgeCount));
                    lblAlertCountValue.setText(alertCount + " Alerts");
                    if (alertCount > 0) lblAlertCountValue.setForeground(DarkTheme.ACCENT_RED);

                    cmbEmployeeSelector.removeAllItems();
                    for (String item : employeeItems) {
                        cmbEmployeeSelector.addItem(item);
                    }

                    refreshHoneytokensTable();
                    updateQuarantineButtonState();
                    logTopology(String.format("[TOPOLOGY READY] Loaded %d nodes and %d lateral edges. Ready for analysis.", nodeCount, edgeCount));

                } catch (Exception ex) {
                    logTopology("[DATABASE ERROR] Failed to load telemetry: " + ex.getMessage());
                    DarkTheme.showToast(BlueTeamDashboardFrame.this, "❌ Database error: " + ex.getMessage(), DarkTheme.ACCENT_RED);
                }
            }
        };

        worker.execute();
    }

    private void refreshHoneytokensTable() {
        honeytokenTableModel.setRowCount(0);
        List<Honeytoken> canaries = honeytokenGenerator.getActiveCanaries();
        lblCanaryCountValue.setText(canaries.size() + " Active Decoys");

        for (Honeytoken canary : canaries) {
            honeytokenTableModel.addRow(new Object[]{
                    canary.getCanaryId(),
                    canary.getTokenType().name(),
                    canary.getPlantedLocation(),
                    canary.getHashPrefix(),
                    canary.getStatus().name()
            });
        }
    }

    private void updateQuarantineButtonState() {
        String selected = (String) cmbEmployeeSelector.getSelectedItem();
        if (selected == null) return;
        String nodeId = selected.split(" - ")[0].trim();
        Node node = identityGraph.getNode(nodeId);

        if (node != null && node.isQuarantined()) {
            btnQuarantine.setText("🔓 Unquarantine Node");
            btnQuarantine.setForeground(DarkTheme.ACCENT_GREEN);
        } else {
            btnQuarantine.setText("🛑 Quarantine Node");
            btnQuarantine.setForeground(DarkTheme.ACCENT_RED);
        }
    }

    // =========================================================================
    // INTERACTIVE THREAT OPERATIONS: ASYNC BFS & QUARANTINE
    // =========================================================================

    private void computeBlastRadiusAsync() {
        String selected = (String) cmbEmployeeSelector.getSelectedItem();
        if (selected == null) {
            DarkTheme.showToast(this, "⚠️ Please select a breach root node.", DarkTheme.ACCENT_AMBER);
            return;
        }
        String nodeId = selected.split(" - ")[0].trim();

        btnRunBfs.setEnabled(false);
        btnRunBfs.setText("⚡ Computing BFS...");
        logTopology("\n>>> [ASYNC BFS] Traversing identity graph starting from root: " + nodeId);

        SwingWorker<BlastRadiusResult, Void> worker = new SwingWorker<>() {
            @Override
            protected BlastRadiusResult doInBackground() throws Exception {
                return identityGraph.calculateBlastRadius(nodeId);
            }

            @Override
            protected void done() {
                btnRunBfs.setEnabled(true);
                btnRunBfs.setText("⚡ Compute Blast Radius");

                try {
                    BlastRadiusResult result = get();
                    double score = result.getSystemicRiskScore();
                    String severity = result.getRiskSeverity();

                    // Update Systemic Risk Index KPI Pill Badge
                    riskPillBadge.updateScore(score, severity);

                    // Render formatted ASCII attack tree hierarchy
                    String asciiTree = buildAsciiAttackTree(result);
                    logTopology(asciiTree);

                    // Trigger Observer evaluation if score exceeds threshold
                    scraper.evaluateBlastRadiusThreshold(result);

                    DarkTheme.showToast(BlueTeamDashboardFrame.this,
                            String.format("✔️ Blast Radius for %s: %.2f%% [%s]", nodeId, score, severity),
                            score >= 80 ? DarkTheme.ACCENT_RED : (score >= 50 ? DarkTheme.ACCENT_AMBER : DarkTheme.ACCENT_GREEN));

                } catch (Exception ex) {
                    logTopology("[BFS ERROR] Traversal failed: " + ex.getMessage());
                    DarkTheme.showToast(BlueTeamDashboardFrame.this, "❌ Traversal error: " + ex.getMessage(), DarkTheme.ACCENT_RED);
                }
            }
        };

        worker.execute();
    }

    private void quarantineSelectedNodeAsync() {
        String selected = (String) cmbEmployeeSelector.getSelectedItem();
        if (selected == null) return;
        String nodeId = selected.split(" - ")[0].trim();
        Node node = identityGraph.getNode(nodeId);

        if (node == null) return;
        boolean newState = !node.isQuarantined();

        btnQuarantine.setEnabled(false);

        SwingWorker<BlastRadiusResult, Void> worker = new SwingWorker<>() {
            @Override
            protected BlastRadiusResult doInBackground() throws Exception {
                node.setQuarantined(newState);
                db.executeUpdate("UPDATE identity_nodes SET is_quarantined = ? WHERE node_id = ?", newState, nodeId);
                // Instantly recalculate mitigated risk score
                return identityGraph.calculateBlastRadius(nodeId);
            }

            @Override
            protected void done() {
                btnQuarantine.setEnabled(true);
                updateQuarantineButtonState();

                try {
                    BlastRadiusResult mitigated = get();
                    riskPillBadge.updateScore(mitigated.getSystemicRiskScore(), mitigated.getRiskSeverity());

                    String action = newState ? "QUARANTINED & ISOLATED" : "RESTORED & UNQUARANTINED";
                    logTopology(String.format("\n>>> [CONTAINMENT ACTION APPLIED] Node %s is now %s.", nodeId, action));
                    logTopology(String.format(">>> New Mitigated Risk Score: %.2f%% [%s] (Downstream assets reachable: %d)",
                            mitigated.getSystemicRiskScore(), mitigated.getRiskSeverity(), mitigated.getReachableAssets().size()));

                    String asciiTree = buildAsciiAttackTree(mitigated);
                    logTopology(asciiTree);

                    DarkTheme.showToast(BlueTeamDashboardFrame.this,
                            String.format("%s: %s | New Risk: %.2f%%", newState ? "🛑 Node Quarantined" : "✔️ Node Restored", nodeId, mitigated.getSystemicRiskScore()),
                            newState ? DarkTheme.ACCENT_RED : DarkTheme.ACCENT_GREEN);

                } catch (Exception ex) {
                    logTopology("[CONTAINMENT ERROR] " + ex.getMessage());
                    DarkTheme.showToast(BlueTeamDashboardFrame.this, "❌ Quarantine error: " + ex.getMessage(), DarkTheme.ACCENT_RED);
                }
            }
        };

        worker.execute();
    }

    // =========================================================================
    // HONEYTOKEN CENTER ASYNC OPERATIONS
    // =========================================================================

    private void deployCanaryAsync() {
        Honeytoken.TokenType[] types = Honeytoken.TokenType.values();
        Honeytoken.TokenType selectedType = (Honeytoken.TokenType) JOptionPane.showInputDialog(
                this, "Select Decoy Honeytoken Type to Generate:",
                "Deploy Decoy Canary", JOptionPane.QUESTION_MESSAGE, null, types, types[0]
        );
        if (selectedType == null) return;

        String location = JOptionPane.showInputDialog(
                this, "Enter Strategic Planting Location (e.g. '.env.dev', 's3://internal-dump'):",
                "infra/ci-cd-secrets.yaml"
        );
        if (location == null || location.trim().isEmpty()) return;

        btnNewCanary.setEnabled(false);

        SwingWorker<Honeytoken, Void> worker = new SwingWorker<>() {
            @Override
            protected Honeytoken doInBackground() throws Exception {
                return honeytokenGenerator.generateAndRecordHoneytoken(selectedType, location.trim());
            }

            @Override
            protected void done() {
                btnNewCanary.setEnabled(true);
                try {
                    Honeytoken canary = get();
                    refreshHoneytokensTable();
                    logTopology(String.format("[CANARY DEPLOYED] Created %s [%s] at '%s'. Hash Prefix: %s",
                            canary.getCanaryId(), canary.getTokenType(), canary.getPlantedLocation(), canary.getHashPrefix()));
                    DarkTheme.showToast(BlueTeamDashboardFrame.this, "✔️ Canary [" + canary.getCanaryId() + "] deployed successfully!", DarkTheme.ACCENT_GREEN);
                } catch (Exception ex) {
                    DarkTheme.showToast(BlueTeamDashboardFrame.this, "❌ Failed to record canary: " + ex.getMessage(), DarkTheme.ACCENT_RED);
                }
            }
        };

        worker.execute();
    }

    private void simulateDarkWebLeakFeedAsync() {
        List<Honeytoken> canaries = honeytokenGenerator.getActiveCanaries();
        if (canaries.isEmpty()) {
            DarkTheme.showToast(this, "⚠️ No active canaries deployed. Deploy one first!", DarkTheme.ACCENT_AMBER);
            return;
        }

        btnSimulateScrape.setEnabled(false);
        btnSimulateScrape.setText("📡 Ingesting Dump...");

        Honeytoken targetCanary = canaries.get(0);
        List<String> leakedSecrets = Arrays.asList(
                "corp_unrelated_password_2026",
                targetCanary.getSecretValue(), // The injected canary leak!
                "admin_shadow_credential#99"
        );

        ThreatIntelFeedScraper.MockBreachDump dump = new ThreatIntelFeedScraper.MockBreachDump(
                "TorMarket_BreachForums_DarkWeb_Dump_#9901",
                leakedSecrets
        );

        SwingWorker<List<SecurityAlert>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<SecurityAlert> doInBackground() throws Exception {
                return scraper.scanThreatIntelDump(dump);
            }

            @Override
            protected void done() {
                btnSimulateScrape.setEnabled(true);
                btnSimulateScrape.setText("📡 Simulate Dark Web Leak Feed");

                try {
                    List<SecurityAlert> alerts = get();
                    refreshHoneytokensTable();

                    // Refresh alert count
                    db.executeQuery("SELECT COUNT(*) FROM blast_alerts", rs -> {
                        if (rs.next()) {
                            int count = rs.getInt(1);
                            lblAlertCountValue.setText(count + " Alerts");
                            if (count > 0) lblAlertCountValue.setForeground(DarkTheme.ACCENT_RED);
                        }
                        return null;
                    });

                    logTopology(String.format("[FEED SCRAPED] Dark web dump ingested: %d breach incident(s) triggered!", alerts.size()));
                    DarkTheme.showToast(BlueTeamDashboardFrame.this, "🚨 Leak Alert: Decoy token detected in dark web dump!", DarkTheme.ACCENT_RED);

                } catch (Exception ex) {
                    DarkTheme.showToast(BlueTeamDashboardFrame.this, "❌ Simulation error: " + ex.getMessage(), DarkTheme.ACCENT_RED);
                }
            }
        };

        worker.execute();
    }

    private void containTriggeredTokens() {
        List<Honeytoken> canaries = honeytokenGenerator.getActiveCanaries();
        int containedCount = 0;
        for (Honeytoken canary : canaries) {
            if (canary.isTriggered() && !canary.isContained()) {
                canary.setContained(true);
                containedCount++;
            }
        }

        refreshHoneytokensTable();
        if (containedCount > 0) {
            logTopology(String.format("[CONTAINMENT] Revoked and isolated %d breached canary tokens.", containedCount));
            DarkTheme.showToast(this, "🛡️ " + containedCount + " triggered canary token(s) revoked & contained.", DarkTheme.ACCENT_CYAN);
        } else {
            DarkTheme.showToast(this, "No uncontained triggered tokens found.", DarkTheme.FG_MUTED);
        }
    }

    // =========================================================================
    // OBSERVER PATTERN & ASCII TREE FORMATTER
    // =========================================================================

    @Override
    public void onSecurityAlert(SecurityAlert alert) {
        SwingUtilities.invokeLater(() -> {
            logTopology(String.format("\n>>> [OBSERVER ALERT DISPATCH: %s] Alert ID: %s | Source: %s | Risk: %.2f%%",
                    alert.getSeverity(), alert.getAlertId(), alert.getCompromisedSource(), alert.getSystemicRiskScore()));

            if (alert.getSystemicRiskScore() >= 80.0) {
                riskPillBadge.updateScore(alert.getSystemicRiskScore(), "CRITICAL");
            }

            refreshHoneytokensTable();
        });
    }

    private String buildAsciiAttackTree(BlastRadiusResult result) {
        StringBuilder sb = new StringBuilder();
        EmployeeNode root = result.getCompromisedNode();
        double score = result.getSystemicRiskScore();
        String severity = result.getRiskSeverity();
        List<AssetNode> assets = result.getReachableAssets();

        sb.append("╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
        sb.append("║                   PROJECT CRYPTALEAK - ZERO-TRUST THREAT TOPOLOGY EXPLORER                       ║\n");
        sb.append("╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝\n");
        sb.append(String.format("[BREACH ROOT ORIGIN] : %s (%s)\n", root.getName(), root.getNodeId()));
        sb.append(String.format("  ├─ Role / Department  : %s | Department: %s\n", root.getPrivilegeTier(), root.getDepartment()));
        sb.append(String.format("  ├─ Base Node Weight   : %.1f\n", root.getRiskWeight()));
        sb.append(String.format("  ├─ Quarantine Status  : %s\n", root.isQuarantined() ? "[ 🛑 QUARANTINED / ISOLATED ]" : "[ ● ACTIVE / UNCONFINED ]"));
        sb.append(String.format("  ├─ Total Exposed Assets: %d downstream targets reachable\n", assets.size()));
        sb.append(String.format("  └─ Systemic Risk Score: %.2f%% [%s]\n", score, severity));
        sb.append("───────────────────────────────────────────────────────────────────────────────────────────────────\n");
        sb.append("LATERAL ATTACK PROPAGATION HIERARCHY (BFS TRAVERSAL):\n\n");

        if (assets.isEmpty()) {
            if (root.isQuarantined()) {
                sb.append("  └── [CONTAINMENT ACTIVE] Lateral traversal boundaries active. All vectors severed.\n");
            } else {
                sb.append("  └── (Isolated Identity) No downstream assets reachable from this node.\n");
            }
        } else {
            sb.append(String.format("  └── (Root) %s [%s]\n", root.getNodeId(), root.getName()));
            for (int i = 0; i < assets.size(); i++) {
                AssetNode asset = assets.get(i);
                boolean isLastAsset = (i == assets.size() - 1);
                String branch = isLastAsset ? "      └── " : "      ├── ";
                int hops = result.getHopDistances().getOrDefault(asset, 1);
                List<Edge> path = result.getAttackPaths().get(asset);

                String edgeInfo = "";
                if (path != null && !path.isEmpty()) {
                    Edge lastEdge = path.get(path.size() - 1);
                    edgeInfo = String.format("[%s, mult: x%.1f]", lastEdge.getAccessType(), lastEdge.getAccessMultiplier());
                }

                sb.append(String.format("  %s[HOP %d] %s ──► %s (%s)\n",
                        branch, hops, edgeInfo, asset.getNodeId(), asset.getName()));

                String subBranch = isLastAsset ? "          " : "      │   ";
                sb.append(String.format("%s├─ Asset Type     : %s\n", subBranch, asset.getAssetType()));
                sb.append(String.format("%s├─ Critical Weight: %.1f\n", subBranch, asset.getRiskWeight()));
                sb.append(String.format("%s└─ Target Endpoint: %s\n", subBranch, asset.getEndpoint()));
            }
        }

        sb.append("\n───────────────────────────────────────────────────────────────────────────────────────────────────\n");
        sb.append("EXPOSED ASSET BREAKDOWN:\n");
        if (assets.isEmpty()) {
            sb.append("  None. Perimeter secure.\n");
        } else {
            for (int i = 0; i < assets.size(); i++) {
                AssetNode a = assets.get(i);
                int hops = result.getHopDistances().getOrDefault(a, 1);
                sb.append(String.format("  [%d] %-22s | Type: %-12s | Criticality: %-8s | Weight: %4.1f | Hops: %d\n",
                        i + 1, a.getNodeId(), a.getAssetType(),
                        a.getRiskWeight() >= 80 ? "CRITICAL" : a.getRiskWeight() >= 50 ? "HIGH" : "MEDIUM",
                        a.getRiskWeight(), hops));
            }
        }

        sb.append("───────────────────────────────────────────────────────────────────────────────────────────────────\n");
        if (root.isQuarantined()) {
            sb.append("CONTAINMENT STATUS: MITIGATED. Lateral movement severed across all identity edges.\n");
        } else {
            sb.append("ACTIONABLE INTELLIGENCE:\n");
            sb.append("  Threat vectors active! Click [ 🛑 Quarantine Node ] to isolate this identity\n");
            sb.append("  and sever downstream lateral privilege escalation pathways.\n");
        }
        sb.append("===================================================================================================\n");
        return sb.toString();
    }

    private void logTopology(String msg) {
        String entry = "[" + dateFormat.format(new Date()) + "] " + msg + "\n";
        if (SwingUtilities.isEventDispatchThread()) {
            txtTopologyConsole.append(entry);
            txtTopologyConsole.setCaretPosition(txtTopologyConsole.getDocument().getLength());
        } else {
            SwingUtilities.invokeLater(() -> {
                txtTopologyConsole.append(entry);
                txtTopologyConsole.setCaretPosition(txtTopologyConsole.getDocument().getLength());
            });
        }
    }

    // =========================================================================
    // CUSTOM UI COMPONENTS: CIRCULAR/PILL RISK BADGE & STATUS TAG RENDERER
    // =========================================================================

    /**
     * Modern circular / pill risk-colored badge for Systemic Risk Index
     */
    public static class RiskPillBadge extends JPanel {
        private String text = "0.00% [NORMAL]";
        private Color severityColor = DarkTheme.ACCENT_GREEN;

        public RiskPillBadge() {
            setOpaque(false);
            setPreferredSize(new Dimension(200, 36));
        }

        public void updateScore(double score, String severity) {
            this.text = String.format("%.2f%% [%s]", score, severity);
            if (score >= 80.0) {
                this.severityColor = DarkTheme.ACCENT_RED;
            } else if (score >= 50.0) {
                this.severityColor = DarkTheme.ACCENT_AMBER;
            } else if (score >= 25.0) {
                this.severityColor = DarkTheme.ACCENT_CYAN;
            } else {
                this.severityColor = DarkTheme.ACCENT_GREEN;
            }
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

            // Background pill tint (translucent)
            Color tint = new Color(severityColor.getRed(), severityColor.getGreen(), severityColor.getBlue(), 35);
            g2.setColor(tint);
            g2.fill(new RoundRectangle2D.Float(2, 2, w - 5, h - 5, h - 2, h - 2));

            // Outer border
            g2.setColor(severityColor);
            g2.setStroke(new BasicStroke(1.5f));
            g2.draw(new RoundRectangle2D.Float(2, 2, w - 5, h - 5, h - 2, h - 2));

            // Indicator dot
            int dotSize = 8;
            int dotY = (h - dotSize) / 2;
            int dotX = 14;
            g2.setColor(severityColor);
            g2.fillOval(dotX, dotY, dotSize, dotSize);

            // Bold Typography
            g2.setFont(new Font("Segoe UI", Font.BOLD, 15));
            FontMetrics fm = g2.getFontMetrics();
            int textX = dotX + dotSize + 8;
            int textY = ((h - fm.getHeight()) / 2) + fm.getAscent();
            g2.drawString(text, textX, textY);

            g2.dispose();
        }
    }

    /**
     * Custom cell renderer for Honeytoken status tags: ACTIVE, TRIGGERED, CONTAINED
     */
    public static class StatusTagRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
            JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
            label.setHorizontalAlignment(JLabel.CENTER);
            String val = (value != null) ? value.toString() : "";

            if (val.contains("TRIGGERED") || val.contains("LEAKED") || val.contains("BREACHED")) {
                label.setText("⚠️ TRIGGERED");
                label.setForeground(DarkTheme.ACCENT_RED);
                label.setFont(DarkTheme.FONT_BODY_BOLD);
            } else if (val.contains("CONTAINED") || val.contains("REVOKED")) {
                label.setText("🛡️ CONTAINED");
                label.setForeground(DarkTheme.ACCENT_CYAN);
                label.setFont(DarkTheme.FONT_BODY_BOLD);
            } else {
                label.setText("● ACTIVE");
                label.setForeground(DarkTheme.ACCENT_GREEN);
                label.setFont(DarkTheme.FONT_BODY_BOLD);
            }
            label.setBackground(DarkTheme.BG_CARD);
            return label;
        }
    }
}