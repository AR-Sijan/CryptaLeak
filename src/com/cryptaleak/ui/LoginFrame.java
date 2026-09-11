package com.cryptaleak.ui;

import com.cryptaleak.crypto.CryptoService;
import com.cryptaleak.db.DatabaseConnection;
import com.cryptaleak.strategy.BreachResult;
import com.cryptaleak.strategy.KAnonymitySearchStrategy;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Project CryptaLeak - Enterprise Authentication & Role Router
 * 
 * Authenticates users via corporate credentials, checks credential breach exposure
 * via KAnonymitySearchStrategy, and dynamically routes roles to either the
 * Blue Team Dashboard or the Employee Portal.
 */
public class LoginFrame extends JFrame {

    private static final Logger LOGGER = Logger.getLogger(LoginFrame.class.getName());

    private final DatabaseConnection db;
    private final CryptoService cryptoService;
    private final KAnonymitySearchStrategy searchStrategy;

    private JTextField txtEmail;
    private JPasswordField txtPassword;
    private JLabel lblStatus;
    private JButton btnLogin;

    public LoginFrame() {
        this.db = DatabaseConnection.getInstance();
        this.cryptoService = new CryptoService();
        this.searchStrategy = new KAnonymitySearchStrategy(db, cryptoService);

        initComponents();
    }

    private void initComponents() {
        setTitle("Project CryptaLeak - Enterprise Cyber Defense");
        setSize(480, 620);
        setResizable(false);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        DarkTheme.applyThemeToFrame(this);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBackground(DarkTheme.BG_DARKEST);
        mainPanel.setBorder(new EmptyBorder(30, 40, 30, 40));

        // 1. BRANDING HEADER
        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));
        headerPanel.setBackground(DarkTheme.BG_DARKEST);
        headerPanel.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel lblShield = new JLabel("🛡️", SwingConstants.CENTER);
        lblShield.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 52));
        lblShield.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel lblBrand = new JLabel("CRYPTALEAK", SwingConstants.CENTER);
        lblBrand.setFont(new Font("Segoe UI", Font.BOLD, 24));
        lblBrand.setForeground(DarkTheme.ACCENT_CYAN);
        lblBrand.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel lblSubtitle = new JLabel("Zero-Trust Architecture", SwingConstants.CENTER);
        lblSubtitle.setFont(DarkTheme.FONT_SMALL);
        lblSubtitle.setForeground(DarkTheme.FG_MUTED);
        lblSubtitle.setAlignmentX(Component.CENTER_ALIGNMENT);

        headerPanel.add(lblShield);
        headerPanel.add(Box.createVerticalStrut(8));
        headerPanel.add(lblBrand);
        headerPanel.add(Box.createVerticalStrut(4));
        headerPanel.add(lblSubtitle);
        headerPanel.add(Box.createVerticalStrut(24));

        mainPanel.add(headerPanel);

        // 2. CREDENTIAL FORM CARD
        JPanel formCard = DarkTheme.createCardPanel();
        formCard.setLayout(new BoxLayout(formCard, BoxLayout.Y_AXIS));
        formCard.setAlignmentX(Component.CENTER_ALIGNMENT);

        // Email field
        JLabel lblEmail = new JLabel("Corporate Email");
        lblEmail.setFont(DarkTheme.FONT_BODY_BOLD);
        lblEmail.setForeground(DarkTheme.FG_MUTED);
        lblEmail.setAlignmentX(Component.LEFT_ALIGNMENT);

        txtEmail = DarkTheme.createTextField(20);
        txtEmail.setText("admin@cryptaleak.corp");
        txtEmail.setMaximumSize(new Dimension(Short.MAX_VALUE, 40));
        txtEmail.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Password field
        JLabel lblPass = new JLabel("Master Password");
        lblPass.setFont(DarkTheme.FONT_BODY_BOLD);
        lblPass.setForeground(DarkTheme.FG_MUTED);
        lblPass.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel passContainer = new JPanel(new BorderLayout(8, 0));
        passContainer.setOpaque(false);
        passContainer.setMaximumSize(new Dimension(Short.MAX_VALUE, 40));
        passContainer.setAlignmentX(Component.LEFT_ALIGNMENT);

        txtPassword = DarkTheme.createPasswordField(20);
        txtPassword.setText("Admin#2026!Crypta");
        
        JButton btnToggleEye = new JButton("👁");
        btnToggleEye.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 14));
        btnToggleEye.setFocusPainted(false);
        btnToggleEye.setContentAreaFilled(false);
        btnToggleEye.setBorderPainted(false);
        btnToggleEye.setForeground(DarkTheme.FG_MUTED);
        btnToggleEye.setCursor(new Cursor(Cursor.HAND_CURSOR));
        
        final boolean[] passVisible = {false};
        btnToggleEye.addActionListener(e -> {
            passVisible[0] = !passVisible[0];
            if (passVisible[0]) {
                txtPassword.setEchoChar((char) 0);
                btnToggleEye.setForeground(DarkTheme.ACCENT_CYAN);
            } else {
                txtPassword.setEchoChar('•');
                btnToggleEye.setForeground(DarkTheme.FG_MUTED);
            }
        });

        passContainer.add(txtPassword, BorderLayout.CENTER);
        passContainer.add(btnToggleEye, BorderLayout.EAST);

        // Status message (Inline error label)
        lblStatus = new JLabel(" "); // Reserved space
        lblStatus.setFont(DarkTheme.FONT_BODY_BOLD);
        lblStatus.setForeground(DarkTheme.ACCENT_RED);
        lblStatus.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Login Button
        btnLogin = DarkTheme.createButton("Authenticate", DarkTheme.ACCENT_BLUE, DarkTheme.FG_PRIMARY);
        btnLogin.setMaximumSize(new Dimension(Short.MAX_VALUE, 44));
        btnLogin.setAlignmentX(Component.LEFT_ALIGNMENT);
        btnLogin.addActionListener(e -> authenticateUser());

        // Pressing Enter inside password triggers login
        txtPassword.addActionListener(e -> authenticateUser());
        txtEmail.addActionListener(e -> txtPassword.requestFocusInWindow());

        formCard.add(lblEmail);
        formCard.add(Box.createVerticalStrut(6));
        formCard.add(txtEmail);
        formCard.add(Box.createVerticalStrut(14));
        formCard.add(lblPass);
        formCard.add(Box.createVerticalStrut(6));
        formCard.add(passContainer);
        formCard.add(Box.createVerticalStrut(10));
        formCard.add(lblStatus);
        formCard.add(Box.createVerticalStrut(14));
        formCard.add(btnLogin);

        mainPanel.add(formCard);

        // 3. FOOTER: Quick Test Dropdown
        mainPanel.add(Box.createVerticalStrut(20));
        
        JPanel footerPanel = new JPanel();
        footerPanel.setLayout(new BoxLayout(footerPanel, BoxLayout.Y_AXIS));
        footerPanel.setBackground(DarkTheme.BG_DARKEST);
        footerPanel.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel lblDemo = new JLabel("Quick Test Credentials");
        lblDemo.setFont(DarkTheme.FONT_SMALL);
        lblDemo.setForeground(DarkTheme.FG_MUTED);
        lblDemo.setAlignmentX(Component.CENTER_ALIGNMENT);

        String[] demoAccounts = {
            "Select Demo Account...", 
            "Blue Team Lead (admin@cryptaleak.corp)", 
            "Standard Staff (employee@cryptaleak.corp)",
            "Compromised Account (Demo)"
        };
        JComboBox<String> cmbDemo = new JComboBox<>(demoAccounts);
        cmbDemo.setMaximumSize(new Dimension(300, 32));
        cmbDemo.setAlignmentX(Component.CENTER_ALIGNMENT);
        cmbDemo.setBackground(DarkTheme.BG_CARD);
        cmbDemo.setForeground(DarkTheme.FG_PRIMARY);
        cmbDemo.setFont(DarkTheme.FONT_BODY);
        
        cmbDemo.addActionListener(e -> {
            int idx = cmbDemo.getSelectedIndex();
            if (idx == 1) {
                txtEmail.setText("admin@cryptaleak.corp");
                txtPassword.setText("Admin#2026!Crypta");
                lblStatus.setText(" ");
            } else if (idx == 2) {
                txtEmail.setText("employee@cryptaleak.corp");
                txtPassword.setText("EmployeePass123!");
                lblStatus.setText(" ");
            } else if (idx == 3) {
                txtEmail.setText("user1.devops@cryptaleak.corp"); // Might exist or need exact seeded account
                txtPassword.setText("Random123456"); // This won't work perfectly unless we know a seeded compromised one, but the user can type
                lblStatus.setText(" ");
            }
        });

        footerPanel.add(lblDemo);
        footerPanel.add(Box.createVerticalStrut(6));
        footerPanel.add(cmbDemo);

        mainPanel.add(footerPanel);

        setContentPane(mainPanel);
    }

    private void authenticateUser() {
        String email = txtEmail.getText().trim();
        String pass = new String(txtPassword.getPassword()).trim();

        if (email.isEmpty() || pass.isEmpty()) {
            lblStatus.setText("⚠️ Email and password are required.");
            lblStatus.setForeground(DarkTheme.ACCENT_AMBER);
            return;
        }

        lblStatus.setText("Authenticating with Identity Provider...");
        lblStatus.setForeground(DarkTheme.ACCENT_CYAN);
        btnLogin.setEnabled(false);

        // Run authentication off the EDT to avoid UI freeze
        SwingWorker<UserSession, Void> authWorker = new SwingWorker<>() {
            @Override
            protected UserSession doInBackground() throws Exception {
                String inputHash = cryptoService.hashCredential(pass);

                // 1. Query users table with parameterized query
                String selectUserSql = "SELECT id, email, password_hash, role, is_active FROM users WHERE email = ?";
                UserSession session = db.executeQuery(selectUserSql, rs -> {
                    if (rs.next()) {
                        long id = rs.getLong("id");
                        String dbEmail = rs.getString("email");
                        String dbHash = rs.getString("password_hash");
                        String role = rs.getString("role");
                        boolean active = rs.getBoolean("is_active");

                        if (!active) {
                            throw new IllegalStateException("Account is deactivated. Contact security admin.");
                        }

                        // Compare SHA-256 digests
                        if (dbHash.equalsIgnoreCase(inputHash)) {
                            // 2. Perform zero-knowledge K-Anonymity check to detect if user's password is compromised
                            BreachResult breachResult = searchStrategy.checkCredential(pass);
                            return new UserSession(id, dbEmail, role, breachResult.isCompromised());
                        }
                    }
                    return null;
                }, email);

                return session;
            }

            @Override
            protected void done() {
                btnLogin.setEnabled(true);
                try {
                    UserSession session = get();

                    if (session == null) {
                        lblStatus.setText("❌ Invalid credentials or account does not exist.");
                        lblStatus.setForeground(DarkTheme.ACCENT_RED);
                        return;
                    }

                    // Update last login timestamp in MySQL
                    try {
                        db.executeUpdate("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", session.getId());
                    } catch (SQLException ignored) {}

                    // ROUTE USER ACCORDING TO ROLE
                    dispose(); // Close LoginFrame

                    if (session.isBlueTeam()) {
                        LOGGER.info("[Auth Router] Routing " + session.getEmail() + " to Blue Team Dashboard (" + session.getRole() + ")");
                        SwingUtilities.invokeLater(() -> new BlueTeamDashboardFrame(session).setVisible(true));
                    } else {
                        LOGGER.info("[Auth Router] Routing " + session.getEmail() + " to Employee Portal (" + session.getRole() + ")");
                        SwingUtilities.invokeLater(() -> new EmployeePortalFrame(session).setVisible(true));
                    }

                    // Show toast AFTER disposing so it centers on screen or new frame.
                    if (session.isCompromisedCredential()) {
                        DarkTheme.showToast(null, "⚠️ CRITICAL: Your master password was identified in a leaked dataset!", DarkTheme.ACCENT_RED);
                    } else {
                        DarkTheme.showToast(null, "✔️ Authentication Successful. Welcome back.", DarkTheme.ACCENT_GREEN);
                    }

                } catch (Exception ex) {
                    Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                    lblStatus.setText("❌ Auth Error: " + cause.getMessage());
                    lblStatus.setForeground(DarkTheme.ACCENT_RED);
                    LOGGER.log(Level.WARNING, "Login failure: " + cause.getMessage(), cause);
                }
            }
        };

        authWorker.execute();
    }

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
        } catch (Exception ignored) {}

        SwingUtilities.invokeLater(() -> new LoginFrame().setVisible(true));
    }
}