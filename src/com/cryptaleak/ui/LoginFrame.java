package com.cryptaleak.ui;

import com.cryptaleak.crypto.CryptoService;
import com.cryptaleak.db.DatabaseConnection;
import com.cryptaleak.strategy.BreachResult;
import com.cryptaleak.strategy.KAnonymitySearchStrategy;

import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
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
        setTitle("Project CryptaLeak - Enterprise Cyber Defense Login");
        setSize(460, 600);
        setResizable(false);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        DarkTheme.applyThemeToFrame(this);

        JPanel mainPanel = new JPanel(new BorderLayout(16, 16));
        mainPanel.setBackground(DarkTheme.BG_DARKEST);
        mainPanel.setBorder(new EmptyBorder(30, 36, 30, 36));

        // 1. BRANDING HEADER
        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));
        headerPanel.setBackground(DarkTheme.BG_DARKEST);

        JLabel lblShield = new JLabel("🛡️");
        lblShield.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 46));
        lblShield.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel lblBrand = new JLabel("PROJECT CRYPTALEAK");
        lblBrand.setFont(new Font("Segoe UI", Font.BOLD, 20));
        lblBrand.setForeground(DarkTheme.ACCENT_CYAN);
        lblBrand.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel lblSubtitle = new JLabel("Enterprise Breach Detection & Identity Defense");
        lblSubtitle.setFont(DarkTheme.FONT_SMALL);
        lblSubtitle.setForeground(DarkTheme.FG_MUTED);
        lblSubtitle.setAlignmentX(Component.CENTER_ALIGNMENT);

        headerPanel.add(lblShield);
        headerPanel.add(Box.createVerticalStrut(8));
        headerPanel.add(lblBrand);
        headerPanel.add(Box.createVerticalStrut(4));
        headerPanel.add(lblSubtitle);
        headerPanel.add(Box.createVerticalStrut(14));

        mainPanel.add(headerPanel, BorderLayout.NORTH);

        // 2. CREDENTIAL FORM CARD
        JPanel formCard = DarkTheme.createCardPanel();
        formCard.setLayout(new BoxLayout(formCard, BoxLayout.Y_AXIS));

        // Email field
        JLabel lblEmail = new JLabel("Corporate Email Address");
        lblEmail.setFont(DarkTheme.FONT_BODY_BOLD);
        lblEmail.setForeground(DarkTheme.FG_PRIMARY);
        lblEmail.setAlignmentX(Component.LEFT_ALIGNMENT);

        txtEmail = DarkTheme.createTextField(20);
        txtEmail.setText("admin@cryptaleak.corp");
        txtEmail.setMaximumSize(new Dimension(Short.MAX_VALUE, 36));
        txtEmail.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Password field
        JLabel lblPass = new JLabel("Master Password / Security Key");
        lblPass.setFont(DarkTheme.FONT_BODY_BOLD);
        lblPass.setForeground(DarkTheme.FG_PRIMARY);
        lblPass.setAlignmentX(Component.LEFT_ALIGNMENT);

        txtPassword = DarkTheme.createPasswordField(20);
        txtPassword.setText("Admin#2026!Crypta");
        txtPassword.setMaximumSize(new Dimension(Short.MAX_VALUE, 36));
        txtPassword.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Status message
        lblStatus = new JLabel("Enter credentials to authenticate.");
        lblStatus.setFont(DarkTheme.FONT_SMALL);
        lblStatus.setForeground(DarkTheme.FG_MUTED);
        lblStatus.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Login Button
        btnLogin = DarkTheme.createButton("Authenticate & Access Vault", DarkTheme.ACCENT_BLUE, DarkTheme.FG_PRIMARY);
        btnLogin.setMaximumSize(new Dimension(Short.MAX_VALUE, 40));
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
        formCard.add(txtPassword);
        formCard.add(Box.createVerticalStrut(14));
        formCard.add(lblStatus);
        formCard.add(Box.createVerticalStrut(16));
        formCard.add(btnLogin);

        mainPanel.add(formCard, BorderLayout.CENTER);

        // 3. FOOTER: Quick Demo Account Selectors
        JPanel footerPanel = new JPanel();
        footerPanel.setLayout(new BoxLayout(footerPanel, BoxLayout.Y_AXIS));
        footerPanel.setBackground(DarkTheme.BG_DARKEST);

        JLabel lblDemo = new JLabel("DEMO ROLES SELECTOR:");
        lblDemo.setFont(DarkTheme.FONT_SMALL);
        lblDemo.setForeground(DarkTheme.FG_MUTED);
        lblDemo.setAlignmentX(Component.CENTER_ALIGNMENT);

        JPanel demoButtons = new JPanel(new FlowLayout(FlowLayout.CENTER, 8, 4));
        demoButtons.setBackground(DarkTheme.BG_DARKEST);

        JButton btnAdmin = DarkTheme.createButton("Blue Team Lead", DarkTheme.BG_INPUT, DarkTheme.ACCENT_CYAN);
        btnAdmin.addActionListener(e -> {
            txtEmail.setText("admin@cryptaleak.corp");
            txtPassword.setText("Admin#2026!Crypta");
        });

        JButton btnEmployee = DarkTheme.createButton("Standard Staff", DarkTheme.BG_INPUT, DarkTheme.ACCENT_GREEN);
        btnEmployee.addActionListener(e -> {
            txtEmail.setText("employee@cryptaleak.corp");
            txtPassword.setText("EmployeePass123!");
        });

        demoButtons.add(btnAdmin);
        demoButtons.add(btnEmployee);

        footerPanel.add(lblDemo);
        footerPanel.add(Box.createVerticalStrut(4));
        footerPanel.add(demoButtons);

        mainPanel.add(footerPanel, BorderLayout.SOUTH);
        setContentPane(mainPanel);
    }

    private void authenticateUser() {
        String email = txtEmail.getText().trim();
        String pass = new String(txtPassword.getPassword()).trim();

        if (email.isEmpty() || pass.isEmpty()) {
            lblStatus.setText("Email and password are required.");
            lblStatus.setForeground(DarkTheme.ACCENT_AMBER);
            return;
        }

        lblStatus.setText("Authenticating with MySQL database...");
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
                        lblStatus.setText("Invalid credentials or account does not exist.");
                        lblStatus.setForeground(DarkTheme.ACCENT_RED);
                        return;
                    }

                    // Update last login timestamp in MySQL
                    try {
                        db.executeUpdate("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", session.getId());
                    } catch (SQLException ignored) {}

                    // Notify if user's own password was detected in the compromised vault
                    if (session.isCompromisedCredential()) {
                        JOptionPane.showMessageDialog(LoginFrame.this,
                                "⚠️ CRITICAL SECURITY WARNING:\n\n" +
                                "Your master password was identified in a leaked credential dataset!\n" +
                                "Please change your password immediately inside the vault portal.",
                                "Credential Leak Detected", JOptionPane.WARNING_MESSAGE);
                    }

                    // ROUTE USER ACCORDING TO ROLE
                    dispose(); // Close LoginFrame

                    if (session.isBlueTeam()) {
                        LOGGER.info("[Auth Router] Routing " + session.getEmail() + " to Blue Team Dashboard (" + session.getRole() + ")");
                        SwingUtilities.invokeLater(() -> new BlueTeamDashboardFrame(session).setVisible(true));
                    } else {
                        LOGGER.info("[Auth Router] Routing " + session.getEmail() + " to Employee Portal (" + session.getRole() + ")");
                        SwingUtilities.invokeLater(() -> new EmployeePortalFrame(session).setVisible(true));
                    }

                } catch (Exception ex) {
                    Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                    lblStatus.setText("Auth Error: " + cause.getMessage());
                    lblStatus.setForeground(DarkTheme.ACCENT_AMBER);
                    LOGGER.log(Level.WARNING, "Login failure: " + cause.getMessage(), cause);
                }
            }
        };

        authWorker.execute();
    }

    public static void main(String[] args) {
        // Set cross-platform look and feel
        try {
            UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
        } catch (Exception ignored) {}

        SwingUtilities.invokeLater(() -> new LoginFrame().setVisible(true));
    }
}