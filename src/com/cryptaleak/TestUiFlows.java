package com.cryptaleak;

import com.cryptaleak.crypto.CryptoService;
import com.cryptaleak.db.DatabaseConnection;
import com.cryptaleak.strategy.BreachResult;
import com.cryptaleak.strategy.KAnonymitySearchStrategy;
import com.cryptaleak.ui.BlueTeamDashboardFrame;
import com.cryptaleak.ui.EmployeePortalFrame;
import com.cryptaleak.ui.UserSession;

import javax.swing.SwingUtilities;

public class TestUiFlows {

    public static void main(String[] args) {
        System.out.println("=================================================================");
        System.out.println(" Project CryptaLeak - UI Roles, Routing & Security Access Test");
        System.out.println("=================================================================");

        try {
            DatabaseConnection db = DatabaseConnection.getInstance();
            CryptoService crypto = new CryptoService();
            KAnonymitySearchStrategy search = new KAnonymitySearchStrategy(db, crypto);

            // -------------------------------------------------------------
            // TEST 1: Authenticate Admin & Route to Blue Team Dashboard
            // -------------------------------------------------------------
            System.out.println("\n--- [TEST 1] Authenticating Blue Team Lead (ADMIN) ---");
            String adminEmail = "admin@cryptaleak.corp";
            String adminPass = "Admin#2026!Crypta";
            String adminHash = crypto.hashCredential(adminPass);

            UserSession adminSession = db.executeQuery(
                    "SELECT id, email, role FROM users WHERE email = ? AND password_hash = ?",
                    rs -> {
                        if (rs.next()) {
                            return new UserSession(rs.getLong("id"), rs.getString("email"), rs.getString("role"), false);
                        }
                        return null;
                    },
                    adminEmail, adminHash
            );

            if (adminSession == null || !adminSession.isBlueTeam()) {
                throw new AssertionError("Admin authentication or Blue Team role check failed!");
            }
            System.out.printf("[+] Authenticated: %s (Role: %s) -> Authorized for Blue Team Dashboard.\n",
                    adminSession.getEmail(), adminSession.getRole());

            // Instantiate BlueTeamDashboardFrame on EDT
            SwingUtilities.invokeAndWait(() -> {
                BlueTeamDashboardFrame blueFrame = new BlueTeamDashboardFrame(adminSession);
                System.out.println("[+] BlueTeamDashboardFrame instantiated successfully with live KPI badges and topology matrix.");
                blueFrame.dispose();
            });
            System.out.println("[PASS] Blue Team routing and dashboard initialization verified.");

            // -------------------------------------------------------------
            // TEST 2: Authenticate Standard Staff & Route to Employee Portal
            // -------------------------------------------------------------
            System.out.println("\n--- [TEST 2] Authenticating Standard Staff (STANDARD_EMPLOYEE) ---");
            String empEmail = "employee@cryptaleak.corp";
            String empPass = "EmployeePass123!";
            String empHash = crypto.hashCredential(empPass);

            UserSession empSession = db.executeQuery(
                    "SELECT id, email, role FROM users WHERE email = ? AND password_hash = ?",
                    rs -> {
                        if (rs.next()) {
                            return new UserSession(rs.getLong("id"), rs.getString("email"), rs.getString("role"), false);
                        }
                        return null;
                    },
                    empEmail, empHash
            );

            if (empSession == null || !empSession.isStandardEmployee()) {
                throw new AssertionError("Employee authentication or Standard role check failed!");
            }
            System.out.printf("[+] Authenticated: %s (Role: %s) -> Routed to Employee Portal.\n",
                    empSession.getEmail(), empSession.getRole());

            // Instantiate EmployeePortalFrame on EDT
            SwingUtilities.invokeAndWait(() -> {
                EmployeePortalFrame portalFrame = new EmployeePortalFrame(empSession);
                System.out.println("[+] EmployeePortalFrame instantiated successfully with bulk verification table & crypto console.");
                portalFrame.dispose();
            });
            System.out.println("[PASS] Employee Portal routing and portal initialization verified.");

            // -------------------------------------------------------------
            // TEST 3: Access Control Guard - Block Employee from Blue Team
            // -------------------------------------------------------------
            System.out.println("\n--- [TEST 3] Enforcing Access Control Guard ---");
            boolean accessDeniedTriggered = false;
            try {
                // Attempt to open BlueTeamDashboardFrame using a standard employee session
                new BlueTeamDashboardFrame(empSession);
            } catch (SecurityException secEx) {
                accessDeniedTriggered = true;
                System.out.println("[+] Access Control Exception caught as expected: " + secEx.getMessage());
            }

            if (!accessDeniedTriggered) {
                throw new AssertionError("Security Guard failed! Standard employee should have been blocked from Blue Team dashboard!");
            }
            System.out.println("[PASS] Standard employees strictly blocked from Blue Team Incident Response dashboard.");

            System.out.println("\n=================================================================");
            System.out.println(" >>> ALL UI ROLES, ROUTING & SECURITY TESTS PASSED 100%! <<<");
            System.out.println("=================================================================");

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}