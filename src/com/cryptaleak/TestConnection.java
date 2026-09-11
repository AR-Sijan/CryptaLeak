package com.cryptaleak;

import com.cryptaleak.db.DatabaseConnection;
import java.sql.Connection;
import java.util.UUID;

public class TestConnection {
    public static void main(String[] args) {
        System.out.println("=== Testing Project CryptaLeak Database Connection ===");
        try {
            DatabaseConnection db = DatabaseConnection.getInstance();
            Connection conn = db.getConnection();
            System.out.println("[+] Successfully connected to MySQL server: " + conn.getMetaData().getDatabaseProductName() + " " + conn.getMetaData().getDatabaseProductVersion());

            // Test INSERT into blast_alerts using parameterized statement
            String alertId = "ALT-" + UUID.randomUUID().toString().substring(0, 8);
            String insertSql = "INSERT INTO blast_alerts (alert_id, compromised_source, systemic_risk_score, breached_endpoint, severity) VALUES (?, ?, ?, ?, ?)";
            int inserted = db.executeUpdate(insertSql, alertId, "admin_test", 92.50, "192.168.1.100", "HIGH");
            System.out.println("[+] Parameterized INSERT successful. Rows affected: " + inserted);

            // Test parameterized SELECT
            String selectSql = "SELECT alert_id, compromised_source, systemic_risk_score, severity FROM blast_alerts WHERE alert_id = ?";
            db.executeQuery(selectSql, rs -> {
                if (rs.next()) {
                    System.out.println("[+] Parameterized SELECT verified: ID=" + rs.getString("alert_id") +
                                       ", Source=" + rs.getString("compromised_source") +
                                       ", Risk=" + rs.getDouble("systemic_risk_score") +
                                       ", Severity=" + rs.getString("severity"));
                }
                return null;
            }, alertId);

            // Clean up test alert
            db.executeUpdate("DELETE FROM blast_alerts WHERE alert_id = ?", alertId);
            System.out.println("[+] Test cleanup completed.");
            System.out.println(">>> ALL PREREQUISITES VERIFIED AND WORKING PERFECTLY! <<<");

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}