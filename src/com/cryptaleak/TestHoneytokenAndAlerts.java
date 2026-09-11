package com.cryptaleak;

import com.cryptaleak.alert.AlertSubject;
import com.cryptaleak.alert.DatabaseAlertLogger;
import com.cryptaleak.alert.SecurityAlert;
import com.cryptaleak.alert.SocNotificationObserver;
import com.cryptaleak.db.DatabaseConnection;
import com.cryptaleak.graph.BlastRadiusResult;
import com.cryptaleak.graph.IdentityGraph;
import com.cryptaleak.honeytoken.Honeytoken;
import com.cryptaleak.honeytoken.HoneytokenGenerator;
import com.cryptaleak.honeytoken.ThreatIntelFeedScraper;

import java.sql.Connection;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.List;

public class TestHoneytokenAndAlerts {

    public static void main(String[] args) {
        System.out.println("=================================================================");
        System.out.println(" Project CryptaLeak - Honeytoken & Observer Alerting System Test");
        System.out.println("=================================================================");

        try {
            DatabaseConnection db = DatabaseConnection.getInstance();
            AlertSubject alertSubject = AlertSubject.getInstance();

            // -------------------------------------------------------------
            // SETUP: Observer Pattern Registrations
            // -------------------------------------------------------------
            System.out.println("\n--- [SETUP] Initializing Observer Pattern ---");
            DatabaseAlertLogger dbLogger = new DatabaseAlertLogger(db);
            SocNotificationObserver socObserver = new SocNotificationObserver();

            alertSubject.registerObserver(dbLogger);
            alertSubject.registerObserver(socObserver);

            System.out.printf("[+] Registered %d observers with AlertSubject.\n", alertSubject.getObserverCount());
            if (alertSubject.getObserverCount() < 2) {
                throw new AssertionError("Expected at least 2 registered observers!");
            }

            // -------------------------------------------------------------
            // TEST 1: Honeytoken Generation & Database Recording
            // -------------------------------------------------------------
            System.out.println("\n--- [TEST 1] Generating Decoy Honeytokens via SecureRandom ---");
            HoneytokenGenerator generator = new HoneytokenGenerator(db, new com.cryptaleak.crypto.CryptoService());

            Honeytoken awsCanary = generator.generateAndRecordHoneytoken(
                    Honeytoken.TokenType.AWS_ACCESS_KEY,
                    "deploy/aws-credentials.staging"
            );
            Honeytoken dbCanary = generator.generateAndRecordHoneytoken(
                    Honeytoken.TokenType.DATABASE_PASSWORD,
                    "backups/db-archive-2025.sql"
            );

            System.out.println("[+] Generated AWS Canary: " + awsCanary.getCanaryId());
            System.out.println("    Secret Key Value   : " + awsCanary.getSecretValue());
            System.out.println("    SHA-256 Hash       : " + awsCanary.getSha256Hash());
            System.out.println("    Planted Location   : " + awsCanary.getPlantedLocation());

            // Verify persistence in MySQL identity_nodes table
            String checkSql = "SELECT COUNT(*) FROM identity_nodes WHERE node_id IN (?, ?)";
            db.executeQuery(checkSql, rs -> {
                if (rs.next() && rs.getInt(1) == 2) {
                    System.out.println("[PASS] Both canary honeytokens recorded in MySQL identity_nodes table.");
                } else {
                    throw new AssertionError("Canary honeytokens not found in database!");
                }
                return null;
            }, awsCanary.getCanaryId(), dbCanary.getCanaryId());

            // -------------------------------------------------------------
            // TEST 2: Threat Intelligence Feed Scraper & Canary Breach
            // -------------------------------------------------------------
            System.out.println("\n--- [TEST 2] Dark Web Threat Intelligence Feed Scraper ---");
            ThreatIntelFeedScraper scraper = new ThreatIntelFeedScraper(generator, alertSubject);

            // Simulate Dark Web Leak Dump containing the decoy AWS key
            List<String> leakedDumpPayload = Arrays.asList(
                    "password123",
                    "admin@2024",
                    awsCanary.getSecretValue(), // LEAKED CANARY PRESENT!
                    "spring_cloud_dev_secret"
            );

            ThreatIntelFeedScraper.MockBreachDump darkWebDump = new ThreatIntelFeedScraper.MockBreachDump(
                    "BreachForums_DarkWeb_TorMarket_Feed_#802",
                    leakedDumpPayload
            );

            System.out.println("[+] Ingesting threat intelligence feed with " + leakedDumpPayload.size() + " dump items...");
            List<SecurityAlert> triggeredCanaries = scraper.scanThreatIntelDump(darkWebDump);

            if (triggeredCanaries.isEmpty()) {
                throw new AssertionError("Scraper failed to detect canary in threat dump!");
            }
            System.out.println("[PASS] Honeytoken canary breach accurately detected!");

            // -------------------------------------------------------------
            // TEST 3: Blast-Radius Exceeding 80% Threshold Alert
            // -------------------------------------------------------------
            System.out.println("\n--- [TEST 3] Evaluating Blast Radius Threshold (> 80%) ---");
            IdentityGraph graph = new IdentityGraph();
            graph.loadFromDatabase(db);

            // EMP-BOB reaches 5 downstream assets with a score of ~94%
            BlastRadiusResult bobResult = graph.calculateBlastRadius("EMP-BOB");
            System.out.printf("[+] Bob's Blast Radius Score: %.2f%%\n", bobResult.getSystemicRiskScore());

            SecurityAlert blastAlert = scraper.evaluateBlastRadiusThreshold(bobResult);
            if (blastAlert == null) {
                throw new AssertionError("Expected blast radius alert for score > 80%!");
            }
            System.out.println("[PASS] High Blast-Radius alert successfully triggered and dispatched!");

            // -------------------------------------------------------------
            // TEST 4: Verify Database Persistence in blast_alerts Table
            // -------------------------------------------------------------
            System.out.println("\n--- [TEST 4] Verifying MySQL blast_alerts Table Persistence ---");
            String queryAlerts = "SELECT alert_id, compromised_source, systemic_risk_score, severity FROM blast_alerts WHERE severity = 'CRITICAL'";
            db.executeQuery(queryAlerts, rs -> {
                int count = 0;
                while (rs.next()) {
                    count++;
                    System.out.printf("  [MySQL Record #%d] ID=%s | Source=%s | Risk=%.2f%% | Severity=%s\n",
                            count, rs.getString("alert_id"), rs.getString("compromised_source"),
                            rs.getDouble("systemic_risk_score"), rs.getString("severity"));
                }
                if (count < 2) {
                    throw new AssertionError("Expected at least 2 CRITICAL alerts in blast_alerts table, found: " + count);
                }
                return null;
            });
            System.out.println("[PASS] All security alerts verified in MySQL blast_alerts table.");

            // -------------------------------------------------------------
            // CLEANUP: Clean up test artifacts
            // -------------------------------------------------------------
            System.out.println("\n--- [CLEANUP] Removing test artifacts from database ---");
            db.executeUpdate("DELETE FROM identity_nodes WHERE node_id IN (?, ?)", awsCanary.getCanaryId(), dbCanary.getCanaryId());
            db.executeUpdate("DELETE FROM blast_alerts WHERE compromised_source LIKE 'HONEYTOKEN_TRIGGER%' OR compromised_source LIKE '%EMP-BOB%'");
            System.out.println("[+] Cleanup complete.");

            System.out.println("\n=================================================================");
            System.out.println(" >>> ALL HONEYTOKEN & OBSERVER ALERT TESTS PASSED 100%! <<<");
            System.out.println("=================================================================");

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}