package com.cryptaleak.db;

import com.cryptaleak.crypto.CryptoService;
import com.cryptaleak.crypto.HashSplit;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.UUID;

public class DataSeeder {

    private static final DatabaseConnection db = DatabaseConnection.getInstance();
    private static final CryptoService crypto = new CryptoService();
    private static final Random random = new Random();

    public static void main(String[] args) {
        System.out.println("=====================================================");
        System.out.println(" Project CryptaLeak - Enterprise Data Seeder");
        System.out.println("=====================================================");

        try {
            ensureStandardEmployeeRole();
            clearExistingData();
            
            seedUsers();
            seedCompromisedVault();
            seedIdentityNodes();
            seedBlastAlerts();

            System.out.println("\n[+] Data seeding completed successfully!");

        } catch (Exception e) {
            System.err.println("[-] Error during data seeding: " + e.getMessage());
            e.printStackTrace();
        } finally {
            db.close();
        }
    }

    private static void ensureStandardEmployeeRole() throws SQLException {
        System.out.println("[*] Ensuring STANDARD_EMPLOYEE role exists in schema...");
        try (Connection conn = db.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute("ALTER TABLE users MODIFY COLUMN role ENUM('ADMIN', 'SECOPS_ANALYST', 'INCIDENT_RESPONDER', 'AUDITOR', 'STANDARD_EMPLOYEE') NOT NULL DEFAULT 'STANDARD_EMPLOYEE'");
        }
    }

    private static void clearExistingData() throws SQLException {
        System.out.println("[*] Clearing existing data...");
        db.executeUpdate("DELETE FROM blast_alerts");
        db.executeUpdate("DELETE FROM identity_nodes");
        db.executeUpdate("DELETE FROM compromised_vault");
        db.executeUpdate("DELETE FROM users");
    }

    private static void seedUsers() throws SQLException {
        System.out.println("[*] Seeding 15+ corporate users...");
        
        String[] departments = {"DevOps", "SecOps", "HR", "Finance", "Cloud Arch"};
        String[] roles = {"ADMIN", "SECOPS_ANALYST", "STANDARD_EMPLOYEE"};
        
        // Ensure at least one of each explicitly
        insertUser("admin@cryptaleak.corp", "Admin#2026!Crypta", "ADMIN");
        insertUser("analyst@cryptaleak.corp", "AnalystSecure123", "SECOPS_ANALYST");
        insertUser("employee@cryptaleak.corp", "EmployeePass123!", "STANDARD_EMPLOYEE");

        // Generate others
        for (int i = 1; i <= 15; i++) {
            String dept = departments[random.nextInt(departments.length)];
            String role = roles[random.nextInt(roles.length)];
            String email = "user" + i + "." + dept.toLowerCase().replace(" ", "") + "@cryptaleak.corp";
            String password = "Password!" + random.nextInt(9999);
            insertUser(email, password, role);
        }
        System.out.println("[+] Seeded Users.");
    }

    private static void insertUser(String email, String password, String role) throws SQLException {
        String hash = crypto.hashCredential(password);
        db.executeUpdate("INSERT INTO users (email, password_hash, role, is_active) VALUES (?, ?, ?, ?)",
                email, hash, role, true);
    }

    private static void seedCompromisedVault() throws SQLException {
        System.out.println("[*] Seeding 250+ compromised credentials (with K-Anonymity collisions)...");
        
        // Define some specific prefixes to force collisions
        String[] targetPrefixes = {"5BAA6", "A92F1", "7C4A1", "E10AD", "12345", "ABCDE"};
        
        int count = 0;
        for (String prefix : targetPrefixes) {
            // Generate 10-30 collisions per prefix
            int collisions = 10 + random.nextInt(20);
            for (int i = 0; i < collisions; i++) {
                String suffix = generateRandomHex(59);
                db.executeUpdate("INSERT INTO compromised_vault (hash_prefix, hash_suffix, breach_source) VALUES (?, ?, ?)",
                        prefix, suffix, "DarkWebDump_2026");
                count++;
            }
        }
        
        // Add random ones to reach 250+
        while (count < 260) {
            String fullHash = crypto.hashCredential("Random" + random.nextInt(1000000));
            HashSplit split = crypto.splitHash(fullHash);
            db.executeUpdate("INSERT INTO compromised_vault (hash_prefix, hash_suffix, breach_source) VALUES (?, ?, ?)",
                    split.getPrefix(), split.getSuffix(), "PublicBreachData");
            count++;
        }
        
        System.out.println("[+] Seeded " + count + " compromised credentials.");
    }

    private static String generateRandomHex(int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(Integer.toHexString(random.nextInt(16)).toUpperCase());
        }
        return sb.toString();
    }

    private static void seedIdentityNodes() throws SQLException {
        System.out.println("[*] Seeding 25+ identity nodes with graph adjacency...");
        
        class NodeInfo {
            String id;
            String type;
            String name;
            double weight;
            NodeInfo(String id, String type, String name, double weight) {
                this.id = id; this.type = type; this.name = name; this.weight = weight;
            }
        }
        
        List<NodeInfo> nodes = new ArrayList<>();
        
        // Base nodes
        nodes.add(new NodeInfo("DC-01", "DOMAIN_CONTROLLER", "corp-dc01.local", 100.0));
        nodes.add(new NodeInfo("DB-PROD-1", "DATABASE_CLUSTER", "db-prod-main", 80.0));
        nodes.add(new NodeInfo("AWS-IAM-ADMIN", "CLOUD_IAM_ROLE", "AWS_Admin_Role", 90.0));
        nodes.add(new NodeInfo("JENKINS-PIPELINE", "SERVICE_ACCOUNT", "jenkins-cicd", 60.0));
        nodes.add(new NodeInfo("GITHUB-ENTERPRISE", "SERVICE_ACCOUNT", "gh-actions", 50.0));
        
        // Employee nodes
        for (int i = 1; i <= 10; i++) {
            nodes.add(new NodeInfo("EMP-" + i, "DOMAIN_USER", "employee" + i + "@cryptaleak.corp", 1.0));
        }
        
        // Diverse asset nodes
        for (int i = 1; i <= 10; i++) {
            nodes.add(new NodeInfo("SRV-APP" + i, "SERVICE_ACCOUNT", "AppServer0" + i, 30.0));
        }
        
        // Generate random JSON edges for lateral movement
        for (NodeInfo node : nodes) {
            StringBuilder json = new StringBuilder("[");
            int edges = 1 + random.nextInt(3); // 1 to 3 outgoing edges
            boolean first = true;
            for (int i = 0; i < edges; i++) {
                NodeInfo target = nodes.get(random.nextInt(nodes.size()));
                if (target.id.equals(node.id)) continue;
                
                String[] accessTypes = {"RDP_ADMIN", "SSH_SUDO", "READ_ONLY", "API_WRITE"};
                String accessType = accessTypes[random.nextInt(accessTypes.length)];
                double multiplier = random.nextDouble() * 2.0; // 0.0 to 2.0
                
                if (!first) json.append(",");
                json.append(String.format("{\"targetId\":\"%s\",\"accessType\":\"%s\",\"weight\":%.2f}", 
                        target.id, accessType, multiplier));
                first = false;
            }
            json.append("]");
            
            db.executeUpdate("INSERT INTO identity_nodes (node_id, node_type, name, risk_weight, adjacent_nodes_json) VALUES (?, ?, ?, ?, ?)",
                    node.id, node.type, node.name, node.weight, json.toString());
        }
        
        System.out.println("[+] Seeded " + nodes.size() + " identity nodes.");
    }

    private static void seedBlastAlerts() throws SQLException {
        System.out.println("[*] Seeding 10+ historical blast alerts...");
        
        String[] severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"};
        String[] statuses = {"NEW", "INVESTIGATING", "CONTAINED", "RESOLVED"};
        
        for (int i = 0; i < 15; i++) {
            String alertId = "ALT-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
            String source = "EMP-" + (1 + random.nextInt(10));
            double score = random.nextDouble() * 100.0;
            String endpoint = "SRV-APP" + (1 + random.nextInt(10));
            String severity = severities[random.nextInt(severities.length)];
            String status = statuses[random.nextInt(statuses.length)];
            
            db.executeUpdate("INSERT INTO blast_alerts (alert_id, compromised_source, systemic_risk_score, breached_endpoint, severity, mitigation_status) VALUES (?, ?, ?, ?, ?, ?)",
                    alertId, source, score, endpoint, severity, status);
        }
        
        System.out.println("[+] Seeded 15 blast alerts.");
    }
}
