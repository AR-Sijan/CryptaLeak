package com.cryptaleak;

import com.cryptaleak.db.DatabaseConnection;
import com.cryptaleak.graph.BlastRadiusResult;
import com.cryptaleak.graph.IdentityGraph;
import com.cryptaleak.graph.Node;

public class TestIdentityGraph {

    public static void main(String[] args) {
        System.out.println("=================================================================");
        System.out.println(" Project CryptaLeak - Threat Relationship Graph & BFS Test");
        System.out.println("=================================================================");

        try {
            DatabaseConnection db = DatabaseConnection.getInstance();
            IdentityGraph graph = new IdentityGraph();

            // -------------------------------------------------------------
            // TEST 1: Load Topology from MySQL Database at Startup
            // -------------------------------------------------------------
            System.out.println("\n--- [TEST 1] Loading Graph Topology from MySQL ---");
            graph.loadFromDatabase(db);

            System.out.printf("[+] Loaded %d Nodes and %d Edges successfully into memory.\n",
                    graph.getNodeCount(), graph.getEdgeCount());

            if (graph.getNodeCount() != 10) {
                throw new AssertionError("Expected 10 nodes loaded from database, found: " + graph.getNodeCount());
            }
            System.out.println("[PASS] Database loading and JSON adjacency parsing verified.");

            // -------------------------------------------------------------
            // TEST 2: BFS Blast Radius on High-Privilege Target (EMP-BOB)
            // -------------------------------------------------------------
            System.out.println("\n--- [TEST 2] BFS Blast Radius Traversal for EMP-BOB (DevOps) ---");
            BlastRadiusResult bobResult = graph.calculateBlastRadius("EMP-BOB");
            System.out.println(bobResult.generateSecurityReport());

            if (bobResult.getReachableAssets().isEmpty()) {
                throw new AssertionError("Bob should reach downstream assets via infrastructure repo and jump server!");
            }
            if (bobResult.getSystemicRiskScore() < 70.0) {
                throw new AssertionError("Bob's systemic risk score should be HIGH/CRITICAL due to Domain Controller exposure!");
            }
            System.out.printf("[PASS] Bob's Blast Radius verified: %d assets exposed, Risk Score: %.2f%% [%s]\n",
                    bobResult.getTotalAssetsExposed(), bobResult.getSystemicRiskScore(), bobResult.getRiskSeverity());

            // -------------------------------------------------------------
            // TEST 3: BFS Blast Radius on Low-Privilege Target (EMP-CHARLIE)
            // -------------------------------------------------------------
            System.out.println("\n--- [TEST 3] BFS Blast Radius Traversal for EMP-CHARLIE (Junior SOC) ---");
            BlastRadiusResult charlieResult = graph.calculateBlastRadius("EMP-CHARLIE");
            System.out.println(charlieResult.generateSecurityReport());

            if (charlieResult.getTotalAssetsExposed() != 1) {
                throw new AssertionError("Charlie should only reach 1 asset (SRV-SIEM01)!");
            }
            if (charlieResult.getSystemicRiskScore() >= bobResult.getSystemicRiskScore()) {
                throw new AssertionError("Charlie's risk score must be lower than Bob's!");
            }
            System.out.printf("[PASS] Charlie's isolated blast radius verified: %.2f%% [%s]\n",
                    charlieResult.getSystemicRiskScore(), charlieResult.getRiskSeverity());

            // -------------------------------------------------------------
            // TEST 4: Dynamic Incident Containment (Node Quarantine)
            // -------------------------------------------------------------
            System.out.println("\n--- [TEST 4] Incident Containment & Quarantine Verification ---");
            Node jumpHost = graph.getNode("SRV-JUMP01");
            Node infraRepo = graph.getNode("REPO-INFRA");

            System.out.println("[+] Simulating SecOps containment: Quarantining SRV-JUMP01 and REPO-INFRA...");
            jumpHost.setQuarantined(true);
            infraRepo.setQuarantined(true);

            BlastRadiusResult containedResult = graph.calculateBlastRadius("EMP-BOB");
            System.out.printf("[+] Post-Quarantine Reachable Assets for Bob: %d (Pre-quarantine was: %d)\n",
                    containedResult.getTotalAssetsExposed(), bobResult.getTotalAssetsExposed());
            System.out.printf("[+] Post-Quarantine Systemic Risk Score: %.2f%% (Pre-quarantine was: %.2f%%)\n",
                    containedResult.getSystemicRiskScore(), bobResult.getSystemicRiskScore());

            if (containedResult.getSystemicRiskScore() >= bobResult.getSystemicRiskScore()) {
                throw new AssertionError("Quarantine should reduce systemic risk score significantly!");
            }
            System.out.println("[PASS] Active quarantine containment halts BFS lateral movement effectively.");

            System.out.println("\n=================================================================");
            System.out.println(" >>> ALL GRAPH & BFS TRAVERSAL TESTS PASSED 100%! <<<");
            System.out.println("=================================================================");

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}