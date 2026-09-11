package com.cryptaleak.graph;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Project CryptaLeak - Blast Radius Assessment Telemetry
 * 
 * Result of a Breadth-First Search (BFS) threat propagation analysis.
 */
public class BlastRadiusResult {

    private final EmployeeNode compromisedNode;
    private final List<AssetNode> reachableAssets;
    private final Map<Node, Integer> hopDistances;
    private final Map<Node, List<Edge>> attackPaths;
    private final double systemicRiskScore;
    private final String riskSeverity;

    public BlastRadiusResult(EmployeeNode compromisedNode,
                             List<AssetNode> reachableAssets,
                             Map<Node, Integer> hopDistances,
                             Map<Node, List<Edge>> attackPaths,
                             double systemicRiskScore) {
        this.compromisedNode = compromisedNode;
        this.reachableAssets = Collections.unmodifiableList(reachableAssets);
        this.hopDistances = Collections.unmodifiableMap(hopDistances);
        this.attackPaths = Collections.unmodifiableMap(attackPaths);
        this.systemicRiskScore = Math.min(100.0, Math.max(0.0, systemicRiskScore));
        this.riskSeverity = determineSeverity(this.systemicRiskScore);
    }

    private static String determineSeverity(double score) {
        if (score >= 80.0) return "CRITICAL";
        if (score >= 50.0) return "HIGH";
        if (score >= 25.0) return "MEDIUM";
        return "LOW";
    }

    public EmployeeNode getCompromisedNode() {
        return compromisedNode;
    }

    public List<AssetNode> getReachableAssets() {
        return reachableAssets;
    }

    public Map<Node, Integer> getHopDistances() {
        return hopDistances;
    }

    public Map<Node, List<Edge>> getAttackPaths() {
        return attackPaths;
    }

    public double getSystemicRiskScore() {
        return systemicRiskScore;
    }

    public String getRiskSeverity() {
        return riskSeverity;
    }

    public int getTotalAssetsExposed() {
        return reachableAssets.size();
    }

    public String generateSecurityReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("=================================================================\n");
        sb.append("         PROJECT CRYPTALEAK - BLAST RADIUS ASSESSMENT REPORT     \n");
        sb.append("=================================================================\n");
        sb.append(String.format("Compromised Origin : %s (%s)\n", compromisedNode.getName(), compromisedNode.getNodeId()));
        sb.append(String.format("Department / Tier  : %s / %s\n", compromisedNode.getDepartment(), compromisedNode.getPrivilegeTier()));
        sb.append(String.format("Origin Base Weight : %.1f\n", compromisedNode.getRiskWeight()));
        sb.append(String.format("Exposed Assets     : %d\n", reachableAssets.size()));
        sb.append(String.format("Systemic Risk Score: %.2f%% [%s]\n", systemicRiskScore, riskSeverity));
        sb.append("-----------------------------------------------------------------\n");
        sb.append("DOWNSTREAM REACHABLE ASSETS (BFS ORDER):\n");

        if (reachableAssets.isEmpty()) {
            sb.append("  (No downstream infrastructure reachable from this node)\n");
        } else {
            for (AssetNode asset : reachableAssets) {
                int distance = hopDistances.getOrDefault(asset, -1);
                sb.append(String.format("  • [Hop %d] %s (Type: %s, Base Weight: %.1f, Endpoint: %s)\n",
                        distance, asset.getName(), asset.getAssetType(), asset.getRiskWeight(), asset.getEndpoint()));

                List<Edge> path = attackPaths.get(asset);
                if (path != null && !path.isEmpty()) {
                    sb.append("      Vector Path: ");
                    for (int i = 0; i < path.size(); i++) {
                        Edge e = path.get(i);
                        sb.append(e.getSource().getNodeId())
                          .append(" -[").append(e.getAccessType()).append("]-> ");
                        if (i == path.size() - 1) {
                            sb.append(e.getTarget().getNodeId());
                        }
                    }
                    sb.append("\n");
                }
            }
        }
        sb.append("=================================================================\n");
        return sb.toString();
    }

    @Override
    public String toString() {
        return String.format("BlastRadiusResult[Origin=%s, AssetsExposed=%d, RiskScore=%.2f%%, Severity=%s]",
                compromisedNode.getNodeId(), reachableAssets.size(), systemicRiskScore, riskSeverity);
    }
}