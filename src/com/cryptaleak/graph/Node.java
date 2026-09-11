package com.cryptaleak.graph;

import java.util.Objects;

/**
 * Project CryptaLeak - Base Graph Node
 * 
 * Abstract base class representing an entity in the Threat Relationship Graph.
 * Enforces ID-based equality and hashing for adjacency list integrity.
 */
public abstract class Node {

    protected final String nodeId;
    protected final String name;
    protected double riskWeight;
    protected boolean quarantined;

    public Node(String nodeId, String name, double riskWeight, boolean quarantined) {
        this.nodeId = Objects.requireNonNull(nodeId, "nodeId cannot be null");
        this.name = Objects.requireNonNull(name, "name cannot be null");
        this.riskWeight = Math.max(1.0, Math.min(100.0, riskWeight));
        this.quarantined = quarantined;
    }

    public String getNodeId() {
        return nodeId;
    }

    public String getName() {
        return name;
    }

    public double getRiskWeight() {
        return riskWeight;
    }

    public void setRiskWeight(double riskWeight) {
        this.riskWeight = Math.max(1.0, Math.min(100.0, riskWeight));
    }

    public boolean isQuarantined() {
        return quarantined;
    }

    public void setQuarantined(boolean quarantined) {
        this.quarantined = quarantined;
    }

    /**
     * Returns the high-level category of this node (e.g. EMPLOYEE or ASSET).
     */
    public abstract String getNodeCategory();

    /**
     * Specific type string matching the database schema (e.g. DOMAIN_USER, DATABASE_CLUSTER).
     */
    public abstract String getSpecificType();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || !(o instanceof Node)) return false;
        Node node = (Node) o;
        return Objects.equals(nodeId, node.nodeId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(nodeId);
    }

    @Override
    public String toString() {
        return String.format("%s[%s: '%s', Weight=%.1f, Quarantined=%b]",
                getClass().getSimpleName(), nodeId, name, riskWeight, quarantined);
    }
}