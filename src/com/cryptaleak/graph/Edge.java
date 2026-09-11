package com.cryptaleak.graph;

import java.util.Objects;

/**
 * Project CryptaLeak - Directed Access Edge
 * 
 * Represents an access authorization, credential dependency, or lateral network route
 * connecting a source Node to a target Node.
 */
public class Edge {

    private final Node source;
    private final Node target;
    private final String accessType;
    private final double accessMultiplier;

    public Edge(Node source, Node target, String accessType, double accessMultiplier) {
        this.source = Objects.requireNonNull(source, "source node cannot be null");
        this.target = Objects.requireNonNull(target, "target node cannot be null");
        this.accessType = (accessType != null && !accessType.trim().isEmpty()) ? accessType.trim().toUpperCase() : "STANDARD_ACCESS";
        this.accessMultiplier = Math.max(0.1, accessMultiplier);
    }

    public Edge(Node source, Node target, String accessType) {
        this(source, target, accessType, 1.0);
    }

    public Node getSource() {
        return source;
    }

    public Node getTarget() {
        return target;
    }

    public String getAccessType() {
        return accessType;
    }

    public double getAccessMultiplier() {
        return accessMultiplier;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Edge edge = (Edge) o;
        return Objects.equals(source, edge.source) &&
               Objects.equals(target, edge.target) &&
               Objects.equals(accessType, edge.accessType);
    }

    @Override
    public int hashCode() {
        return Objects.hash(source, target, accessType);
    }

    @Override
    public String toString() {
        return String.format("Edge[%s ---[%s (x%.1f)]---> %s]",
                source.getNodeId(), accessType, accessMultiplier, target.getNodeId());
    }
}