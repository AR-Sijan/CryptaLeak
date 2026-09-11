package com.cryptaleak.graph;

import com.cryptaleak.db.DatabaseConnection;

import java.sql.SQLException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Project CryptaLeak - In-Memory Threat Relationship Graph
 * 
 * Implemented using pure Java OOP constructs without external graph libraries.
 * Maintains an in-memory adjacency list: Map<Node, List<Edge>>.
 * 
 * Capabilities:
 * 1. Loads topological identity/asset nodes and JSON adjacencies from MySQL identity_nodes table.
 * 2. Executes Breadth-First Search (BFS) blast-radius traversal starting from compromised employees.
 * 3. Computes a dynamic organizational Risk Score (0-100%) incorporating:
 *    - Node privilege weights
 *    - Edge hops / distance decay
 *    - Structural adjacency / centrality leverage
 */
public class IdentityGraph {

    private static final Logger LOGGER = Logger.getLogger(IdentityGraph.class.getName());

    // Core In-Memory Graph Data Structures
    private final Map<Node, List<Edge>> adjacencyList = new HashMap<>();
    private final Map<String, Node> nodeRegistry = new HashMap<>();

    public IdentityGraph() {
    }

    // =========================================================================
    // GRAPH MUTATION & ACCESSORS
    // =========================================================================

    public synchronized void addNode(Node node) {
        Objects.requireNonNull(node, "Node cannot be null");
        nodeRegistry.put(node.getNodeId(), node);
        adjacencyList.putIfAbsent(node, new ArrayList<>());
    }

    public synchronized void addEdge(Edge edge) {
        Objects.requireNonNull(edge, "Edge cannot be null");
        addNode(edge.getSource());
        addNode(edge.getTarget());
        List<Edge> edges = adjacencyList.get(edge.getSource());
        if (!edges.contains(edge)) {
            edges.add(edge);
        }
    }

    public synchronized void addEdge(Node source, Node target, String accessType, double weight) {
        addEdge(new Edge(source, target, accessType, weight));
    }

    public synchronized Node getNode(String nodeId) {
        return nodeRegistry.get(nodeId);
    }

    public synchronized List<Node> getAllNodes() {
        return Collections.unmodifiableList(new ArrayList<>(nodeRegistry.values()));
    }

    public synchronized List<Edge> getOutgoingEdges(Node node) {
        return Collections.unmodifiableList(adjacencyList.getOrDefault(node, Collections.emptyList()));
    }

    public synchronized int getNodeCount() {
        return nodeRegistry.size();
    }

    public synchronized int getEdgeCount() {
        return adjacencyList.values().stream().mapToInt(List::size).sum();
    }

    public synchronized void clear() {
        adjacencyList.clear();
        nodeRegistry.clear();
    }

    // =========================================================================
    // DATABASE LOADING (FROM identity_nodes TABLE AT STARTUP)
    // =========================================================================

    private static final String SELECT_NODES_SQL = 
            "SELECT node_id, node_type, name, risk_weight, adjacent_nodes_json, is_quarantined FROM identity_nodes";

    /**
     * Loads graph topology from MySQL identity_nodes table at startup.
     *
     * @param db DatabaseConnection singleton instance
     * @throws SQLException on database access error
     */
    public synchronized void loadFromDatabase(DatabaseConnection db) throws SQLException {
        LOGGER.info("[CryptaLeak Graph] Loading identity nodes and topologies from database...");
        clear();

        // Temporary storage for raw adjacency JSON to resolve in pass 2
        Map<String, String> rawAdjacencyMap = new HashMap<>();

        // PASS 1: Reconstruct Nodes from Database
        db.executeQuery(SELECT_NODES_SQL, rs -> {
            while (rs.next()) {
                String nodeId = rs.getString("node_id");
                String nodeType = rs.getString("node_type");
                String name = rs.getString("name");
                double riskWeight = rs.getDouble("risk_weight");
                String adjacentJson = rs.getString("adjacent_nodes_json");
                boolean isQuarantined = rs.getBoolean("is_quarantined");

                Node node = instantiateNode(nodeId, nodeType, name, riskWeight, isQuarantined);
                addNode(node);

                if (adjacentJson != null && !adjacentJson.trim().isEmpty()) {
                    rawAdjacencyMap.put(nodeId, adjacentJson);
                }
            }
            return null;
        });

        // PASS 2: Reconstruct Edges from JSON adjacency lists
        int loadedEdges = 0;
        for (Map.Entry<String, String> entry : rawAdjacencyMap.entrySet()) {
            String sourceId = entry.getKey();
            Node sourceNode = nodeRegistry.get(sourceId);
            if (sourceNode == null) continue;

            List<ParsedEdgeRecord> parsedEdges = parseAdjacencyJson(entry.getValue());
            for (ParsedEdgeRecord pe : parsedEdges) {
                Node targetNode = nodeRegistry.get(pe.targetId());
                if (targetNode != null) {
                    addEdge(new Edge(sourceNode, targetNode, pe.accessType(), pe.weight()));
                    loadedEdges++;
                } else {
                    LOGGER.log(Level.FINE, "[CryptaLeak Graph] Target node not found: " + pe.targetId());
                }
            }
        }

        LOGGER.info(String.format("[CryptaLeak Graph] Initialization complete: %d nodes, %d edges loaded.",
                nodeRegistry.size(), loadedEdges));
    }

    /**
     * Factory method mapping database record to specialized EmployeeNode or AssetNode.
     */
    private Node instantiateNode(String id, String type, String name, double riskWeight, boolean quarantined) {
        String upperType = (type != null) ? type.trim().toUpperCase() : "SERVICE_ACCOUNT";

        if ("DOMAIN_USER".equals(upperType) || id.toUpperCase().startsWith("EMP")) {
            return new EmployeeNode(id, name, riskWeight, quarantined);
        }

        AssetNode.AssetType assetType = switch (upperType) {
            case "DOMAIN_CONTROLLER" -> AssetNode.AssetType.DOMAIN_CONTROLLER;
            case "DATABASE_CLUSTER"  -> AssetNode.AssetType.DATABASE;
            case "CLOUD_IAM_ROLE"    -> AssetNode.AssetType.CLOUD_ROLE;
            case "API_KEY"           -> AssetNode.AssetType.API_KEY;
            case "REPOSITORY"        -> AssetNode.AssetType.REPOSITORY;
            default                  -> AssetNode.AssetType.SERVER;
        };

        return new AssetNode(id, name, riskWeight, quarantined, assetType);
    }

    // =========================================================================
    // BFS BLAST-RADIUS TRAVERSAL ALGORITHM
    // =========================================================================

    /**
     * Executes a Breadth-First Search (BFS) blast-radius traversal starting from
     * any compromised employee node to discover all downstream reachable assets.
     *
     * @param employeeNodeId Node ID of the compromised employee
     * @return BlastRadiusResult containing discovered assets, hop paths, and dynamic risk score
     */
    public synchronized BlastRadiusResult calculateBlastRadius(String employeeNodeId) {
        Node startNode = getNode(employeeNodeId);
        if (startNode == null) {
            throw new IllegalArgumentException("Node ID not found in graph: " + employeeNodeId);
        }
        if (!(startNode instanceof EmployeeNode)) {
            throw new IllegalArgumentException("Starting node must be an EmployeeNode, got: " + startNode.getClass().getSimpleName());
        }

        return calculateBlastRadius((EmployeeNode) startNode);
    }

    /**
     * Core BFS blast-radius implementation.
     *
     * @param startEmployee Compromised starting employee
     * @return BlastRadiusResult telemetry
     */
    public synchronized BlastRadiusResult calculateBlastRadius(EmployeeNode startEmployee) {
        Objects.requireNonNull(startEmployee, "Starting employee cannot be null");

        // BFS Tracking Structures
        Queue<Node> queue = new ArrayDeque<>();
        Set<Node> visited = new HashSet<>();
        Map<Node, Integer> hopDistances = new HashMap<>();
        Map<Node, List<Edge>> attackPaths = new HashMap<>();
        List<AssetNode> reachableAssets = new ArrayList<>();

        // Initialize BFS from starting employee
        visited.add(startEmployee);
        queue.add(startEmployee);
        hopDistances.put(startEmployee, 0);
        attackPaths.put(startEmployee, new ArrayList<>());

        while (!queue.isEmpty()) {
            Node current = queue.poll();
            int currentDistance = hopDistances.get(current);

            // If an asset node was reached, record it
            if (current instanceof AssetNode && current != startEmployee) {
                reachableAssets.add((AssetNode) current);
            }

            // Containment Boundary: If an intermediate node is quarantined, halt lateral expansion through it
            if (current.isQuarantined() && current != startEmployee) {
                LOGGER.info("[CryptaLeak Containment] Quarantined node encountered: " + current.getNodeId() + ". Halting deeper traversal.");
                continue;
            }

            // Explore adjacent outgoing edges
            List<Edge> edges = adjacencyList.getOrDefault(current, Collections.emptyList());
            for (Edge edge : edges) {
                Node neighbor = edge.getTarget();

                if (!visited.contains(neighbor)) {
                    visited.add(neighbor);
                    hopDistances.put(neighbor, currentDistance + 1);

                    // Reconstruct lateral path
                    List<Edge> currentPath = attackPaths.get(current);
                    List<Edge> neighborPath = new ArrayList<>(currentPath);
                    neighborPath.add(edge);
                    attackPaths.put(neighbor, neighborPath);

                    queue.add(neighbor);
                }
            }
        }

        // Calculate dynamic organizational Risk Score (0-100%)
        double riskScore = computeSystemicRiskScore(startEmployee, reachableAssets, hopDistances, attackPaths);

        return new BlastRadiusResult(startEmployee, reachableAssets, hopDistances, attackPaths, riskScore);
    }

    // =========================================================================
    // DYNAMIC ORGANIZATIONAL RISK SCORE FORMULA (0 - 100%)
    // =========================================================================

    /**
     * Calculates the systemic organizational Risk Score based on:
     * 1. Node privilege weight (P_i): Base criticality of reached assets (1.0 to 100.0)
     * 2. Edge hops / distance decay (D_i): Attenuation factor D_i = 1.0 / (1.0 + 0.4 * (hops - 1))
     * 3. Structural adjacency / centrality (S_i): Out-degree centrality S_i = 1.0 + min(1.0, 0.15 * outDegree)
     * 4. Edge access multiplier (M_i): Privilege level (Admin/Root = 1.5, Write = 1.2, Read = 0.8)
     *
     * Total risk is saturated into a smooth [0.0% to 100.0%] percentage using an exponential saturation curve.
     */
    private double computeSystemicRiskScore(EmployeeNode startEmployee,
                                            List<AssetNode> reachableAssets,
                                            Map<Node, Integer> hopDistances,
                                            Map<Node, List<Edge>> attackPaths) {
        if (reachableAssets.isEmpty()) {
            // Minimal baseline risk based solely on employee's base weight
            return Math.min(15.0, startEmployee.getRiskWeight() * 0.15);
        }

        double totalRawRisk = 0.0;

        for (AssetNode asset : reachableAssets) {
            int hops = hopDistances.getOrDefault(asset, 1);
            if (hops < 1) hops = 1;

            // 1. Node Privilege Weight
            double nodePrivilege = asset.getRiskWeight();

            // 2. Edge Hops / Distance Decay (Immediate hops have full impact, decaying smoothly with distance)
            double distanceDecay = 1.0 / (1.0 + 0.4 * (hops - 1));

            // 3. Structural Adjacency (Assets that pivot to many downstream nodes amplify the blast radius)
            int outDegree = adjacencyList.getOrDefault(asset, Collections.emptyList()).size();
            double structuralCentrality = 1.0 + Math.min(1.0, 0.15 * outDegree);

            // 4. Inbound Edge Access Multiplier
            double edgeMultiplier = 1.0;
            List<Edge> path = attackPaths.get(asset);
            if (path != null && !path.isEmpty()) {
                Edge lastEdge = path.get(path.size() - 1);
                edgeMultiplier = lastEdge.getAccessMultiplier();
            }

            // Asset Threat Contribution
            double assetRiskContribution = nodePrivilege * distanceDecay * structuralCentrality * edgeMultiplier;
            totalRawRisk += assetRiskContribution;
        }

        // Incorporate initial employee compromise weight
        double employeeOriginRisk = startEmployee.getRiskWeight() * 0.25;
        double aggregateScore = totalRawRisk + employeeOriginRisk;

        // Exponential saturation curve mapping smoothly and deterministically to [0.0%, 100.0%]
        // Score approaches 100% as cumulative high-value assets and pivot servers are reached.
        double normalizedScore = 100.0 * (1.0 - Math.exp(-aggregateScore / 220.0));

        // Format to 2 decimal places
        return Math.round(normalizedScore * 100.0) / 100.0;
    }

    // =========================================================================
    // BUILT-IN PURE JAVA JSON PARSER (NO THIRD-PARTY LIBRARIES)
    // =========================================================================

    private record ParsedEdgeRecord(String targetId, String accessType, double weight) {}

    /**
     * Parses standard JSON array of edge objects or ID strings without external libraries:
     * Format A: [{"targetId": "SRV-01", "accessType": "SSH_ROOT", "weight": 1.5}, ...]
     * Format B: [{"target": "DB-PROD", "access": "READ", "weight": 0.8}, ...]
     * Format C: ["SRV-01", "DB-PROD"]
     */
    public static List<ParsedEdgeRecord> parseAdjacencyJson(String json) {
        List<ParsedEdgeRecord> list = new ArrayList<>();
        if (json == null || json.trim().isEmpty()) {
            return list;
        }

        // Try matching JSON objects { ... }
        Pattern objectPattern = Pattern.compile("\\{([^}]+)\\}");
        Matcher objMatcher = objectPattern.matcher(json);

        while (objMatcher.find()) {
            String block = objMatcher.group(1);

            String targetId = extractJsonString(block, "targetId", "target", "node_id", "id");
            String accessType = extractJsonString(block, "accessType", "access", "relation", "type");
            double weight = extractJsonDouble(block, "weight", 1.0);

            if (targetId != null && !targetId.trim().isEmpty()) {
                list.add(new ParsedEdgeRecord(
                        targetId.trim(),
                        accessType != null ? accessType.trim() : "STANDARD_ACCESS",
                        weight
                ));
            }
        }

        // Fallback: array of strings ["ID_1", "ID_2"]
        if (list.isEmpty()) {
            Pattern arrayItemPattern = Pattern.compile("\"([^\"]+)\"");
            Matcher arrayMatcher = arrayItemPattern.matcher(json);
            while (arrayMatcher.find()) {
                String id = arrayMatcher.group(1).trim();
                if (!id.isEmpty()) {
                    list.add(new ParsedEdgeRecord(id, "STANDARD_ACCESS", 1.0));
                }
            }
        }

        return list;
    }

    private static String extractJsonString(String block, String... keys) {
        for (String key : keys) {
            Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]+)\"");
            Matcher m = p.matcher(block);
            if (m.find()) {
                return m.group(1);
            }
        }
        return null;
    }

    private static double extractJsonDouble(String block, String key, double defaultVal) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*([0-9]+(?:\\.[0-9]+)?)");
        Matcher m = p.matcher(block);
        if (m.find()) {
            try {
                return Double.parseDouble(m.group(1));
            } catch (NumberFormatException ignored) {
            }
        }
        return defaultVal;
    }
}