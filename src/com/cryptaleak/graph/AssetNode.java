package com.cryptaleak.graph;

import java.util.Objects;

/**
 * Project CryptaLeak - Organizational Asset Node
 * 
 * Represents high-value enterprise infrastructure:
 * Servers, Production Databases, Code Repositories, Domain Controllers, and Cloud Services.
 */
public class AssetNode extends Node {

    public enum AssetType {
        SERVER,
        DATABASE,
        REPOSITORY,
        DOMAIN_CONTROLLER,
        CLOUD_ROLE,
        API_KEY,
        OTHER
    }

    private final AssetType assetType;
    private final String endpoint;
    private final boolean containsSensitiveData;

    public AssetNode(String nodeId, String name, double riskWeight, boolean quarantined,
                     AssetType assetType, String endpoint, boolean containsSensitiveData) {
        super(nodeId, name, riskWeight, quarantined);
        this.assetType = Objects.requireNonNull(assetType, "assetType cannot be null");
        this.endpoint = (endpoint != null && !endpoint.trim().isEmpty()) ? endpoint.trim() : "internal://unspecified";
        this.containsSensitiveData = containsSensitiveData;
    }

    public AssetNode(String nodeId, String name, double riskWeight, boolean quarantined, AssetType assetType) {
        this(nodeId, name, riskWeight, quarantined, assetType, null, false);
    }

    public AssetType getAssetType() {
        return assetType;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public boolean isContainsSensitiveData() {
        return containsSensitiveData;
    }

    @Override
    public String getNodeCategory() {
        return "ASSET";
    }

    @Override
    public String getSpecificType() {
        return switch (assetType) {
            case DOMAIN_CONTROLLER -> "DOMAIN_CONTROLLER";
            case DATABASE -> "DATABASE_CLUSTER";
            case SERVER -> "SERVICE_ACCOUNT";
            case CLOUD_ROLE -> "CLOUD_IAM_ROLE";
            case API_KEY -> "API_KEY";
            default -> "SERVICE_ACCOUNT";
        };
    }

    @Override
    public String toString() {
        return String.format("AssetNode[%s: '%s', Type=%s, Endpoint='%s', Weight=%.1f, Sensitive=%b]",
                nodeId, name, assetType, endpoint, riskWeight, containsSensitiveData);
    }
}