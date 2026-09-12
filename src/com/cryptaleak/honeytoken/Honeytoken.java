package com.cryptaleak.honeytoken;

import java.sql.Timestamp;
import java.util.Objects;

/**
 * Project CryptaLeak - Honeytoken / Canary Decoy Entity
 * 
 * Represents a decoy credential planted strategically across the organization
 * (in source code repos, staging configs, database dumps) to detect unauthorized intrusion.
 */
public class Honeytoken {

    public enum TokenType {
        AWS_ACCESS_KEY,
        DATABASE_PASSWORD,
        API_TOKEN,
        SERVICE_ACCOUNT_KEY
    }

    public enum Status {
        ACTIVE,
        TRIGGERED,
        CONTAINED
    }

    private final String canaryId;
    private final TokenType tokenType;
    private final String secretValue;
    private final String sha256Hash;
    private final String hashPrefix;
    private final String hashSuffix;
    private final String plantedLocation;
    private final Timestamp createdAt;
    private boolean triggered;
    private boolean contained;

    public Honeytoken(String canaryId, TokenType tokenType, String secretValue,
                      String sha256Hash, String hashPrefix, String hashSuffix,
                      String plantedLocation) {
        this.canaryId = Objects.requireNonNull(canaryId, "canaryId cannot be null");
        this.tokenType = Objects.requireNonNull(tokenType, "tokenType cannot be null");
        this.secretValue = Objects.requireNonNull(secretValue, "secretValue cannot be null");
        this.sha256Hash = Objects.requireNonNull(sha256Hash, "sha256Hash cannot be null");
        this.hashPrefix = Objects.requireNonNull(hashPrefix, "hashPrefix cannot be null");
        this.hashSuffix = Objects.requireNonNull(hashSuffix, "hashSuffix cannot be null");
        this.plantedLocation = Objects.requireNonNull(plantedLocation, "plantedLocation cannot be null");
        this.createdAt = new Timestamp(System.currentTimeMillis());
        this.triggered = false;
        this.contained = false;
    }

    public String getCanaryId() {
        return canaryId;
    }

    public TokenType getTokenType() {
        return tokenType;
    }

    public String getSecretValue() {
        return secretValue;
    }

    public String getSha256Hash() {
        return sha256Hash;
    }

    public String getHashPrefix() {
        return hashPrefix;
    }

    public String getHashSuffix() {
        return hashSuffix;
    }

    public String getPlantedLocation() {
        return plantedLocation;
    }

    public Timestamp getCreatedAt() {
        return createdAt;
    }

    public boolean isTriggered() {
        return triggered;
    }

    public void setTriggered(boolean triggered) {
        this.triggered = triggered;
    }

    public boolean isContained() {
        return contained;
    }

    public void setContained(boolean contained) {
        this.contained = contained;
    }

    public Status getStatus() {
        if (contained) return Status.CONTAINED;
        if (triggered) return Status.TRIGGERED;
        return Status.ACTIVE;
    }

    @Override
    public String toString() {
        return String.format("Honeytoken[%s (%s), Location='%s', Prefix=%s, Triggered=%b]",
                canaryId, tokenType, plantedLocation, hashPrefix, triggered);
    }
}