package com.cryptaleak.strategy;

import java.sql.SQLException;

/**
 * Strategy interface for checking credential exposure and breach intelligence.
 */
public interface SearchStrategy {

    /**
     * Inspects a plaintext credential using a privacy-preserving mechanism.
     *
     * @param plainCredential Raw credential or password
     * @return BreachResult with exposure telemetry
     * @throws SQLException if database interaction fails
     */
    BreachResult checkCredential(String plainCredential) throws SQLException;

    /**
     * Inspects a precomputed cryptographic hash.
     *
     * @param fullHash 64-character SHA-256 hexadecimal hash
     * @return BreachResult with exposure telemetry
     * @throws SQLException if database interaction fails
     */
    BreachResult checkHash(String fullHash) throws SQLException;

    /**
     * Quick boolean check determining if a credential is compromised.
     */
    default boolean isCompromised(String plainCredential) throws SQLException {
        return checkCredential(plainCredential).isCompromised();
    }
}