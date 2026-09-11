package com.cryptaleak.crypto;

import java.util.Objects;

/**
 * Encapsulates a cryptographic hash split according to the K-Anonymity privacy model.
 * - prefix: 5 hexadecimal characters sent over the network to query candidate buckets.
 * - suffix: Remaining characters retained on client side for privacy-preserving verification.
 */
public final class HashSplit {
    private final String fullHash;
    private final String prefix;
    private final String suffix;

    public HashSplit(String fullHash, String prefix, String suffix) {
        this.fullHash = Objects.requireNonNull(fullHash, "fullHash cannot be null");
        this.prefix = Objects.requireNonNull(prefix, "prefix cannot be null");
        this.suffix = Objects.requireNonNull(suffix, "suffix cannot be null");
    }

    public String getFullHash() {
        return fullHash;
    }

    public String getPrefix() {
        return prefix;
    }

    public String getSuffix() {
        return suffix;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        HashSplit hashSplit = (HashSplit) o;
        return fullHash.equalsIgnoreCase(hashSplit.fullHash);
    }

    @Override
    public int hashCode() {
        return fullHash.toUpperCase().hashCode();
    }

    @Override
    public String toString() {
        return "HashSplit[prefix=" + prefix + ", suffixLen=" + suffix.length() + "]";
    }
}