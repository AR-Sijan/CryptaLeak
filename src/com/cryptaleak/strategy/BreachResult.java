package com.cryptaleak.strategy;

/**
 * Encapsulates the evaluation result of a K-Anonymity breach lookup.
 */
public final class BreachResult {
    private final boolean compromised;
    private final String hashPrefix;
    private final String matchedSuffix;
    private final String breachSource;
    private final int totalCandidatesReceived;

    public BreachResult(boolean compromised, String hashPrefix, String matchedSuffix, String breachSource, int totalCandidatesReceived) {
        this.compromised = compromised;
        this.hashPrefix = hashPrefix;
        this.matchedSuffix = matchedSuffix;
        this.breachSource = breachSource;
        this.totalCandidatesReceived = totalCandidatesReceived;
    }

    public static BreachResult clean(String hashPrefix, int totalCandidatesReceived) {
        return new BreachResult(false, hashPrefix, null, null, totalCandidatesReceived);
    }

    public static BreachResult breached(String hashPrefix, String matchedSuffix, String breachSource, int totalCandidatesReceived) {
        return new BreachResult(true, hashPrefix, matchedSuffix, breachSource, totalCandidatesReceived);
    }

    public boolean isCompromised() {
        return compromised;
    }

    public String getHashPrefix() {
        return hashPrefix;
    }

    public String getMatchedSuffix() {
        return matchedSuffix;
    }

    public String getBreachSource() {
        return breachSource;
    }

    public int getTotalCandidatesReceived() {
        return totalCandidatesReceived;
    }

    @Override
    public String toString() {
        if (compromised) {
            return String.format("BreachResult[STATUS=COMPROMISED, Prefix=%s, Source=%s, BucketCandidates=%d]",
                    hashPrefix, breachSource, totalCandidatesReceived);
        } else {
            return String.format("BreachResult[STATUS=SECURE, Prefix=%s, BucketCandidates=%d]",
                    hashPrefix, totalCandidatesReceived);
        }
    }
}