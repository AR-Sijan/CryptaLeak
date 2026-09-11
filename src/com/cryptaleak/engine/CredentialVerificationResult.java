package com.cryptaleak.engine;

import java.util.Objects;

/**
 * Project CryptaLeak - Credential Verification Item Result
 * 
 * Encapsulates the evaluation outcome for a single candidate credential in an async bulk scan.
 */
public class CredentialVerificationResult {

    public enum Status {
        SECURE,
        COMPROMISED,
        ERROR
    }

    private final String maskedCredential;
    private final String hashPrefix;
    private final Status status;
    private final String breachSource;
    private final int bucketCandidatesExamined;
    private final String userFriendlyMessage;
    private final long processingTimeMs;

    public CredentialVerificationResult(String maskedCredential, String hashPrefix, Status status,
                                        String breachSource, int bucketCandidatesExamined,
                                        String userFriendlyMessage, long processingTimeMs) {
        this.maskedCredential = Objects.requireNonNull(maskedCredential, "maskedCredential cannot be null");
        this.hashPrefix = hashPrefix != null ? hashPrefix : "N/A";
        this.status = Objects.requireNonNull(status, "status cannot be null");
        this.breachSource = breachSource;
        this.bucketCandidatesExamined = bucketCandidatesExamined;
        this.userFriendlyMessage = userFriendlyMessage != null ? userFriendlyMessage : "";
        this.processingTimeMs = processingTimeMs;
    }

    public static CredentialVerificationResult secure(String masked, String prefix, int candidates, long ms) {
        return new CredentialVerificationResult(
                masked, prefix, Status.SECURE, null, candidates, "Verified Clean: Zero matches in K-Anonymity bucket.", ms
        );
    }

    public static CredentialVerificationResult compromised(String masked, String prefix, String source, int candidates, long ms) {
        return new CredentialVerificationResult(
                masked, prefix, Status.COMPROMISED, source, candidates,
                String.format("BREACH CONFIRMED: Matched against %s threat feed.", source), ms
        );
    }

    public static CredentialVerificationResult error(String masked, String prefix, String friendlyErrorMessage, long ms) {
        return new CredentialVerificationResult(
                masked, prefix, Status.ERROR, null, 0, friendlyErrorMessage, ms
        );
    }

    public String getMaskedCredential() {
        return maskedCredential;
    }

    public String getHashPrefix() {
        return hashPrefix;
    }

    public Status getStatus() {
        return status;
    }

    public boolean isCompromised() {
        return status == Status.COMPROMISED;
    }

    public String getBreachSource() {
        return breachSource;
    }

    public int getBucketCandidatesExamined() {
        return bucketCandidatesExamined;
    }

    public String getUserFriendlyMessage() {
        return userFriendlyMessage;
    }

    public long getProcessingTimeMs() {
        return processingTimeMs;
    }

    @Override
    public String toString() {
        return String.format("Result[%s, Prefix=%s, Status=%s, Source='%s', Time=%dms]",
                maskedCredential, hashPrefix, status, breachSource, processingTimeMs);
    }
}