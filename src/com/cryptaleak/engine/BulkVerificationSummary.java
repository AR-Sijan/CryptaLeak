package com.cryptaleak.engine;

import java.util.Collections;
import java.util.List;

/**
 * Project CryptaLeak - Bulk Verification Summary
 * 
 * Aggregated report returned upon completion of an async bulk scan.
 */
public class BulkVerificationSummary {

    private final int totalSubmitted;
    private final int totalProcessed;
    private final int totalCompromised;
    private final int totalSecure;
    private final int totalErrors;
    private final long totalDurationMs;
    private final List<CredentialVerificationResult> results;

    public BulkVerificationSummary(int totalSubmitted, int totalProcessed, int totalCompromised,
                                   int totalSecure, int totalErrors, long totalDurationMs,
                                   List<CredentialVerificationResult> results) {
        this.totalSubmitted = totalSubmitted;
        this.totalProcessed = totalProcessed;
        this.totalCompromised = totalCompromised;
        this.totalSecure = totalSecure;
        this.totalErrors = totalErrors;
        this.totalDurationMs = totalDurationMs;
        this.results = results != null ? Collections.unmodifiableList(results) : Collections.emptyList();
    }

    public int getTotalSubmitted() {
        return totalSubmitted;
    }

    public int getTotalProcessed() {
        return totalProcessed;
    }

    public int getTotalCompromised() {
        return totalCompromised;
    }

    public int getTotalSecure() {
        return totalSecure;
    }

    public int getTotalErrors() {
        return totalErrors;
    }

    public long getTotalDurationMs() {
        return totalDurationMs;
    }

    public List<CredentialVerificationResult> getResults() {
        return results;
    }

    public double getCompromiseRatePercentage() {
        if (totalProcessed == 0) return 0.0;
        return (double) totalCompromised / totalProcessed * 100.0;
    }

    @Override
    public String toString() {
        return String.format("BulkSummary[Submitted=%d, Processed=%d, Leaked=%d (%.1f%%), Clean=%d, Errors=%d, Time=%dms]",
                totalSubmitted, totalProcessed, totalCompromised, getCompromiseRatePercentage(),
                totalSecure, totalErrors, totalDurationMs);
    }
}