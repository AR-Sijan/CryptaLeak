package com.cryptaleak.engine;

/**
 * Project CryptaLeak - Asynchronous Scan Progress Listener
 * 
 * Callback contract for receiving thread-safe updates on the Java Swing UI thread.
 */
public interface ScanProgressListener {

    /**
     * Fired when an individual credential has completed verification.
     * Guaranteed to execute safely on the Swing Event Dispatch Thread (EDT).
     *
     * @param processedCount Number of items processed so far
     * @param totalCount     Total items in the batch
     * @param result         Detailed result for the item
     */
    void onProgressUpdate(int processedCount, int totalCount, CredentialVerificationResult result);

    /**
     * Fired when the entire bulk verification pipeline finishes.
     * Guaranteed to execute on the Swing EDT.
     *
     * @param summary Aggregated statistics
     */
    void onScanCompleted(BulkVerificationSummary summary);

    /**
     * Fired when a critical failure occurs (e.g. database disconnect, worker exhaustion).
     * Guaranteed to execute on the Swing EDT with user-friendly error details.
     *
     * @param userFriendlyMessage Formatted message suitable for display in a JOptionPane/JDialog
     * @param cause               Underlying exception (may be null)
     */
    void onError(String userFriendlyMessage, Throwable cause);
}