package com.cryptaleak.engine;

import com.cryptaleak.crypto.CryptoService;
import com.cryptaleak.crypto.HashSplit;
import com.cryptaleak.strategy.BreachResult;
import com.cryptaleak.strategy.KAnonymitySearchStrategy;

import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Project CryptaLeak - Asynchronous Bulk Credential Verification SwingWorker
 * 
 * Executes high-throughput K-Anonymity verification across a thread pool
 * without blocking the Swing Event Dispatch Thread (EDT).
 * 
 * Integrates:
 * - 5-char prefix extraction
 * - Concurrent database lookups
 * - Local constant-time suffix comparisons
 * - Safe EDT status callbacks via publish()/process() and SwingUtilities.invokeLater
 * - Graceful fault-tolerant exception handling for database disconnects
 */
public class BulkCredentialSwingWorker extends SwingWorker<BulkVerificationSummary, CredentialVerificationResult> {

    private static final Logger LOGGER = Logger.getLogger(BulkCredentialSwingWorker.class.getName());

    private final List<String> credentials;
    private final KAnonymitySearchStrategy searchStrategy;
    private final CryptoService cryptoService;
    private final ExecutorService workerPool;
    private final ScanProgressListener progressListener;

    private final AtomicInteger processedCounter = new AtomicInteger(0);
    private final List<CredentialVerificationResult> aggregatedResults = new ArrayList<>();

    public BulkCredentialSwingWorker(List<String> credentials,
                                     KAnonymitySearchStrategy searchStrategy,
                                     CryptoService cryptoService,
                                     ExecutorService workerPool,
                                     ScanProgressListener progressListener) {
        this.credentials = Objects.requireNonNull(credentials, "credentials list cannot be null");
        this.searchStrategy = Objects.requireNonNull(searchStrategy, "searchStrategy cannot be null");
        this.cryptoService = Objects.requireNonNull(cryptoService, "cryptoService cannot be null");
        this.workerPool = Objects.requireNonNull(workerPool, "workerPool cannot be null");
        this.progressListener = progressListener;
    }

    /**
     * Executes entirely on a background worker thread. UI remains 100% responsive.
     */
    @Override
    protected BulkVerificationSummary doInBackground() throws Exception {
        long startTime = System.currentTimeMillis();
        int total = credentials.size();
        LOGGER.info(String.format("[BulkSwingWorker] Initiating concurrent verification of %d credentials...", total));

        List<Future<CredentialVerificationResult>> futures = new ArrayList<>(total);

        // Dispatch concurrent sub-tasks across ExecutorService worker pool
        for (int i = 0; i < total; i++) {
            final String rawCredential = credentials.get(i);
            final int index = i;

            Callable<CredentialVerificationResult> task = () -> {
                if (isCancelled()) {
                    return null;
                }
                long itemStart = System.currentTimeMillis();
                String masked = maskCredential(rawCredential);
                String prefix = "UNKNOWN";

                try {
                    // 1. Client-Side 5-Character Prefix Extraction
                    HashSplit split = cryptoService.splitCredential(rawCredential);
                    prefix = split.getPrefix();

                    // 2. Query MySQL bucket & 3. Local constant-time suffix comparison
                    BreachResult breachResult = searchStrategy.checkCredential(rawCredential);
                    long duration = System.currentTimeMillis() - itemStart;

                    if (breachResult.isCompromised()) {
                        return CredentialVerificationResult.compromised(
                                masked, prefix, breachResult.getBreachSource(),
                                breachResult.getTotalCandidatesReceived(), duration
                        );
                    } else {
                        return CredentialVerificationResult.secure(
                                masked, prefix, breachResult.getTotalCandidatesReceived(), duration
                        );
                    }

                } catch (SQLException sqlEx) {
                    // Graceful database disconnection handling: do NOT crash JVM
                    long duration = System.currentTimeMillis() - itemStart;
                    LOGGER.log(Level.WARNING, String.format("[BulkSwingWorker] Database access error for item #%d: %s",
                            index, sqlEx.getMessage()));

                    String friendlyMsg = "Database Connection Warning: Unable to query K-Anonymity bucket. " +
                            "Verify that MySQL service is running on port 3306.";
                    return CredentialVerificationResult.error(masked, prefix, friendlyMsg, duration);

                } catch (Exception ex) {
                    long duration = System.currentTimeMillis() - itemStart;
                    LOGGER.log(Level.SEVERE, String.format("[BulkSwingWorker] Processing error on item #%d", index), ex);
                    return CredentialVerificationResult.error(masked, prefix, "Unexpected Error: " + ex.getMessage(), duration);
                }
            };

            futures.add(workerPool.submit(task));
        }

        // Collect results as futures complete and publish them to EDT
        int compromisedCount = 0;
        int secureCount = 0;
        int errorCount = 0;

        for (Future<CredentialVerificationResult> future : futures) {
            if (isCancelled()) {
                LOGGER.info("[BulkSwingWorker] Operation cancelled by user.");
                break;
            }

            try {
                // Await sub-task result
                CredentialVerificationResult res = future.get(30, TimeUnit.SECONDS);
                if (res != null) {
                    aggregatedResults.add(res);

                    if (res.getStatus() == CredentialVerificationResult.Status.COMPROMISED) {
                        compromisedCount++;
                    } else if (res.getStatus() == CredentialVerificationResult.Status.SECURE) {
                        secureCount++;
                    } else {
                        errorCount++;
                    }

                    // Publishes result to process() on the Swing Event Dispatch Thread (EDT)
                    publish(res);
                }
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "[BulkSwingWorker] Sub-task timeout or execution error: " + e.getMessage());
                errorCount++;
            }
        }

        long totalDuration = System.currentTimeMillis() - startTime;
        LOGGER.info(String.format("[BulkSwingWorker] Verification pipeline finished in %dms. Leaked: %d, Clean: %d, Errors: %d",
                totalDuration, compromisedCount, secureCount, errorCount));

        return new BulkVerificationSummary(
                total,
                aggregatedResults.size(),
                compromisedCount,
                secureCount,
                errorCount,
                totalDuration,
                aggregatedResults
        );
    }

    /**
     * Executes safely on the Swing Event Dispatch Thread (EDT).
     * Updates progress bars, tables, or listeners in real-time without UI lag.
     */
    @Override
    protected void process(List<CredentialVerificationResult> chunks) {
        if (progressListener == null) return;

        int total = credentials.size();
        for (CredentialVerificationResult result : chunks) {
            int current = processedCounter.incrementAndGet();
            try {
                progressListener.onProgressUpdate(current, total, result);
            } catch (Exception ex) {
                LOGGER.log(Level.WARNING, "[BulkSwingWorker] Listener error in process(): " + ex.getMessage());
            }
        }
    }

    /**
     * Executes safely on the Swing Event Dispatch Thread (EDT) upon completion or failure.
     */
    @Override
    protected void done() {
        if (progressListener == null) return;

        try {
            if (isCancelled()) {
                progressListener.onError("Bulk verification was cancelled by the user.", null);
                return;
            }

            BulkVerificationSummary summary = get();
            progressListener.onScanCompleted(summary);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            progressListener.onError("Verification pipeline was interrupted.", e);

        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            String userMsg = "A backend processing error occurred during verification: " +
                    (cause != null ? cause.getMessage() : e.getMessage());
            LOGGER.log(Level.SEVERE, "[BulkSwingWorker] Pipeline failure in done()", cause != null ? cause : e);
            progressListener.onError(userMsg, cause);

        } catch (CancellationException e) {
            progressListener.onError("Verification scan was cancelled.", e);
        }
    }

    /**
     * Helper to mask sensitive input (e.g. "P@ssword123!" -> "P@ss****!").
     */
    private static String maskCredential(String raw) {
        if (raw == null || raw.isEmpty()) return "[EMPTY]";
        if (raw.length() <= 4) return "****";
        return raw.substring(0, 2) + "****" + raw.substring(raw.length() - 2);
    }
}