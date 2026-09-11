package com.cryptaleak.engine;

import com.cryptaleak.crypto.CryptoService;
import com.cryptaleak.db.DatabaseConnection;
import com.cryptaleak.strategy.KAnonymitySearchStrategy;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Project CryptaLeak - Multi-Threaded Backend Processing Engine
 * 
 * Orchestrates high-throughput, concurrent K-Anonymity credential verification
 * using built-in java.util.concurrent.ExecutorService and javax.swing.SwingWorker.
 * 
 * Features:
 * - Thread pool sized for optimal I/O and cryptographic hashing concurrency
 * - Asynchronous execution pipeline preventing UI freezes
 * - Graceful shutdown and worker lifecycle management
 */
public class CredentialVerificationEngine implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(CredentialVerificationEngine.class.getName());

    private static final int DEFAULT_THREAD_COUNT = Math.max(4, Runtime.getRuntime().availableProcessors() * 2);

    private final ExecutorService executorPool;
    private final KAnonymitySearchStrategy searchStrategy;
    private final CryptoService cryptoService;

    public CredentialVerificationEngine() {
        this(DatabaseConnection.getInstance(), new CryptoService(), DEFAULT_THREAD_COUNT);
    }

    public CredentialVerificationEngine(DatabaseConnection db, CryptoService cryptoService, int threadCount) {
        Objects.requireNonNull(db, "DatabaseConnection cannot be null");
        this.cryptoService = Objects.requireNonNull(cryptoService, "CryptoService cannot be null");
        this.searchStrategy = new KAnonymitySearchStrategy(db, cryptoService);

        this.executorPool = Executors.newFixedThreadPool(threadCount, r -> {
            Thread t = new Thread(r, "CryptaLeak-WorkerPool");
            t.setDaemon(true);
            return t;
        });

        LOGGER.info(String.format("[VerificationEngine] Initialized with %d concurrent worker threads.", threadCount));
    }

    /**
     * Submits a bulk list of credentials for asynchronous verification.
     * Starts the SwingWorker background pipeline immediately.
     *
     * @param credentials List of raw credentials or passwords to inspect
     * @param listener    Callback listener for real-time EDT UI progress
     * @return Running BulkCredentialSwingWorker instance (allows user cancellation)
     */
    public BulkCredentialSwingWorker submitBulkScan(List<String> credentials, ScanProgressListener listener) {
        Objects.requireNonNull(credentials, "credentials list cannot be null");

        BulkCredentialSwingWorker worker = new BulkCredentialSwingWorker(
                credentials,
                searchStrategy,
                cryptoService,
                executorPool,
                listener
        );

        // Dispatches the worker to Swing's internal worker pool
        worker.execute();
        return worker;
    }

    /**
     * Shuts down the backend executor service gracefully.
     */
    public void shutdown() {
        LOGGER.info("[VerificationEngine] Shutting down worker executor pool...");
        executorPool.shutdown();
        try {
            if (!executorPool.awaitTermination(3, TimeUnit.SECONDS)) {
                executorPool.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorPool.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public void close() {
        shutdown();
    }
}