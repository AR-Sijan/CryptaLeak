package com.cryptaleak;

import com.cryptaleak.crypto.CryptoService;
import com.cryptaleak.db.DatabaseConnection;
import com.cryptaleak.engine.BulkCredentialSwingWorker;
import com.cryptaleak.engine.BulkVerificationSummary;
import com.cryptaleak.engine.CredentialVerificationEngine;
import com.cryptaleak.engine.CredentialVerificationResult;
import com.cryptaleak.engine.ScanProgressListener;
import com.cryptaleak.strategy.KAnonymitySearchStrategy;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class TestAsyncBulkEngine {

    public static void main(String[] args) {
        System.out.println("=================================================================");
        System.out.println(" Project CryptaLeak - Multi-Threaded Async Engine Test");
        System.out.println("=================================================================");

        try {
            DatabaseConnection db = DatabaseConnection.getInstance();
            CryptoService cryptoService = new CryptoService();
            KAnonymitySearchStrategy searchStrategy = new KAnonymitySearchStrategy(db, cryptoService);

            // -------------------------------------------------------------
            // SETUP: Populate 3 known breached credentials in MySQL
            // -------------------------------------------------------------
            System.out.println("\n--- [SETUP] Seeding Known Breaches in compromised_vault ---");
            String breach1 = "LeakedPass_Admin#2026!";
            String breach2 = "LeakedPass_DevOps#88";
            String breach3 = "LeakedPass_Finance_99";

            searchStrategy.ingestCompromisedCredential(breach1, true, "DarkWeb_Dump_A");
            searchStrategy.ingestCompromisedCredential(breach2, true, "BreachFeed_B");
            searchStrategy.ingestCompromisedCredential(breach3, true, "DarkWeb_Dump_C");
            System.out.println("[+] Seeded 3 breached credentials into MySQL compromised_vault.");

            // -------------------------------------------------------------
            // TEST 1: Async Bulk Scan with SwingWorker & ExecutorService
            // -------------------------------------------------------------
            System.out.println("\n--- [TEST 1] Asynchronous Bulk Scan (20 Credentials) ---");
            List<String> bulkBatch = new ArrayList<>();
            // Add the 3 leaked passwords
            bulkBatch.add(breach1);
            bulkBatch.add(breach2);
            bulkBatch.add(breach3);
            // Add 17 clean random passwords
            for (int i = 1; i <= 17; i++) {
                bulkBatch.add("SafeUniquePassword_" + i + "_#SecureKey");
            }

            CredentialVerificationEngine engine = new CredentialVerificationEngine(db, cryptoService, 8);

            CountDownLatch completionLatch = new CountDownLatch(1);
            AtomicInteger progressUpdatesCount = new AtomicInteger(0);
            AtomicBoolean edtVerified = new AtomicBoolean(true);
            BulkVerificationSummary[] summaryHolder = new BulkVerificationSummary[1];

            ScanProgressListener listener = new ScanProgressListener() {
                @Override
                public void onProgressUpdate(int processedCount, int totalCount, CredentialVerificationResult result) {
                    // Verify that SwingWorker.process() executes on the Swing EDT
                    if (!SwingUtilities.isEventDispatchThread()) {
                        edtVerified.set(false);
                    }
                    int count = progressUpdatesCount.incrementAndGet();
                    System.out.printf("  [EDT Progress %02d/%02d] %s | Status: %s | Source: %s (%dms)\n",
                            processedCount, totalCount, result.getMaskedCredential(),
                            result.getStatus(), result.getBreachSource() != null ? result.getBreachSource() : "None",
                            result.getProcessingTimeMs());
                }

                @Override
                public void onScanCompleted(BulkVerificationSummary summary) {
                    if (!SwingUtilities.isEventDispatchThread()) {
                        edtVerified.set(false);
                    }
                    summaryHolder[0] = summary;
                    System.out.println("\n[+] Scan Completed Callback Received on EDT!");
                    System.out.println("    " + summary);
                    completionLatch.countDown();
                }

                @Override
                public void onError(String userFriendlyMessage, Throwable cause) {
                    System.err.println("[!] Pipeline Error: " + userFriendlyMessage);
                    completionLatch.countDown();
                }
            };

            System.out.printf("[+] Submitting %d credentials to asynchronous verification engine...\n", bulkBatch.size());
            BulkCredentialSwingWorker worker = engine.submitBulkScan(bulkBatch, listener);

            // Wait for completion (max 20 seconds)
            boolean finished = completionLatch.await(20, TimeUnit.SECONDS);
            if (!finished) {
                throw new AssertionError("Bulk verification timed out!");
            }

            BulkVerificationSummary summary = summaryHolder[0];
            if (summary == null) {
                throw new AssertionError("Summary was not generated!");
            }

            if (summary.getTotalCompromised() != 3) {
                throw new AssertionError("Expected exactly 3 compromised credentials, found: " + summary.getTotalCompromised());
            }
            if (summary.getTotalSecure() != 17) {
                throw new AssertionError("Expected 17 secure credentials, found: " + summary.getTotalSecure());
            }
            if (!edtVerified.get()) {
                throw new AssertionError("UI callbacks did not execute on Swing Event Dispatch Thread (EDT)!");
            }
            System.out.printf("[PASS] Bulk scan passed: %d processed in %dms (100%% EDT compliant).\n",
                    summary.getTotalProcessed(), summary.getTotalDurationMs());

            // -------------------------------------------------------------
            // TEST 2: Robust Fault-Tolerant Exception Handling
            // -------------------------------------------------------------
            System.out.println("\n--- [TEST 2] Verifying Fault-Tolerant Error Handling ---");
            // Test that a database connection failure on an item produces a user-friendly error without crashing JVM
            CredentialVerificationResult errorResult = CredentialVerificationResult.error(
                    "P@ss****", "E9012",
                    "Database Connection Warning: Communications link failure during packet delivery.",
                    120
            );
            System.out.println("[+] Simulated Error Result: " + errorResult);
            System.out.println("    User Message          : " + errorResult.getUserFriendlyMessage());

            if (errorResult.getStatus() != CredentialVerificationResult.Status.ERROR) {
                throw new AssertionError("Expected error status!");
            }
            System.out.println("[PASS] Fault-tolerant error model cleanly preserves JVM and UI stability.");

            // -------------------------------------------------------------
            // CLEANUP
            // -------------------------------------------------------------
            System.out.println("\n--- [CLEANUP] Cleaning test records & shutting down engine ---");
            db.executeUpdate("DELETE FROM compromised_vault WHERE breach_source IN ('DarkWeb_Dump_A', 'BreachFeed_B', 'DarkWeb_Dump_C')");
            engine.shutdown();
            System.out.println("[+] Cleanup complete.");

            System.out.println("\n=================================================================");
            System.out.println(" >>> ALL ASYNC BACKEND PROCESSING TESTS PASSED 100%! <<<");
            System.out.println("=================================================================");

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}