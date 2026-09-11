package com.cryptaleak.honeytoken;

import com.cryptaleak.alert.AlertSubject;
import com.cryptaleak.alert.SecurityAlert;
import com.cryptaleak.crypto.CryptoService;
import com.cryptaleak.graph.BlastRadiusResult;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Project CryptaLeak - Simulated Threat Intelligence Scraper
 * 
 * Periodically ingests mock Dark Web feed dumps and correlates them
 * against active canary honeytokens and systemic blast radius thresholds.
 * 
 * When a canary breach or >80% blast radius is detected, dispatches
 * high-priority alerts via the Observer Pattern (AlertSubject).
 */
public class ThreatIntelFeedScraper {

    private static final Logger LOGGER = Logger.getLogger(ThreatIntelFeedScraper.class.getName());

    private final HoneytokenGenerator canaryGenerator;
    private final AlertSubject alertSubject;
    private final CryptoService cryptoService;

    private ScheduledExecutorService scheduler;
    private final List<MockBreachDump> feedHistory = new ArrayList<>();

    public ThreatIntelFeedScraper(HoneytokenGenerator canaryGenerator, AlertSubject alertSubject) {
        this(canaryGenerator, alertSubject, new CryptoService());
    }

    public ThreatIntelFeedScraper(HoneytokenGenerator canaryGenerator, AlertSubject alertSubject, CryptoService cryptoService) {
        this.canaryGenerator = Objects.requireNonNull(canaryGenerator, "canaryGenerator cannot be null");
        this.alertSubject = Objects.requireNonNull(alertSubject, "alertSubject cannot be null");
        this.cryptoService = Objects.requireNonNull(cryptoService, "cryptoService cannot be null");
    }

    // =========================================================================
    // THREAT INTEL FEED SCANNING LOGIC
    // =========================================================================

    /**
     * Ingests and inspects a mock dark web dump against active honeytoken canaries.
     *
     * @param dump Mock dark web dump containing leaked credentials/hashes
     * @return List of triggered alerts generated from this dump
     */
    public synchronized List<SecurityAlert> scanThreatIntelDump(MockBreachDump dump) {
        Objects.requireNonNull(dump, "Dump cannot be null");
        feedHistory.add(dump);

        LOGGER.info(String.format("[ThreatIntelScraper] Ingesting feed '%s' with %d records...",
                dump.feedSource(), dump.leakedItems().size()));

        List<SecurityAlert> triggeredAlerts = new ArrayList<>();
        List<Honeytoken> canaries = canaryGenerator.getActiveCanaries();

        for (Honeytoken canary : canaries) {
            byte[] canaryHashBytes = canary.getSha256Hash().getBytes(StandardCharsets.UTF_8);

            for (String leakedItem : dump.leakedItems()) {
                // Check direct match or SHA-256 hash match
                String itemHash = (leakedItem.length() == 64 && leakedItem.matches("^[0-9A-Fa-f]+$")) ?
                        leakedItem.toUpperCase() :
                        cryptoService.hashCredential(leakedItem);

                byte[] itemHashBytes = itemHash.getBytes(StandardCharsets.UTF_8);

                // Constant-time comparison
                if (MessageDigest.isEqual(canaryHashBytes, itemHashBytes)) {
                    canary.setTriggered(true);

                    LOGGER.severe(String.format("[CRITICAL ALARM] CANARY COMPROMISED! Decoy ID: %s, Feed: %s, Location: %s",
                            canary.getCanaryId(), dump.feedSource(), canary.getPlantedLocation()));

                    // Construct alert payload
                    SecurityAlert canaryAlert = SecurityAlert.createCanaryAlert(
                            canary.getCanaryId() + " (" + canary.getTokenType() + ")",
                            canary.getPlantedLocation(),
                            dump.feedSource()
                    );

                    triggeredAlerts.add(canaryAlert);

                    // Instantly notify registered observers (Observer Pattern)
                    alertSubject.notifyObservers(canaryAlert);
                    break; // Move to next canary
                }
            }
        }

        LOGGER.info(String.format("[ThreatIntelScraper] Scan complete for '%s'. %d canary compromises identified.",
                dump.feedSource(), triggeredAlerts.size()));

        return triggeredAlerts;
    }

    /**
     * Evaluates a BlastRadiusResult against the 80% organizational risk threshold.
     * If risk score >= 80%, dispatches a CRITICAL alert to all registered observers.
     *
     * @param blastResult Output of BFS threat propagation traversal
     * @return Dispatched SecurityAlert or null if below threshold
     */
    public SecurityAlert evaluateBlastRadiusThreshold(BlastRadiusResult blastResult) {
        Objects.requireNonNull(blastResult, "blastResult cannot be null");

        double score = blastResult.getSystemicRiskScore();
        if (score >= 80.0) {
            LOGGER.severe(String.format("[CRITICAL BLAST RADIUS] Origin %s has risk score %.2f%% exceeding 80%% threshold!",
                    blastResult.getCompromisedNode().getNodeId(), score));

            String primaryTarget = blastResult.getReachableAssets().isEmpty() ?
                    "Unknown" : blastResult.getReachableAssets().get(0).getName();

            SecurityAlert alert = SecurityAlert.createBlastRadiusAlert(
                    blastResult.getCompromisedNode().getName() + " (" + blastResult.getCompromisedNode().getNodeId() + ")",
                    score,
                    primaryTarget,
                    String.format("%d reachable assets including Domain Controller / Database infrastructure", blastResult.getTotalAssetsExposed())
            );

            // Notify registered observers (Observer Pattern)
            alertSubject.notifyObservers(alert);
            return alert;
        }

        return null;
    }

    // =========================================================================
    // PERIODIC SCHEDULER MANAGEMENT
    // =========================================================================

    /**
     * Starts periodic dark web threat scraping in the background.
     *
     * @param intervalSeconds Scraping interval
     */
    public synchronized void startPeriodicScraping(long intervalSeconds) {
        if (scheduler != null && !scheduler.isShutdown()) {
            return;
        }

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "CryptaLeak-ThreatScraper");
            t.setDaemon(true);
            return t;
        });

        scheduler.scheduleAtFixedRate(() -> {
            try {
                // In production, this pulls from external APIs or onion nodes
                LOGGER.fine("[ThreatIntelScraper] Polling simulated dark web threat intelligence feeds...");
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "[ThreatIntelScraper] Periodic scan encountered error: " + e.getMessage(), e);
            }
        }, 1, intervalSeconds, TimeUnit.SECONDS);

        LOGGER.info("[ThreatIntelScraper] Periodic threat scraper active (Interval: " + intervalSeconds + "s).");
    }

    public synchronized void stopPeriodicScraping() {
        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdownNow();
            LOGGER.info("[ThreatIntelScraper] Periodic threat scraper stopped.");
        }
    }

    public List<MockBreachDump> getFeedHistory() {
        return Collections.unmodifiableList(feedHistory);
    }

    /**
     * Value container for a dark web threat feed dump.
     */
    public record MockBreachDump(String feedSource, List<String> leakedItems) {}
}