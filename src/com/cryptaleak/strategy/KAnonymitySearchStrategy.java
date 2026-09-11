package com.cryptaleak.strategy;

import com.cryptaleak.crypto.CryptoService;
import com.cryptaleak.crypto.HashSplit;
import com.cryptaleak.db.DatabaseConnection;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Project CryptaLeak - K-Anonymity Privacy-Preserving Search Strategy
 * 
 * Guarantees zero-knowledge database querying:
 * 1. Computes client-side SHA-256 and splits it into a 5-char prefix and 59-char suffix.
 * 2. Transmits ONLY the 5-character prefix to MySQL.
 * 3. Receives candidate suffixes belonging to that prefix bucket.
 * 4. Conducts a client-side linear comparison with constant-time equality checks
 *    to prevent side-channel timing analysis.
 * 
 * The full hash or sensitive suffix NEVER leaves the client.
 */
public class KAnonymitySearchStrategy implements SearchStrategy {

    private static final Logger LOGGER = Logger.getLogger(KAnonymitySearchStrategy.class.getName());

    private final DatabaseConnection db;
    private final CryptoService cryptoService;

    /**
     * Parameterized query selecting bucket candidate suffixes using ONLY the 5-char prefix.
     * Prepared statement prevents SQL Injection.
     */
    private static final String SELECT_BUCKET_SQL = 
            "SELECT hash_suffix, breach_source FROM compromised_vault WHERE hash_prefix = ?";

    private static final String INSERT_LEAK_SQL = 
            "INSERT INTO compromised_vault (hash_prefix, hash_suffix, breach_source) " +
            "VALUES (?, ?, ?) " +
            "ON DUPLICATE KEY UPDATE breach_source = VALUES(breach_source)";

    public KAnonymitySearchStrategy() {
        this(DatabaseConnection.getInstance(), new CryptoService());
    }

    public KAnonymitySearchStrategy(DatabaseConnection db, CryptoService cryptoService) {
        this.db = Objects.requireNonNull(db, "DatabaseConnection cannot be null");
        this.cryptoService = Objects.requireNonNull(cryptoService, "CryptoService cannot be null");
    }

    /**
     * Inspects a plaintext credential using the K-Anonymity model.
     */
    @Override
    public BreachResult checkCredential(String plainCredential) throws SQLException {
        Objects.requireNonNull(plainCredential, "Credential cannot be null");
        HashSplit split = cryptoService.splitCredential(plainCredential);
        return executeKAnonymitySearch(split);
    }

    /**
     * Inspects a 64-character SHA-256 hash using the K-Anonymity model.
     */
    @Override
    public BreachResult checkHash(String fullHash) throws SQLException {
        Objects.requireNonNull(fullHash, "Full hash cannot be null");
        HashSplit split = cryptoService.splitHash(fullHash);
        return executeKAnonymitySearch(split);
    }

    /**
     * Core privacy-preserving search execution:
     * - Network payload: prefix only
     * - Client execution: linear constant-time search
     */
    private BreachResult executeKAnonymitySearch(HashSplit split) throws SQLException {
        String prefix = split.getPrefix();
        String targetSuffix = split.getSuffix();

        LOGGER.info(String.format("[CryptaLeak K-Anonymity] Querying bucket for prefix: [%s] (Suffix withheld client-side)", prefix));

        // 1. Query MySQL matching strictly the 5-character prefix
        List<CandidateSuffixRecord> candidates = db.executeQuery(SELECT_BUCKET_SQL, rs -> {
            List<CandidateSuffixRecord> list = new ArrayList<>();
            while (rs.next()) {
                String suffix = rs.getString("hash_suffix");
                String source = rs.getString("breach_source");
                list.add(new CandidateSuffixRecord(suffix, source));
            }
            return list;
        }, prefix);

        LOGGER.info(String.format("[CryptaLeak K-Anonymity] Received %d candidate suffixes from MySQL bucket.", candidates.size()));

        // 2. Perform client-side linear comparison with constant-time equality
        byte[] targetBytes = targetSuffix.toUpperCase().getBytes(StandardCharsets.UTF_8);

        for (CandidateSuffixRecord candidate : candidates) {
            if (candidate.suffix() == null) continue;

            byte[] candidateBytes = candidate.suffix().trim().toUpperCase().getBytes(StandardCharsets.UTF_8);

            // Constant-time array comparison protects against timing attacks
            if (MessageDigest.isEqual(targetBytes, candidateBytes)) {
                LOGGER.warning(String.format("[CryptaLeak Alert] Breach match confirmed locally! Source: %s", candidate.breachSource()));
                return BreachResult.breached(prefix, candidate.suffix(), candidate.breachSource(), candidates.size());
            }
        }

        LOGGER.info(String.format("[CryptaLeak K-Anonymity] Hash suffix verified clean against %d candidates.", candidates.size()));
        return BreachResult.clean(prefix, candidates.size());
    }

    /**
     * Ingests a new compromised credential/hash into the database for threat intelligence feeds.
     * Automatically splits the hash to preserve prefix indexing.
     *
     * @param fullHashOrPlaintext Full 64-char SHA-256 hash or plaintext password
     * @param isPlaintext         True if first argument is plaintext, false if already SHA-256
     * @param breachSource        Name of breach dataset (e.g. 'RockYou2024', 'DarkWebDump')
     * @return Number of rows updated/inserted
     * @throws SQLException on database failure
     */
    public int ingestCompromisedCredential(String fullHashOrPlaintext, boolean isPlaintext, String breachSource) throws SQLException {
        HashSplit split = isPlaintext ? 
                cryptoService.splitCredential(fullHashOrPlaintext) : 
                cryptoService.splitHash(fullHashOrPlaintext);

        String source = (breachSource != null && !breachSource.trim().isEmpty()) ? breachSource.trim() : "UNKNOWN_SOURCE";

        return db.executeUpdate(INSERT_LEAK_SQL, split.getPrefix(), split.getSuffix(), source);
    }

    /**
     * Immutable container for candidate records returned from the MySQL bucket.
     */
    private record CandidateSuffixRecord(String suffix, String breachSource) {}
}