package com.cryptaleak.honeytoken;

import com.cryptaleak.crypto.CryptoService;
import com.cryptaleak.crypto.HashSplit;
import com.cryptaleak.db.DatabaseConnection;

import java.security.SecureRandom;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Project CryptaLeak - Decoy Honeytoken Generator
 * 
 * Uses SecureRandom to generate authentic-looking decoy credentials
 * (AWS Keys, Database Passwords, API Tokens) and records them into the MySQL database.
 */
public class HoneytokenGenerator {

    private static final Logger LOGGER = Logger.getLogger(HoneytokenGenerator.class.getName());

    private static final String ALPHANUMERIC_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final String CHARS_BASE62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final String CHARS_SPECIAL = "!@#$%^&*-_=+";

    private final SecureRandom secureRandom;
    private final CryptoService cryptoService;
    private final DatabaseConnection db;

    // In-Memory Active Canary Registry
    private final Map<String, Honeytoken> activeCanaries = new ConcurrentHashMap<>();

    private static final String INSERT_NODE_SQL = 
            "INSERT INTO identity_nodes (node_id, node_type, name, risk_weight, adjacent_nodes_json, is_quarantined) " +
            "VALUES (?, ?, ?, ?, ?, ?) " +
            "ON DUPLICATE KEY UPDATE name = VALUES(name), risk_weight = VALUES(risk_weight)";

    public HoneytokenGenerator() {
        this(DatabaseConnection.getInstance(), new CryptoService());
    }

    public HoneytokenGenerator(DatabaseConnection db, CryptoService cryptoService) {
        this.db = Objects.requireNonNull(db, "DatabaseConnection cannot be null");
        this.cryptoService = Objects.requireNonNull(cryptoService, "CryptoService cannot be null");
        this.secureRandom = new SecureRandom();
    }

    /**
     * Generates a unique decoy credential of the requested type and records it
     * into the MySQL database identity_nodes table.
     *
     * @param type            Type of credential (AWS, DB Password, API Token)
     * @param plantedLocation Where the decoy is planted (e.g. '.env.staging', 'src/config.json')
     * @return Fully populated and recorded Honeytoken instance
     * @throws SQLException on database record failure
     */
    public Honeytoken generateAndRecordHoneytoken(Honeytoken.TokenType type, String plantedLocation) throws SQLException {
        Objects.requireNonNull(type, "TokenType cannot be null");
        Objects.requireNonNull(plantedLocation, "Planted location cannot be null");

        String canaryId = "CANARY-" + type.name().substring(0, Math.min(3, type.name().length())) + "-" + generateRandomString(CHARS_BASE62, 8).toUpperCase();
        String secretValue = generateDecoySecret(type);

        HashSplit split = cryptoService.splitCredential(secretValue);

        Honeytoken honeytoken = new Honeytoken(
                canaryId,
                type,
                secretValue,
                split.getFullHash(),
                split.getPrefix(),
                split.getSuffix(),
                plantedLocation
        );

        // Record in in-memory registry
        activeCanaries.put(canaryId, honeytoken);

        // Record into MySQL database (identity_nodes table)
        String nodeType = switch (type) {
            case AWS_ACCESS_KEY -> "CLOUD_IAM_ROLE";
            case DATABASE_PASSWORD -> "DATABASE_CLUSTER";
            case API_TOKEN -> "API_KEY";
            case SERVICE_ACCOUNT_KEY -> "SERVICE_ACCOUNT";
        };

        String displayName = String.format("HONEYTOKEN: %s [%s]", canaryId, plantedLocation);
        double canaryRiskWeight = 99.00; // Canaries represent top-tier breach detection triggers

        db.executeUpdate(
                INSERT_NODE_SQL,
                canaryId,
                nodeType,
                displayName,
                canaryRiskWeight,
                "[]", // Canaries have no outgoing access dependencies
                false
        );

        LOGGER.info(String.format("[CryptaLeak Canary] Created and registered decoy token %s at '%s' (Prefix: %s)",
                canaryId, plantedLocation, split.getPrefix()));

        return honeytoken;
    }

    /**
     * Generates decoy secrets matching standard credential formats.
     */
    private String generateDecoySecret(Honeytoken.TokenType type) {
        return switch (type) {
            case AWS_ACCESS_KEY -> "AKIA" + generateRandomString(ALPHANUMERIC_UPPER, 16);
            case DATABASE_PASSWORD -> "CtLeakDB#" + generateRandomString(CHARS_BASE62 + CHARS_SPECIAL, 20);
            case API_TOKEN -> "ctleak_live_" + generateRandomString(CHARS_BASE62, 32);
            case SERVICE_ACCOUNT_KEY -> "sa_key_" + generateRandomString(CHARS_BASE62, 28);
        };
    }

    private String generateRandomString(String charPool, int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int idx = secureRandom.nextInt(charPool.length());
            sb.append(charPool.charAt(idx));
        }
        return sb.toString();
    }

    public Honeytoken getCanaryById(String canaryId) {
        return activeCanaries.get(canaryId);
    }

    public List<Honeytoken> getActiveCanaries() {
        return Collections.unmodifiableList(new ArrayList<>(activeCanaries.values()));
    }

    public void clearRegistry() {
        activeCanaries.clear();
    }
}