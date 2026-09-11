package com.cryptaleak.alert;

import com.cryptaleak.db.DatabaseConnection;

import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Project CryptaLeak - Observer Implementation: Database Alert Logger
 * 
 * Automatically persists triggered security alerts into the blast_alerts MySQL table
 * using parameterized PreparedStatement execution to defend against SQL Injection.
 */
public class DatabaseAlertLogger implements IncidentResponseObserver {

    private static final Logger LOGGER = Logger.getLogger(DatabaseAlertLogger.class.getName());

    private static final String INSERT_ALERT_SQL = 
            "INSERT INTO blast_alerts (alert_id, compromised_source, systemic_risk_score, breached_endpoint, severity, mitigation_status, timestamp) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?) " +
            "ON DUPLICATE KEY UPDATE systemic_risk_score = VALUES(systemic_risk_score), severity = VALUES(severity), mitigation_status = VALUES(mitigation_status)";

    private final DatabaseConnection db;

    public DatabaseAlertLogger() {
        this(DatabaseConnection.getInstance());
    }

    public DatabaseAlertLogger(DatabaseConnection db) {
        this.db = db;
    }

    @Override
    public void onSecurityAlert(SecurityAlert alert) {
        try {
            LOGGER.info("[DatabaseAlertLogger] Persisting alert [" + alert.getAlertId() + "] into blast_alerts table...");
            db.executeUpdate(
                    INSERT_ALERT_SQL,
                    alert.getAlertId(),
                    alert.getCompromisedSource(),
                    alert.getSystemicRiskScore(),
                    alert.getBreachedEndpoint(),
                    alert.getSeverity(),
                    alert.getMitigationStatus(),
                    alert.getTimestamp()
            );
            LOGGER.info("[DatabaseAlertLogger] Successfully recorded alert [" + alert.getAlertId() + "] in MySQL.");
        } catch (SQLException e) {
            LOGGER.log(Level.SEVERE, "[DatabaseAlertLogger] Failed to write alert into MySQL database: " + e.getMessage(), e);
        }
    }
}