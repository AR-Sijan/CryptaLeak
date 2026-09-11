package com.cryptaleak.alert;

import java.sql.Timestamp;
import java.util.Objects;
import java.util.UUID;

/**
 * Project CryptaLeak - Security Incident Alert Entity
 * 
 * Maps to the blast_alerts database table and serves as the payload
 * for the Observer design pattern.
 */
public class SecurityAlert {

    public enum AlertType {
        CANARY_BREACH,
        HIGH_BLAST_RADIUS,
        ANOMALOUS_ACCESS
    }

    private final String alertId;
    private final AlertType alertType;
    private final String compromisedSource;
    private final double systemicRiskScore;
    private final String breachedEndpoint;
    private final String severity;
    private String mitigationStatus;
    private final String narrativeDescription;
    private final Timestamp timestamp;

    public SecurityAlert(String alertId, AlertType alertType, String compromisedSource,
                         double systemicRiskScore, String breachedEndpoint, String severity,
                         String mitigationStatus, String narrativeDescription) {
        this.alertId = (alertId != null && !alertId.trim().isEmpty()) ? alertId.trim() : "ALT-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        this.alertType = Objects.requireNonNull(alertType, "alertType cannot be null");
        this.compromisedSource = Objects.requireNonNull(compromisedSource, "compromisedSource cannot be null");
        this.systemicRiskScore = Math.max(0.0, Math.min(100.0, systemicRiskScore));
        this.breachedEndpoint = (breachedEndpoint != null && !breachedEndpoint.trim().isEmpty()) ? breachedEndpoint.trim() : "unknown-endpoint";
        this.severity = (severity != null && !severity.trim().isEmpty()) ? severity.trim().toUpperCase() : "MEDIUM";
        this.mitigationStatus = (mitigationStatus != null && !mitigationStatus.trim().isEmpty()) ? mitigationStatus.trim().toUpperCase() : "NEW";
        this.narrativeDescription = narrativeDescription != null ? narrativeDescription : "";
        this.timestamp = new Timestamp(System.currentTimeMillis());
    }

    public static SecurityAlert createCanaryAlert(String canaryIdentifier, String plantedLocation, String breachFeed) {
        return new SecurityAlert(
                null,
                AlertType.CANARY_BREACH,
                "HONEYTOKEN_TRIGGER: " + canaryIdentifier,
                99.50, // Canary breach is an indisputable compromise
                plantedLocation,
                "CRITICAL",
                "NEW",
                String.format("Honeytoken decoy credential leaked in dark web threat feed: %s. Zero false positive.", breachFeed)
        );
    }

    public static SecurityAlert createBlastRadiusAlert(String sourceEmployee, double riskScore, String primaryTarget, String pathSummary) {
        String severity = riskScore >= 80.0 ? "CRITICAL" : (riskScore >= 50.0 ? "HIGH" : "MEDIUM");
        return new SecurityAlert(
                null,
                AlertType.HIGH_BLAST_RADIUS,
                sourceEmployee,
                riskScore,
                primaryTarget,
                severity,
                "NEW",
                String.format("Blast radius analysis exceeded security threshold: %.2f%%. Lateral path: %s", riskScore, pathSummary)
        );
    }

    public String getAlertId() {
        return alertId;
    }

    public AlertType getAlertType() {
        return alertType;
    }

    public String getCompromisedSource() {
        return compromisedSource;
    }

    public double getSystemicRiskScore() {
        return systemicRiskScore;
    }

    public String getBreachedEndpoint() {
        return breachedEndpoint;
    }

    public String getSeverity() {
        return severity;
    }

    public String getMitigationStatus() {
        return mitigationStatus;
    }

    public void setMitigationStatus(String mitigationStatus) {
        this.mitigationStatus = mitigationStatus;
    }

    public String getNarrativeDescription() {
        return narrativeDescription;
    }

    public Timestamp getTimestamp() {
        return timestamp;
    }

    @Override
    public String toString() {
        return String.format("SecurityAlert[ID=%s, Type=%s, Source='%s', Risk=%.2f%%, Severity=%s, Status=%s]",
                alertId, alertType, compromisedSource, systemicRiskScore, severity, mitigationStatus);
    }
}