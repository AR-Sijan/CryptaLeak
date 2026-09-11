package com.cryptaleak.alert;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Project CryptaLeak - Observer Implementation: SOC Incident Response Console
 * 
 * Receives security alerts and dispatches immediate triage and containment workflows
 * to the Security Operations Center (SOC) console.
 */
public class SocNotificationObserver implements IncidentResponseObserver {

    private final List<SecurityAlert> receivedAlerts = new ArrayList<>();

    @Override
    public synchronized void onSecurityAlert(SecurityAlert alert) {
        receivedAlerts.add(alert);

        System.out.println("\n*****************************************************************");
        System.out.printf(" [SOC CRITICAL ALERT] - %s [%s]\n", alert.getAlertId(), alert.getSeverity());
        System.out.println("*****************************************************************");
        System.out.printf(" Compromised Source : %s\n", alert.getCompromisedSource());
        System.out.printf(" Breached Target    : %s\n", alert.getBreachedEndpoint());
        System.out.printf(" Systemic Risk Score: %.2f%%\n", alert.getSystemicRiskScore());
        System.out.printf(" Alert Type         : %s\n", alert.getAlertType());
        System.out.printf(" Narrative          : %s\n", alert.getNarrativeDescription());
        System.out.println(" RECOMMENDED TRIAGE ACTIONS:");

        if (alert.getAlertType() == SecurityAlert.AlertType.CANARY_BREACH) {
            System.out.println("  1. IMMEDIATELY revoke credential at location: " + alert.getBreachedEndpoint());
            System.out.println("  2. Initiate forensic audit on all network traffic originating from decoy source.");
            System.out.println("  3. Rotate all associated secrets and invalidate active SSO sessions.");
        } else if (alert.getSystemicRiskScore() >= 80.0) {
            System.out.println("  1. ISOLATE AND QUARANTINE starting node: " + alert.getCompromisedSource());
            System.out.println("  2. Restrict lateral routes to Domain Controller and Production Database clusters.");
            System.out.println("  3. Escalate to P1 Incident Response team.");
        }
        System.out.println("*****************************************************************\n");
    }

    public synchronized List<SecurityAlert> getReceivedAlerts() {
        return Collections.unmodifiableList(new ArrayList<>(receivedAlerts));
    }

    public synchronized void clear() {
        receivedAlerts.clear();
    }
}