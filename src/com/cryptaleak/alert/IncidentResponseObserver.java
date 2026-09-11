package com.cryptaleak.alert;

/**
 * Project CryptaLeak - Observer Design Pattern: Observer Interface
 * 
 * Contract for components that react asynchronously or synchronously to critical security alerts.
 */
public interface IncidentResponseObserver {

    /**
     * Triggered when a critical security event occurs (e.g. Canary breach, >80% blast radius).
     *
     * @param alert Security alert payload
     */
    void onSecurityAlert(SecurityAlert alert);
}