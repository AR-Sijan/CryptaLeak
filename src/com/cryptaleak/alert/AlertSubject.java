package com.cryptaleak.alert;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Project CryptaLeak - Observer Design Pattern: Alert Subject
 * 
 * Thread-safe Subject that maintains registered IncidentResponseObservers
 * and distributes security alerts across the system.
 */
public class AlertSubject {

    private static final Logger LOGGER = Logger.getLogger(AlertSubject.class.getName());

    // Thread-safe observer collection
    private final List<IncidentResponseObserver> observers = new CopyOnWriteArrayList<>();

    // Global default singleton instance
    private static class SingletonHolder {
        private static final AlertSubject INSTANCE = new AlertSubject();
    }

    public static AlertSubject getInstance() {
        return SingletonHolder.INSTANCE;
    }

    public AlertSubject() {
    }

    /**
     * Registers a new incident response observer.
     */
    public void registerObserver(IncidentResponseObserver observer) {
        Objects.requireNonNull(observer, "Observer cannot be null");
        if (!observers.contains(observer)) {
            observers.add(observer);
            LOGGER.info("[CryptaLeak Alert] Registered observer: " + observer.getClass().getSimpleName());
        }
    }

    /**
     * Removes an existing observer.
     */
    public void removeObserver(IncidentResponseObserver observer) {
        if (observer != null) {
            observers.remove(observer);
            LOGGER.info("[CryptaLeak Alert] Unregistered observer: " + observer.getClass().getSimpleName());
        }
    }

    /**
     * Broadcasts a critical security alert to all registered observers.
     */
    public void notifyObservers(SecurityAlert alert) {
        Objects.requireNonNull(alert, "SecurityAlert cannot be null");
        LOGGER.warning(String.format("[CryptaLeak Alert Broadcaster] Dispatching %s alert [%s] to %d observers...",
                alert.getSeverity(), alert.getAlertId(), observers.size()));

        for (IncidentResponseObserver observer : observers) {
            try {
                observer.onSecurityAlert(alert);
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "[CryptaLeak Alert] Observer error in " + observer.getClass().getSimpleName(), e);
            }
        }
    }

    public int getObserverCount() {
        return observers.size();
    }
}