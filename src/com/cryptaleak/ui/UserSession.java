package com.cryptaleak.ui;

import java.util.Objects;

/**
 * Project CryptaLeak - Authenticated User Session Entity
 */
public class UserSession {

    private final long id;
    private final String email;
    private final String role;
    private final boolean compromisedCredential;

    public UserSession(long id, String email, String role, boolean compromisedCredential) {
        this.id = id;
        this.email = Objects.requireNonNull(email, "email cannot be null");
        this.role = Objects.requireNonNull(role, "role cannot be null");
        this.compromisedCredential = compromisedCredential;
    }

    public long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getRole() {
        return role;
    }

    public boolean isCompromisedCredential() {
        return compromisedCredential;
    }

    public boolean isBlueTeam() {
        return "ADMIN".equalsIgnoreCase(role) || 
               "SECOPS_ANALYST".equalsIgnoreCase(role) || 
               "INCIDENT_RESPONDER".equalsIgnoreCase(role);
    }

    public boolean isStandardEmployee() {
        return !isBlueTeam();
    }

    @Override
    public String toString() {
        return String.format("UserSession[Email=%s, Role=%s, Leaked=%b]", email, role, compromisedCredential);
    }
}