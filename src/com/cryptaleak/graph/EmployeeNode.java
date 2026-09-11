package com.cryptaleak.graph;

import java.util.Objects;

/**
 * Project CryptaLeak - Employee Identity Node
 * 
 * Represents a human user, account, or administrative operator within the identity perimeter.
 */
public class EmployeeNode extends Node {

    private final String email;
    private final String department;
    private final String privilegeTier;
    private boolean compromised;

    public EmployeeNode(String nodeId, String name, double riskWeight, boolean quarantined,
                        String email, String department, String privilegeTier) {
        super(nodeId, name, riskWeight, quarantined);
        this.email = (email != null && !email.trim().isEmpty()) ? email.trim() : nodeId.toLowerCase() + "@corp.local";
        this.department = (department != null && !department.trim().isEmpty()) ? department.trim() : "GENERAL";
        this.privilegeTier = (privilegeTier != null && !privilegeTier.trim().isEmpty()) ? privilegeTier.trim() : "STANDARD_USER";
        this.compromised = false;
    }

    public EmployeeNode(String nodeId, String name, double riskWeight, boolean quarantined) {
        this(nodeId, name, riskWeight, quarantined, null, null, null);
    }

    public String getEmail() {
        return email;
    }

    public String getDepartment() {
        return department;
    }

    public String getPrivilegeTier() {
        return privilegeTier;
    }

    public boolean isCompromised() {
        return compromised;
    }

    public void setCompromised(boolean compromised) {
        this.compromised = compromised;
    }

    @Override
    public String getNodeCategory() {
        return "EMPLOYEE";
    }

    @Override
    public String getSpecificType() {
        return "DOMAIN_USER";
    }

    @Override
    public String toString() {
        return String.format("EmployeeNode[%s (%s), Dept='%s', Tier='%s', Weight=%.1f, Compromised=%b]",
                nodeId, name, department, privilegeTier, riskWeight, compromised);
    }
}