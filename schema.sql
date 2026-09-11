-- =====================================================================
-- Project CryptaLeak - Enterprise Cybersecurity Database Schema
-- Database: cryptaleak_db
-- Target Engine: MySQL 8.0+ / MariaDB 10.5+
-- Charset: utf8mb4 (Full Unicode support for secure hash / UTF-8 strings)
-- =====================================================================

CREATE DATABASE IF NOT EXISTS cryptaleak_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE cryptaleak_db;

-- ---------------------------------------------------------------------
-- 1. Table: users
-- Purpose: System access control, role-based authentication, and audit.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL COMMENT 'Bcrypt, Argon2id, or PBKDF2 formatted hash',
    role ENUM('ADMIN', 'SECOPS_ANALYST', 'INCIDENT_RESPONDER', 'AUDITOR') NOT NULL DEFAULT 'SECOPS_ANALYST',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_login TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_user_role (role),
    INDEX idx_user_status (is_active)
) ENGINE=InnoDB COMMENT='Authorized personnel credentials and RBAC';

-- ---------------------------------------------------------------------
-- 2. Table: compromised_vault
-- Purpose: K-Anonymity model for breached credential lookup (HIBP style).
--          Lookup queries search by hash_prefix (e.g. first 5 characters of SHA-1/SHA-256),
--          preventing full hash exposure over the wire.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS compromised_vault (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    hash_prefix CHAR(5) NOT NULL COMMENT 'First 5 characters of credential hash (K-Anonymity bucket)',
    hash_suffix VARCHAR(59) NOT NULL COMMENT 'Remaining characters of credential hash',
    breach_source VARCHAR(100) DEFAULT 'UNKNOWN' COMMENT 'Name or ID of breach dataset',
    ingested_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_hash_prefix (hash_prefix),
    UNIQUE INDEX uq_prefix_suffix (hash_prefix, hash_suffix)
) ENGINE=InnoDB COMMENT='K-Anonymity credential leakage repository';

-- ---------------------------------------------------------------------
-- 3. Table: identity_nodes
-- Purpose: Graph topology representing network identities, domain accounts,
--          privilege tiers, and adjacent attack vectors.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identity_nodes (
    node_id VARCHAR(64) PRIMARY KEY COMMENT 'Unique node identifier (UUID or IAM ARN/Principal)',
    node_type ENUM('SERVICE_ACCOUNT', 'DOMAIN_USER', 'DOMAIN_CONTROLLER', 'DATABASE_CLUSTER', 'CLOUD_IAM_ROLE', 'API_KEY') NOT NULL,
    name VARCHAR(255) NOT NULL COMMENT 'Display name or FQDN of the identity',
    risk_weight DECIMAL(5, 2) NOT NULL DEFAULT 1.00 COMMENT 'Base criticality factor (1.00 to 100.00)',
    adjacent_nodes_json JSON NOT NULL COMMENT 'Adjacency list of reachable nodes and edge weights in JSON format',
    is_quarantined BOOLEAN NOT NULL DEFAULT FALSE,
    last_assessed TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_node_type (node_type),
    INDEX idx_risk_weight (risk_weight)
) ENGINE=InnoDB COMMENT='Identity attack surface and graph node registry';

-- ---------------------------------------------------------------------
-- 4. Table: blast_alerts
-- Purpose: Real-time blast radius calculations and incident telemetry
--          triggered when identity nodes or compromised credentials correlate.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blast_alerts (
    alert_id VARCHAR(64) PRIMARY KEY COMMENT 'Unique alert identifier (e.g., ALT-UUID)',
    compromised_source VARCHAR(255) NOT NULL COMMENT 'Originator of breach or compromise (user, node, IP)',
    systemic_risk_score DECIMAL(5, 2) NOT NULL COMMENT 'Calculated blast radius score (0.00 to 100.00)',
    breached_endpoint VARCHAR(255) NOT NULL COMMENT 'Target endpoint, IP, hostname or service breached',
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'MEDIUM',
    mitigation_status ENUM('NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED') NOT NULL DEFAULT 'NEW',
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_alert_timestamp (timestamp),
    INDEX idx_risk_score (systemic_risk_score),
    INDEX idx_severity (severity)
) ENGINE=InnoDB COMMENT='High-priority blast radius alerts and telemetry';
