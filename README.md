# 🛡️ Project CryptaLeak

> **Enterprise Cybersecurity & Threat Exposure Management Suite**  
> *Zero-Knowledge K-Anonymity Credential Verification, BFS Blast-Radius Attack Graphs, Honeytoken Canaries, and Dark-Themed Java Swing Interface.*

---

## 📌 Overview

**Project CryptaLeak** is an enterprise-grade cybersecurity application built with **pure Java (OpenJDK 21 LTS)** and **MySQL 8.4 LTS**. It detects compromised credentials across enterprise identities without leaking sensitive hashes, models organizational lateral attack paths using in-memory graph theory, deploys active decoy honeytokens, and triggers real-time security alerts.

---

## 🚀 Core Features

* **Zero-Knowledge K-Anonymity Lookup**:
  * Hashes credentials locally with client-side **SHA-256**.
  * Extracts the first 5 hexadecimal characters as a query prefix and withholds the remaining 59 characters.
  * Queries MySQL matching only the 5-character prefix bucket.
  * Executes a local **constant-time linear comparison** (`MessageDigest.isEqual`) across bucket candidates to prevent side-channel timing attacks.
* **Field-Level End-to-End Encryption (E2EE)**:
  * Encrypts sensitive telemetry using standard `AES/GCM/NoPadding` with 256-bit keys and 12-byte random IV nonces.
  * Verifies 128-bit authentication tags to reject tampered envelopes.
* **In-Memory Threat Relationship Graph & BFS Engine**:
  * Pure OOP graph representation (`Node`, `EmployeeNode`, `AssetNode`, `Edge`).
  * In-memory adjacency list (`Map<Node, List<Edge>>`) loaded from MySQL `identity_nodes`.
  * **Breadth-First Search (BFS)** lateral traversal discovering reachable infrastructure from compromised nodes.
  * Dynamic organizational **Risk Score formula (0–100%)** combining privilege weights, distance decay, and structural adjacency.
  * Active containment boundaries (quarantining nodes halts lateral movement).
* **Honeytoken Decoy Alerting System**:
  * Generates decoy AWS access keys, database passwords, and API tokens using `SecureRandom`.
  * Records decoy nodes into MySQL with top-tier criticality.
  * Simulated dark web threat scraper correlates breach dumps against active canaries.
  * **Observer Design Pattern** (`AlertSubject`, `DatabaseAlertLogger`, `SocNotificationObserver`) triggering automated incident triage and SQL injection-proof database logging.
* **Multi-Threaded Async Concurrency Engine**:
  * High-throughput `BulkCredentialSwingWorker` backed by `ExecutorService`.
  * Guarantees 100% Event Dispatch Thread (EDT) safety without freezing the UI.
  * Fault-tolerant exception handling that keeps the JVM running even during database connection loss.
* **Dark-Themed Java Swing UI**:
  * `LoginFrame.java`: Corporate authentication, proactive breach check, and RBAC role routing.
  * `EmployeePortalFrame.java`: Single credential inspection, async bulk verification table, and raw crypto telemetry console.
  * `BlueTeamDashboardFrame.java`: Live KPI badges, interactive topology matrix, canary log tables, and strict RBAC guards blocking standard employees.

---

## 🗄️ Database Architecture (`cryptaleak_db`)

The database consists of 4 core tables:
1. `users`: System access control and role-based accounts (`ADMIN`, `SECOPS_ANALYST`, `STANDARD_EMPLOYEE`).
2. `compromised_vault`: K-Anonymity breach repository with indexed `hash_prefix CHAR(5)` and confidential `hash_suffix VARCHAR(59)`.
3. `identity_nodes`: Identity graph topology containing servers, domain controllers, databases, and JSON adjacencies.
4. `blast_alerts`: High-priority incident telemetry, blast radius scores, and mitigation statuses.

---

## ⚙️ Quick Start Guide

### 1. Prerequisites
* **Java**: OpenJDK 21 LTS or higher (`javac` and `java` in PATH)
* **MySQL Server**: 8.4 LTS or MariaDB running on `localhost:3306`

### 2. Database Initialization
Import the database schema:
```powershell
Get-Content schema.sql -Raw | mysql -u root
```

### 3. Launching the Application
Double-click `run_app.bat` or execute:
```powershell
javac -cp ".;lib/mysql-connector-j-8.4.0.jar" -d bin src/com/cryptaleak/db/*.java src/com/cryptaleak/crypto/*.java src/com/cryptaleak/strategy/*.java src/com/cryptaleak/graph/*.java src/com/cryptaleak/alert/*.java src/com/cryptaleak/honeytoken/*.java src/com/cryptaleak/engine/*.java src/com/cryptaleak/ui/*.java

java -cp "bin;lib/mysql-connector-j-8.4.0.jar" com.cryptaleak.ui.LoginFrame
```

---

## 🔑 Pre-Configured Test Accounts

| Role | Corporate Email | Password | Accessible Console |
| :--- | :--- | :--- | :--- |
| **Blue Team Lead** | `admin@cryptaleak.corp` | `Admin#2026!Crypta` | Blue Team Dashboard |
| **SecOps Analyst** | `analyst@cryptaleak.corp` | `SecOps#Analyst99` | Blue Team Dashboard |
| **Standard Staff** | `employee@cryptaleak.corp` | `EmployeePass123!` | Employee Vault Portal |
| **DevOps Staff** | `bob@cryptaleak.corp` | `BobDevOps#2026` | Employee Vault Portal |

---

## 🛡️ Security & Privacy Philosophy

* **Zero-Knowledge Principle**: The server never sees the full hash or suffix.
* **Constant-Time Operations**: Uses `MessageDigest.isEqual` to prevent side-channel timing attacks.
* **SQL Injection Immunity**: 100% pure parameterized `PreparedStatement` execution.
* **No Third-Party Bloat**: Built strictly with built-in standard Java packages (`java.security`, `javax.crypto`, `java.util.concurrent`, `javax.swing`) and the official MySQL JDBC driver.

---
*Created by [AR-Sijan](https://github.com/AR-Sijan)*