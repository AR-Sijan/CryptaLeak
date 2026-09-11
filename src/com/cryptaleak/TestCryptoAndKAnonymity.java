package com.cryptaleak;

import com.cryptaleak.crypto.CryptoService;
import com.cryptaleak.crypto.HashSplit;
import com.cryptaleak.db.DatabaseConnection;
import com.cryptaleak.strategy.BreachResult;
import com.cryptaleak.strategy.KAnonymitySearchStrategy;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

public class TestCryptoAndKAnonymity {

    public static void main(String[] args) {
        System.out.println("=================================================================");
        System.out.println(" Project CryptaLeak - Cryptographic & K-Anonymity Layer Test");
        System.out.println("=================================================================");

        try {
            CryptoService cryptoService = new CryptoService();

            // -------------------------------------------------------------
            // TEST 1: Client-Side SHA-256 Hashing & 5-Char Prefix Splitting
            // -------------------------------------------------------------
            System.out.println("\n--- [TEST 1] Client-Side SHA-256 & K-Anonymity Prefix Splitting ---");
            String samplePassword = "P@ssword123!Secure";
            HashSplit split = cryptoService.splitCredential(samplePassword);
            System.out.println("Original Credential : [REDACTED]");
            System.out.println("Full SHA-256 Hash   : " + split.getFullHash());
            System.out.println("Prefix (5 chars)    : " + split.getPrefix());
            System.out.println("Suffix (59 chars)   : " + split.getSuffix());
            System.out.println("Total Length        : " + (split.getPrefix().length() + split.getSuffix().length()));

            if (split.getPrefix().length() != 5 || split.getSuffix().length() != 59) {
                throw new AssertionError("Prefix/Suffix length mismatch!");
            }
            System.out.println("[PASS] Prefix/Suffix extraction verified (5 + 59 = 64 hex characters).");

            // -------------------------------------------------------------
            // TEST 2: Field-Level E2EE (AES/GCM/NoPadding 256-bit)
            // -------------------------------------------------------------
            System.out.println("\n--- [TEST 2] Field-Level End-to-End Encryption (AES-GCM-256) ---");
            SecretKey key = cryptoService.generateAESKey();
            String exportedKey = cryptoService.exportKeyToBase64(key);
            System.out.println("Generated AES-256 Key (Base64) : " + exportedKey);

            String sensitiveAlertPayload = "{\"incident_id\":\"INC-9021\",\"compromised_host\":\"dc01.corp.internal\",\"blast_radius\":98.4}";
            System.out.println("Original Payload : " + sensitiveAlertPayload);

            String encryptedEnvelope = cryptoService.encryptPayload(sensitiveAlertPayload, key);
            System.out.println("Encrypted Envelope (Base64) : " + encryptedEnvelope);

            String decryptedPayload = cryptoService.decryptPayload(encryptedEnvelope, key);
            System.out.println("Decrypted Payload : " + decryptedPayload);

            if (!sensitiveAlertPayload.equals(decryptedPayload)) {
                throw new AssertionError("Decrypted payload does not match original!");
            }
            System.out.println("[PASS] E2EE AES-GCM Encrypt/Decrypt round-trip successful.");

            // Verify tampering detection (GCM Authentication Tag)
            try {
                // Tamper with one character in ciphertext
                byte[] tamperedBytes = java.util.Base64.getDecoder().decode(encryptedEnvelope);
                tamperedBytes[tamperedBytes.length - 1] ^= 0xFF;
                String tamperedBase64 = java.util.Base64.getEncoder().encodeToString(tamperedBytes);
                cryptoService.decryptPayload(tamperedBase64, key);
                throw new AssertionError("Tampered ciphertext should have failed GCM authentication check!");
            } catch (GeneralSecurityException ex) {
                System.out.println("[PASS] GCM authentication tag integrity verified: Tampered payload successfully rejected.");
            }

            // -------------------------------------------------------------
            // TEST 3: K-Anonymity Search Strategy with MySQL
            // -------------------------------------------------------------
            System.out.println("\n--- [TEST 3] K-Anonymity Search Strategy via MySQL Database ---");
            DatabaseConnection db = DatabaseConnection.getInstance();
            KAnonymitySearchStrategy searchStrategy = new KAnonymitySearchStrategy(db, cryptoService);

            String leakedPassword1 = "CyberSecWinter2026!";
            String leakedPassword2 = "AdminBackup#1099";
            String cleanPassword   = "CompletelyUnbreached_Password_99!";

            // Ingest leaked test credentials into compromised_vault
            System.out.println("[+] Ingesting test breach telemetry into compromised_vault...");
            searchStrategy.ingestCompromisedCredential(leakedPassword1, true, "DarkWeb_Breach_Dataset_A");
            searchStrategy.ingestCompromisedCredential(leakedPassword2, true, "ThreatIntel_Feed_B");

            // Query 1: Leaked password 1
            System.out.println("\n[Lookup 1] Testing leaked credential...");
            BreachResult result1 = searchStrategy.checkCredential(leakedPassword1);
            System.out.println("Lookup Result: " + result1);
            if (!result1.isCompromised() || !"DarkWeb_Breach_Dataset_A".equals(result1.getBreachSource())) {
                throw new AssertionError("Lookup 1 failed: Expected compromised from DarkWeb_Breach_Dataset_A");
            }
            System.out.println("[PASS] Breached credential detected accurately via 5-char prefix query.");

            // Query 2: Clean password
            System.out.println("\n[Lookup 2] Testing clean/uncompromised credential...");
            BreachResult result2 = searchStrategy.checkCredential(cleanPassword);
            System.out.println("Lookup Result: " + result2);
            if (result2.isCompromised()) {
                throw new AssertionError("Lookup 2 failed: Clean password reported as compromised!");
            }
            System.out.println("[PASS] Clean credential confirmed secure.");

            // Clean up test records
            HashSplit split1 = cryptoService.splitCredential(leakedPassword1);
            HashSplit split2 = cryptoService.splitCredential(leakedPassword2);
            db.executeUpdate("DELETE FROM compromised_vault WHERE hash_prefix = ? AND hash_suffix = ?", split1.getPrefix(), split1.getSuffix());
            db.executeUpdate("DELETE FROM compromised_vault WHERE hash_prefix = ? AND hash_suffix = ?", split2.getPrefix(), split2.getSuffix());
            System.out.println("\n[+] Cleaned up test data in compromised_vault.");

            System.out.println("\n=================================================================");
            System.out.println(" >>> ALL CRYPTOGRAPHIC & K-ANONYMITY TESTS PASSED 100%! <<<");
            System.out.println("=================================================================");

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}