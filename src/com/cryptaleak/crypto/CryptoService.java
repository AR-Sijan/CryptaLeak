package com.cryptaleak.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Project CryptaLeak - Privacy-Preserving Cryptographic Service
 * 
 * Provides:
 * 1. Client-side SHA-256 hashing and K-Anonymity 5-character prefix/suffix splitting.
 * 2. Field-level End-to-End Encryption (E2EE) using AES/GCM/NoPadding with 256-bit keys.
 * 
 * Implemented exclusively with standard JDK java.security.* and javax.crypto.* packages.
 */
public final class CryptoService {

    // K-Anonymity Configuration
    public static final int PREFIX_LENGTH = 5;
    public static final String HASH_ALGORITHM = "SHA-256";

    // E2EE AES-GCM Configuration
    public static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    public static final String KEY_ALGORITHM = "AES";
    public static final int AES_KEY_SIZE_BITS = 256;
    public static final int GCM_IV_LENGTH_BYTES = 12; // 96 bits recommended for GCM
    public static final int GCM_TAG_LENGTH_BITS = 128; // Standard 128-bit authentication tag

    private final SecureRandom secureRandom;

    public CryptoService() {
        this.secureRandom = new SecureRandom();
    }

    // =========================================================================
    // 1. CLIENT-SIDE SHA-256 HASHING & K-ANONYMITY PREFIX SPLITTING
    // =========================================================================

    /**
     * Computes the SHA-256 cryptographic hash of a plaintext credential.
     *
     * @param plainCredential Plaintext password or secret to hash
     * @return Uppercase 64-character hexadecimal SHA-256 digest
     */
    public String hashCredential(String plainCredential) {
        Objects.requireNonNull(plainCredential, "Plaintext credential cannot be null");
        try {
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
            byte[] hashBytes = digest.digest(plainCredential.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Standard algorithm " + HASH_ALGORITHM + " unavailable", e);
        }
    }

    /**
     * Computes SHA-256 and decomposes into K-Anonymity components:
     * - First 5 hex chars as prefix (safe to transmit)
     * - Remainder as suffix (kept confidential on the client)
     *
     * @param plainCredential Raw credential
     * @return HashSplit containing fullHash, prefix, and suffix
     */
    public HashSplit splitCredential(String plainCredential) {
        String fullHash = hashCredential(plainCredential);
        return splitHash(fullHash);
    }

    /**
     * Splits an existing hexadecimal hash into a 5-char prefix and remaining suffix.
     *
     * @param fullHash Hexadecimal hash string (at least 6 characters)
     * @return HashSplit object
     */
    public HashSplit splitHash(String fullHash) {
        Objects.requireNonNull(fullHash, "Hash cannot be null");
        String normalized = fullHash.trim().toUpperCase();
        if (normalized.length() <= PREFIX_LENGTH) {
            throw new IllegalArgumentException("Hash length must be greater than " + PREFIX_LENGTH + " characters.");
        }
        String prefix = normalized.substring(0, PREFIX_LENGTH);
        String suffix = normalized.substring(PREFIX_LENGTH);
        return new HashSplit(normalized, prefix, suffix);
    }

    // =========================================================================
    // 2. FIELD-LEVEL END-TO-END ENCRYPTION (AES/GCM/NoPadding, 256-bit)
    // =========================================================================

    /**
     * Generates a cryptographically strong 256-bit AES SecretKey.
     *
     * @return 256-bit SecretKey
     */
    public SecretKey generateAESKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(KEY_ALGORITHM);
            keyGen.init(AES_KEY_SIZE_BITS, secureRandom);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("AES algorithm not supported by JDK provider", e);
        }
    }

    /**
     * Reconstructs an AES SecretKey from a Base64-encoded raw key string.
     *
     * @param base64Key Base64 encoded 256-bit key
     * @return SecretKey
     */
    public SecretKey importKeyFromBase64(String base64Key) {
        Objects.requireNonNull(base64Key, "Base64 key cannot be null");
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        if (keyBytes.length != (AES_KEY_SIZE_BITS / 8)) {
            throw new IllegalArgumentException("Invalid AES key size. Expected 256 bits (32 bytes), got " + (keyBytes.length * 8) + " bits");
        }
        return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
    }

    /**
     * Exports a SecretKey into a Base64 string for storage or secure transmission.
     *
     * @param key SecretKey
     * @return Base64 encoded string
     */
    public String exportKeyToBase64(SecretKey key) {
        Objects.requireNonNull(key, "SecretKey cannot be null");
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Encrypts a sensitive payload using AES/GCM/NoPadding with a fresh 12-byte random IV.
     * The resulting payload format is: [12-byte IV] + [Ciphertext + 16-byte Auth Tag], encoded in Base64.
     *
     * @param plainText Sensitive log or alert payload
     * @param key       256-bit SecretKey
     * @return Base64-encoded encrypted envelope
     * @throws GeneralSecurityException if encryption fails
     */
    public String encryptPayload(String plainText, SecretKey key) throws GeneralSecurityException {
        Objects.requireNonNull(plainText, "plainText cannot be null");
        Objects.requireNonNull(key, "SecretKey cannot be null");

        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv); // Generate cryptographically unique IV per operation

        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        // Pack [IV (12 bytes)] + [Ciphertext & Auth Tag]
        ByteBuffer buffer = ByteBuffer.allocate(iv.length + cipherBytes.length);
        buffer.put(iv);
        buffer.put(cipherBytes);

        return Base64.getEncoder().encodeToString(buffer.array());
    }

    /**
     * Decrypts a Base64-encoded envelope generated by encryptPayload().
     * Verifies the 128-bit authentication tag before releasing decrypted plaintext.
     *
     * @param encryptedBase64 Base64-encoded IV + ciphertext envelope
     * @param key             256-bit SecretKey
     * @return Decrypted UTF-8 plaintext string
     * @throws GeneralSecurityException if ciphertext is tampered or key is invalid
     */
    public String decryptPayload(String encryptedBase64, SecretKey key) throws GeneralSecurityException {
        Objects.requireNonNull(encryptedBase64, "encryptedBase64 cannot be null");
        Objects.requireNonNull(key, "SecretKey cannot be null");

        byte[] envelope = Base64.getDecoder().decode(encryptedBase64);
        int minLength = GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / 8);
        if (envelope.length < minLength) {
            throw new IllegalArgumentException("Corrupted or invalid ciphertext payload: insufficient length.");
        }

        ByteBuffer buffer = ByteBuffer.wrap(envelope);
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        buffer.get(iv);

        byte[] cipherBytes = new byte[buffer.remaining()];
        buffer.get(cipherBytes);

        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

        byte[] plainBytes = cipher.doFinal(cipherBytes);
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    // =========================================================================
    // UTILITY HELPERS
    // =========================================================================

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}