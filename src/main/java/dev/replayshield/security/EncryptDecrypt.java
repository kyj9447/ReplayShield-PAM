// src/main/java/dev/replayshield/security/EncryptDecrypt.java
package dev.replayshield.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import dev.replayshield.util.ReplayShieldException;
import dev.replayshield.util.ReplayShieldException.ErrorType;

public class EncryptDecrypt {

    private static final int GCM_NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final SecureRandom rnd;

    static {
        SecureRandom tmp;
        try {
            tmp = SecureRandom.getInstanceStrong();
        } catch (Exception exception) {
            tmp = new SecureRandom();
        }
        rnd = tmp;
    }

    public static byte[] encrypt(byte[] key, byte[] plain) {
        try {
            byte[] iv = new byte[GCM_NONCE_LENGTH];
            rnd.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            SecretKeySpec ks = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, ks, spec);

            byte[] cipherText = cipher.doFinal(plain);

            byte[] out = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(cipherText, 0, out, iv.length, cipherText.length);
            return out;
        } catch (GeneralSecurityException exception) {
            throw new ReplayShieldException(ErrorType.CRYPTO, "Failed to encrypt data", exception);
        }
    }

    public static byte[] decrypt(byte[] key, byte[] enc) {
        if (enc.length < GCM_NONCE_LENGTH + GCM_TAG_LENGTH) {
            throw new ReplayShieldException(ErrorType.CRYPTO, "Encrypted data too short");
        }
        try {
            byte[] iv = Arrays.copyOfRange(enc, 0, GCM_NONCE_LENGTH);
            byte[] cipherText = Arrays.copyOfRange(enc, GCM_NONCE_LENGTH, enc.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            SecretKeySpec ks = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, ks, spec);

            return cipher.doFinal(cipherText);
        } catch (GeneralSecurityException exception) {
            throw new ReplayShieldException(ErrorType.CRYPTO, "Failed to decrypt data", exception);
        }
    }

    public static void encryptFile(byte[] key, Path plainFile, Path encFile) {
        try {
            byte[] plain = Files.readAllBytes(plainFile);
            byte[] enc = encrypt(key, plain);
            Files.write(encFile, enc);
            Arrays.fill(plain, (byte) 0);
        } catch (IOException exception) {
            throw new ReplayShieldException(ErrorType.CRYPTO, "Failed to encrypt database file", exception);
        }
    }

    public static void decryptFile(byte[] key, Path encFile, Path plainFile) {
        try {
            byte[] enc = Files.readAllBytes(encFile);
            byte[] plain = decrypt(key, enc);
            Files.write(plainFile, plain);
            Arrays.fill(plain, (byte) 0);
        } catch (IOException exception) {
            throw new ReplayShieldException(ErrorType.CRYPTO, "Failed to decrypt database file", exception);
        }
    }
}
