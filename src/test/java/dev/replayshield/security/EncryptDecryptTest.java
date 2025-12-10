package dev.replayshield.security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EncryptDecryptTest {

    private final SecureRandom random = new SecureRandom();

    @TempDir
    Path tempDir;

    @Test
    void encryptDecryptRoundTrip() {
        byte[] key = randomKey();
        byte[] plain = "sensitive-data".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = EncryptDecrypt.encrypt(key, plain);
        assertFalse(Arrays.equals(plain, encrypted));

        byte[] decrypted = EncryptDecrypt.decrypt(key, encrypted);
        assertArrayEquals(plain, decrypted);
    }

    @Test
    void encryptDecryptFileRoundTrip() throws Exception {
        byte[] key = randomKey();
        byte[] plain = new byte[256];
        random.nextBytes(plain);

        Path plainFile = tempDir.resolve("plain.bin");
        Path encFile = tempDir.resolve("cipher.bin");
        Path outFile = tempDir.resolve("roundtrip.bin");

        Files.write(plainFile, plain);
        EncryptDecrypt.encryptFile(key, plainFile, encFile);
        EncryptDecrypt.decryptFile(key, encFile, outFile);

        byte[] result = Files.readAllBytes(outFile);
        assertArrayEquals(plain, result);
    }

    private byte[] randomKey() {
        byte[] key = new byte[32];
        random.nextBytes(key);
        return key;
    }
}
