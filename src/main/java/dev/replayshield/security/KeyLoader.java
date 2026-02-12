package dev.replayshield.security;

import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import dev.replayshield.util.CliUtils;
import dev.replayshield.util.IoUtils;
import dev.replayshield.util.PathResolver;
import dev.replayshield.util.ReplayShieldException;
import dev.replayshield.util.ReplayShieldException.ErrorType;

public class KeyLoader {
    private static final int SALT_LEN = 32;
    private static final int ITER = 200000;
    private static final int KEY_LEN = 256; // bits
    private static final byte[] ADMIN_MARKER_CONTEXT = "ReplayShieldAdminMarkerV1".getBytes(StandardCharsets.UTF_8);

    public static boolean saltExists() {
        return PathResolver.getSaltFile().exists();
    }

    private static byte[] generateSalt() {
        try {
            byte[] salt = new byte[SALT_LEN];
            SecureRandom.getInstanceStrong().nextBytes(salt);
            return salt;
        } catch (NoSuchAlgorithmException exception) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Failed to acquire secure random instance",
                    exception);
        }
    }

    private static char[] passwordPrompt(String prompt) {
        System.out.print(prompt);
        Console console = CliUtils.requireInteractiveConsole();
        return console.readPassword();
    }

    // 평문 패스워드 Salt 암호화
    private static byte[] deriveKey(char[] pw, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(pw, salt, ITER, KEY_LEN);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return skf.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException exception) {
            throw new ReplayShieldException(ErrorType.ADMIN_AUTH, "Failed to derive admin key", exception);
        }
    }

    private static void saveSalt(byte[] salt) {
        try {
            Files.write(PathResolver.getSaltFile().toPath(), salt);
        } catch (IOException exception) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Failed to write salt file", exception);
        }
    }

    private static byte[] buildAdminMarkerDigest(byte[] key) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(ADMIN_MARKER_CONTEXT);
            sha256.update(key);
            return sha256.digest();
        } catch (NoSuchAlgorithmException exception) {
            throw new ReplayShieldException(ErrorType.ADMIN_AUTH, "SHA-256 digest not available", exception);
        }
    }

    private static void saveAdminMarker(byte[] key) {
        PathResolver.writeAdminMarker(buildAdminMarkerDigest(key));
    }

    // ================================================
    // INIT 모드 - admin 암호 설정 + 사용자별 encrypted DB 스토리지 초기화
    // ================================================
    public static boolean initializeAdminPassword() {
        char[] p1 = passwordPrompt("Set admin password: ");
        char[] p2 = passwordPrompt("Confirm admin password: ");

        if (!Arrays.equals(p1, p2)) {
            System.out.println("Passwords do not match. Aborting.");
            Arrays.fill(p1, '\0');
            Arrays.fill(p2, '\0');
            return false;
        }

        byte[] salt = generateSalt();
        saveSalt(salt);

        byte[] key = deriveKey(p1, salt);
        Arrays.fill(p1, '\0');
        Arrays.fill(p2, '\0');

        AdminKeyHolder.setKey(key);
        PathResolver.deleteAllUserEncryptedDbs();
        PathResolver.deleteAdminMarkerIfExists();
        saveAdminMarker(key);
        System.out.println("Encrypted user DB directory initialized at: " + PathResolver.getEncryptedDbDir());

        return true;
    }

    // ================================================
    // 실행 시 admin 암호 검증
    // ================================================
    public static byte[] verifyAdminPassword() {
        if (!saltExists()) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Salt not found. Run init first.");
        }

        char[] pw = passwordPrompt("ReplayShield Admin password: ");
        byte[] salt;
        try {
            salt = Files.readAllBytes(PathResolver.getSaltFile().toPath());
        } catch (IOException exception) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Failed to load salt file", exception);
        }

        byte[] key = deriveKey(pw, salt);
        Arrays.fill(pw, '\0');

        verifyKeyAgainstStorage(key);

        return key;
    }

    public static byte[] changeAdminPassword(byte[] currentKey) {
        if (currentKey == null || currentKey.length == 0) {
            throw new ReplayShieldException(ErrorType.ADMIN_AUTH, "Current admin key is not available.");
        }
        if (!saltExists()) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Salt not found. Run init first.");
        }

        verifyKeyAgainstStorage(currentKey);

        char[] newPw = passwordPrompt("New admin password: ");
        char[] confirm = passwordPrompt("Confirm new admin password: ");
        if (!Arrays.equals(newPw, confirm)) {
            System.out.println("Passwords do not match. Aborting.");
            Arrays.fill(newPw, '\0');
            Arrays.fill(confirm, '\0');
            return null;
        }
        Arrays.fill(confirm, '\0');

        byte[] newSalt = generateSalt();
        byte[] newKey = deriveKey(newPw, newSalt);
        Arrays.fill(newPw, '\0');

        for (String username : PathResolver.listUserEncryptedDbUsernames()) {
            Path userDb = PathResolver.getUserEncryptedDbFile(username).toPath();
            Path tmp = PathResolver.createMemoryDbTempFile();
            try {
                EncryptDecrypt.decryptFile(currentKey, userDb, tmp);
                EncryptDecrypt.encryptFile(newKey, tmp, userDb);
            } finally {
                IoUtils.deleteQuietly(tmp);
            }
        }

        saveSalt(newSalt);
        saveAdminMarker(newKey);
        Arrays.fill(newSalt, (byte) 0);
        return newKey;
    }

    // Admin 마커, 입력받은 키 검증
    private static void verifyKeyAgainstStorage(byte[] key) {

        // Admin 마커 파일 확인
        Path marker = PathResolver.getAdminMarkerFile().toPath();
        if (!Files.exists(marker)) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Admin marker not found. Run init first.");
        }

        // Admin 마커, 입력받은 키 비교
        byte[] expected = PathResolver.readAdminMarker(); // 저장된 Admin 마커
        byte[] actual = buildAdminMarkerDigest(key); // 입력받은 키로 생성한 마커
        if (!Arrays.equals(expected, actual)) { // 비교
            throw new ReplayShieldException(ErrorType.ADMIN_AUTH, "Invalid admin password.");
        }

        // return;
    }

}
