package dev.replayshield.security;

import java.io.Console;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import dev.replayshield.db.SecureDbSession;
import dev.replayshield.util.PathResolver;
import dev.replayshield.util.ReplayShieldException;
import dev.replayshield.util.ReplayShieldException.ErrorType;

public class KeyLoader {

    private static final int SALT_LEN = 32;
    private static final int ITER = 200_000;
    private static final int KEY_LEN = 256; // bits

    public static boolean saltExists() {
        return PathResolver.getSaltFile().exists();
    }

    private static byte[] generateSalt() {
        try {
            byte[] salt = new byte[SALT_LEN];
            SecureRandom.getInstanceStrong().nextBytes(salt);
            return salt;
        } catch (NoSuchAlgorithmException e) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Failed to acquire secure random instance", e);
        }
    }

    // ========= PW input =========
    private static char[] readPassword(String prompt) {
        Console console = System.console();
        if (console != null) {
            System.out.print(prompt);
            return console.readPassword();
        } else {
            System.out.print(prompt);
            return new Scanner(System.in).nextLine().toCharArray();
        }
    }

    private static byte[] deriveKey(char[] pw, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(pw, salt, ITER, KEY_LEN);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return skf.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new ReplayShieldException(ErrorType.ADMIN_AUTH, "Failed to derive admin key", e);
        }
    }

    private static void saveSalt(byte[] salt) {
        try {
            Files.write(PathResolver.getSaltFile().toPath(), salt);
        } catch (IOException e) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Failed to write salt file", e);
        }
    }

    private static byte[] loadSalt() {
        try {
            return Files.readAllBytes(PathResolver.getSaltFile().toPath());
        } catch (IOException e) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Failed to load salt file", e);
        }
    }

    // ================================================
    // INIT 모드 - admin 암호 설정 + fresh encrypted DB 생성
    // ================================================
    public static boolean initializeAdminPassword() {

        char[] p1 = readPassword("Set admin password: ");
        char[] p2 = readPassword("Confirm admin password: ");

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

        createFreshEncryptedDb(key);
        return true;
    }

    // fresh DB 생성
    private static void createFreshEncryptedDb(byte[] key) {

        Path encFile = PathResolver.getEncryptedDbFile().toPath();
        try {
            Files.deleteIfExists(encFile);
        } catch (IOException e) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Failed to clean old encrypted DB", e);
        }

        // SecureDbSession 내부에서 tmpfs DB 생성 → 스키마 자동 생성 → 암호화 저장
        try (SecureDbSession.DbSession session = SecureDbSession.openWritable(key)) {
            session.connection(); // open to trigger schema creation
        }

        System.out.println("Encrypted DB created at: " + encFile);
    }

    // ================================================
    // 실행 시 admin 암호 검증
    // ================================================
    public static byte[] verifyAdminPassword() {

        if (!saltExists()) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Salt not found. Run init first.");
        }

        char[] pw = readPassword("Admin password: ");
        byte[] salt = loadSalt();

        byte[] key = deriveKey(pw, salt);
        Arrays.fill(pw, '\0');

        verifyKeyAgainstDb(key);

        return key;
    }

    // key 검증 → 복호화 후 sqlite_master 조회 가능해야 정상 key
    private static void verifyKeyAgainstDb(byte[] key) {

        Path enc = PathResolver.getEncryptedDbFile().toPath();
        if (!Files.exists(enc)) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Encrypted DB not found. Run init first.");
        }

        try (SecureDbSession.DbSession session = SecureDbSession.openReadOnly(key)) {
            verifySqliteMasterReadable(session.connection());
        } catch (ReplayShieldException e) {
            if (e.getType() == ErrorType.CRYPTO || e.getType() == ErrorType.DATABASE_ACCESS) {
                throw new ReplayShieldException(ErrorType.ADMIN_AUTH, "Invalid admin password (DB decryption failed)",
                        e);
            }
            throw e;
        } catch (Exception e) {
            throw new ReplayShieldException(ErrorType.ADMIN_AUTH, "Invalid admin password (DB decryption failed)", e);
        }
    }

    private static Object verifySqliteMasterReadable(Connection conn) throws SQLException {
        try (var st = conn.createStatement();
                var rs = st.executeQuery("SELECT name FROM sqlite_master LIMIT 1")) {
            return null;
        }
    }

}
