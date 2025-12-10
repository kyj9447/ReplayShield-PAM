package dev.replayshield.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import dev.replayshield.Main;
import dev.replayshield.db.SecureDbSession;
import dev.replayshield.db.SecureDbSession.DbSession;
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
        } catch (NoSuchAlgorithmException exception) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Failed to acquire secure random instance",
                    exception);
        }
    }

    // ========= PW input =========
    private static char[] passwordPrompt(String prompt) {
        System.out.print(prompt);
        return Main.CONSOLE.readPassword();
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

    private static byte[] loadSalt() {
        try {
            return Files.readAllBytes(PathResolver.getSaltFile().toPath());
        } catch (IOException exception) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Failed to load salt file", exception);
        }
    }

    // ================================================
    // INIT 모드 - admin 암호 설정 + fresh encrypted DB 생성
    // ================================================
    public static boolean initializeAdminPassword() {

        // 암호 입력
        char[] p1 = passwordPrompt("Set admin password: ");
        char[] p2 = passwordPrompt("Confirm admin password: ");

        if (!Arrays.equals(p1, p2)) {
            System.out.println("Passwords do not match. Aborting.");
            Arrays.fill(p1, '\0');
            Arrays.fill(p2, '\0');
            return false;
        }

        // salt 생성
        byte[] salt = generateSalt();
        saveSalt(salt);

        // 키 생성
        byte[] key = deriveKey(p1, salt);

        Arrays.fill(p1, '\0');
        Arrays.fill(p2, '\0');

        AdminKeyHolder.setKey(key);

        // 암호화된 DB 생성
        createFreshEncryptedDb(key);

        // 해당 과정 예외없이 끝났을때 true return
        return true;
    }

    // fresh DB 생성
    private static void createFreshEncryptedDb(byte[] key) {

        // 파일 삭제 다시 확인
        Path encFile = PathResolver.getEncryptedDbFile().toPath();
        try {
            Files.deleteIfExists(encFile);
        } catch (IOException exception) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Failed to clean old encrypted DB", exception);
        }

        // SecureDbSession 내부에서 tmpfs DB 생성 → 스키마 자동 생성 → 암호화 저장
        try (DbSession session = SecureDbSession.openWritable(key)) {
            session.connection(); // 연결 -> 스키마 자동 생성
            // try문 종료시 session.close() 자동 호출
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

        char[] pw = passwordPrompt("Admin password: ");
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

        // key로 읽기상태로 세션 시작
        try (DbSession session = SecureDbSession.openReadOnly(key)) {
            // 마스터 테이블 읽기 시도
            verifySqliteMasterReadable(session.connection());
        } catch (ReplayShieldException exception) {
            // DB 세션 열기 실패
            throw new ReplayShieldException(
                    ErrorType.ADMIN_AUTH,
                    "Invalid admin password (DB decryption failed)",
                    exception);
        }
    }

    private static void verifySqliteMasterReadable(Connection conn) {
        try (Statement st = conn.createStatement();) {
            st.executeQuery("SELECT name FROM sqlite_master LIMIT 1");
        } catch (SQLException exception) {
            // DB 마스터 테이블 읽기 실패
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.DATABASE_ACCESS,
                    "Failed to verify SQLite master table",
                    exception);
        }
    }
}
