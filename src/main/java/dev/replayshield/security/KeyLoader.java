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
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import dev.replayshield.db.SecureDbSession;
import dev.replayshield.db.SecureDbSession.DbSession;
import dev.replayshield.util.IoUtils;
import dev.replayshield.util.PathResolver;
import dev.replayshield.util.ReplayShieldException;
import dev.replayshield.util.ReplayShieldException.ErrorType;

public class KeyLoader {
    private static final int SALT_LEN = 32;
    private static final int ITER = 200_000;
    private static final int KEY_LEN = 256; // bits
    private static final byte[] ADMIN_MARKER_CONTEXT = "ReplayShieldAdminMarkerV1".getBytes(StandardCharsets.UTF_8);
    private static final Path LEGACY_ENCRYPTED_DB = Path.of("/var/lib/replayshield/secure.db.enc");

    private record UserConfigRow(String username, int blockCount) {
    }

    private record PasswordPoolRow(String hash, String hint, int hitCount, int blocked, long lastUse) {
    }

    private record PasswordHistoryRow(String hash, String hint, long createdAt) {
    }

    private record LegacyUserData(
            UserConfigRow config,
            List<PasswordPoolRow> poolRows,
            List<PasswordHistoryRow> historyRows) {
    }

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
        Console console = System.console();
        if (console == null) {
            throw new ReplayShieldException(
                    ErrorType.CONFIGURATION,
                    "Interactive console required (TTY not detected)");
        }
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

    private static byte[] loadSalt() {
        try {
            return Files.readAllBytes(PathResolver.getSaltFile().toPath());
        } catch (IOException exception) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Failed to load salt file", exception);
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
        resetEncryptedStorage(key);

        return true;
    }

    private static void resetEncryptedStorage(byte[] key) {
        PathResolver.deleteAllUserEncryptedDbs();
        PathResolver.deleteAdminMarkerIfExists();
        try {
            Files.deleteIfExists(LEGACY_ENCRYPTED_DB);
        } catch (IOException exception) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Failed to clean legacy encrypted DB", exception);
        }
        saveAdminMarker(key);
        System.out.println("Encrypted user DB directory initialized at: " + PathResolver.getEncryptedDbDir());
    }

    // ================================================
    // 실행 시 admin 암호 검증
    // ================================================
    public static byte[] verifyAdminPassword() {
        if (!saltExists()) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Salt not found. Run init first.");
        }

        char[] pw = passwordPrompt("ReplayShield Admin password: ");
        byte[] salt = loadSalt();

        byte[] key = deriveKey(pw, salt);
        Arrays.fill(pw, '\0');

        verifyKeyAgainstStorage(key);
        migrateLegacySingleDbIfNeeded(key);

        return key;
    }

    private static void verifyKeyAgainstStorage(byte[] key) {
        Path marker = PathResolver.getAdminMarkerFile().toPath();
        if (Files.exists(marker)) {
            byte[] expected = PathResolver.readAdminMarker();
            byte[] actual = buildAdminMarkerDigest(key);
            if (!Arrays.equals(expected, actual)) {
                throw new ReplayShieldException(ErrorType.ADMIN_AUTH, "Invalid admin password.");
            }
            return;
        }

        Path firstUserDb = findAnyUserDbPath();
        if (firstUserDb != null) {
            verifyKeyAgainstDbFile(key, firstUserDb);
            saveAdminMarker(key);
            return;
        }

        if (Files.exists(LEGACY_ENCRYPTED_DB)) {
            verifyKeyAgainstDbFile(key, LEGACY_ENCRYPTED_DB);
            saveAdminMarker(key);
            return;
        }

        throw new ReplayShieldException(ErrorType.INITIALIZATION, "ReplayShield storage not found. Run init first.");
    }

    private static Path findAnyUserDbPath() {
        List<String> users = PathResolver.listUserEncryptedDbUsernames();
        if (users.isEmpty()) {
            return null;
        }
        return PathResolver.getUserEncryptedDbFile(users.get(0)).toPath();
    }

    private static void verifyKeyAgainstDbFile(byte[] key, Path encFile) {
        try (DbSession session = SecureDbSession.openReadOnly(key, encFile)) {
            verifySqliteMasterReadable(session.connection());
        } catch (ReplayShieldException exception) {
            throw new ReplayShieldException(
                    ErrorType.ADMIN_AUTH,
                    "Invalid admin password (DB decryption failed)",
                    exception);
        }
    }

    private static void verifySqliteMasterReadable(Connection conn) {
        try (Statement st = conn.createStatement()) {
            st.executeQuery("SELECT name FROM sqlite_master LIMIT 1");
        } catch (SQLException exception) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.DATABASE_ACCESS,
                    "Failed to verify SQLite master table",
                    exception);
        }
    }

    private static void migrateLegacySingleDbIfNeeded(byte[] key) {
        if (!Files.exists(LEGACY_ENCRYPTED_DB)) {
            return;
        }
        if (PathResolver.hasAnyUserEncryptedDb()) {
            return;
        }

        List<LegacyUserData> legacyUsers = loadLegacyUsers(key, LEGACY_ENCRYPTED_DB);
        for (LegacyUserData legacyUser : legacyUsers) {
            writeLegacyUserToEncryptedDb(key, legacyUser);
        }

        try {
            Files.deleteIfExists(LEGACY_ENCRYPTED_DB);
        } catch (IOException exception) {
            throw new ReplayShieldException(
                    ErrorType.SYSTEM_ENVIRONMENT,
                    "Failed to remove legacy encrypted DB after migration.",
                    exception);
        }

        if (!legacyUsers.isEmpty()) {
            System.out.println("Migrated legacy encrypted DB to per-user files at: " + PathResolver.getEncryptedDbDir());
        }
    }

    private static List<LegacyUserData> loadLegacyUsers(byte[] key, Path legacyEncFile) {
        List<LegacyUserData> users = new ArrayList<>();
        try (DbSession session = SecureDbSession.openReadOnly(key, legacyEncFile)) {
            Connection conn = session.connection();

            try (PreparedStatement userPs = conn.prepareStatement("""
                    SELECT username, block_count
                    FROM user_config
                    ORDER BY username
                    """);
                    ResultSet userRs = userPs.executeQuery()) {
                while (userRs.next()) {
                    String username = userRs.getString("username");
                    int blockCount = userRs.getInt("block_count");

                    List<PasswordPoolRow> poolRows = new ArrayList<>();
                    try (PreparedStatement poolPs = conn.prepareStatement("""
                            SELECT pw_hash, pw_hint, hit_count, blocked, last_use
                            FROM password_pool
                            WHERE username=?
                            ORDER BY id
                            """)) {
                        poolPs.setString(1, username);
                        try (ResultSet poolRs = poolPs.executeQuery()) {
                            while (poolRs.next()) {
                                poolRows.add(new PasswordPoolRow(
                                        poolRs.getString("pw_hash"),
                                        poolRs.getString("pw_hint"),
                                        poolRs.getInt("hit_count"),
                                        poolRs.getInt("blocked"),
                                        poolRs.getLong("last_use")));
                            }
                        }
                    }

                    List<PasswordHistoryRow> historyRows = new ArrayList<>();
                    try (PreparedStatement historyPs = conn.prepareStatement("""
                            SELECT pw_hash, pw_hint, created_at
                            FROM password_history
                            WHERE username=?
                            ORDER BY id
                            """)) {
                        historyPs.setString(1, username);
                        try (ResultSet historyRs = historyPs.executeQuery()) {
                            while (historyRs.next()) {
                                historyRows.add(new PasswordHistoryRow(
                                        historyRs.getString("pw_hash"),
                                        historyRs.getString("pw_hint"),
                                        historyRs.getLong("created_at")));
                            }
                        }
                    }

                    users.add(new LegacyUserData(
                            new UserConfigRow(username, blockCount),
                            poolRows,
                            historyRows));
                }
            }
        } catch (SQLException exception) {
            throw new ReplayShieldException(
                    ErrorType.DATABASE_ACCESS,
                    "Failed to load legacy encrypted DB for migration.",
                    exception);
        }
        return users;
    }

    private static void writeLegacyUserToEncryptedDb(byte[] key, LegacyUserData legacyUser) {
        Path userDbFile = PathResolver.getUserEncryptedDbFile(legacyUser.config().username()).toPath();
        try (DbSession session = SecureDbSession.openWritable(key, userDbFile)) {
            Connection conn = session.connection();

            try (PreparedStatement userPs = conn.prepareStatement("""
                    INSERT INTO user_config(username, block_count)
                    VALUES(?, ?)
                    """)) {
                userPs.setString(1, legacyUser.config().username());
                userPs.setInt(2, legacyUser.config().blockCount());
                userPs.executeUpdate();
            }

            try (PreparedStatement poolPs = conn.prepareStatement("""
                    INSERT INTO password_pool(username, pw_hash, pw_hint, hit_count, blocked, last_use)
                    VALUES(?, ?, ?, ?, ?, ?)
                    """)) {
                for (PasswordPoolRow row : legacyUser.poolRows()) {
                    poolPs.setString(1, legacyUser.config().username());
                    poolPs.setString(2, row.hash());
                    poolPs.setString(3, row.hint());
                    poolPs.setInt(4, row.hitCount());
                    poolPs.setInt(5, row.blocked());
                    poolPs.setLong(6, row.lastUse());
                    poolPs.executeUpdate();
                }
            }

            try (PreparedStatement historyPs = conn.prepareStatement("""
                    INSERT INTO password_history(username, pw_hash, pw_hint, created_at)
                    VALUES(?, ?, ?, ?)
                    """)) {
                for (PasswordHistoryRow row : legacyUser.historyRows()) {
                    historyPs.setString(1, legacyUser.config().username());
                    historyPs.setString(2, row.hash());
                    historyPs.setString(3, row.hint());
                    historyPs.setLong(4, row.createdAt());
                    historyPs.executeUpdate();
                }
            }
        } catch (SQLException exception) {
            throw new ReplayShieldException(
                    ErrorType.DATABASE_ACCESS,
                    "Failed to write migrated user DB for " + legacyUser.config().username(),
                    exception);
        }
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

        reEncryptAllUserDbFiles(currentKey, newKey);
        if (Files.exists(LEGACY_ENCRYPTED_DB)) {
            reEncryptFile(LEGACY_ENCRYPTED_DB, currentKey, newKey);
        }

        saveSalt(newSalt);
        saveAdminMarker(newKey);
        Arrays.fill(newSalt, (byte) 0);
        return newKey;
    }

    private static void reEncryptAllUserDbFiles(byte[] currentKey, byte[] newKey) {
        for (String username : PathResolver.listUserEncryptedDbUsernames()) {
            Path userDb = PathResolver.getUserEncryptedDbFile(username).toPath();
            reEncryptFile(userDb, currentKey, newKey);
        }
    }

    private static void reEncryptFile(Path encFile, byte[] currentKey, byte[] newKey) {
        Path tmp = PathResolver.createMemoryDbTempFile();
        try {
            EncryptDecrypt.decryptFile(currentKey, encFile, tmp);
            EncryptDecrypt.encryptFile(newKey, tmp, encFile);
        } finally {
            IoUtils.deleteQuietly(tmp);
        }
    }
}
