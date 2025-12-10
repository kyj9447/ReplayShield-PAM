package dev.replayshield.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.replayshield.db.Db;

class PamAuthHandlerTest {

    private static final Method DO_AUTH_METHOD;

    static {
        try {
            DO_AUTH_METHOD = PamAuthHandler.class.getDeclaredMethod("doAuth", Connection.class, String.class,
                    String.class);
            DO_AUTH_METHOD.setAccessible(true);
        } catch (NoSuchMethodException exception) {
            throw new ExceptionInInitializerError(exception);
        }
    }

    private final PamAuthHandler handler = new PamAuthHandler(new byte[32]);

    @TempDir
    Path tempDir;

    private final AtomicInteger dbCounter = new AtomicInteger();

    @Test
    void returnsFailWhenUserMissing() throws Exception {
        try (Connection conn = openConnection()) {
            String result = invokeDoAuth(conn, "ghost", "pw");
            assertEquals("FAIL", result);
        }
    }

    @Test
    void returnsPassAndUpdatesHistoryAndStats() throws Exception {
        try (Connection conn = openConnection()) {
            insertUser(conn, "alice", 2);
            int pwId = insertPassword(conn, "alice", "secret");

            String result = invokeDoAuth(conn, "alice", "secret");
            assertEquals("PASS", result);
            assertEquals(1, countHistory(conn, "alice"));
            assertEquals(1, fetchHitCount(conn, pwId));
        }
    }

    @Test
    void returnsKickWhenPasswordRecentlyUsed() throws Exception {
        try (Connection conn = openConnection()) {
            insertUser(conn, "bob", 2);
            int pwId = insertPassword(conn, "bob", "hunter2");
            insertHistory(conn, "bob", "hunter2", System.currentTimeMillis());

            int beforeHistory = countHistory(conn, "bob");
            String result = invokeDoAuth(conn, "bob", "hunter2");

            assertEquals("KICK", result);
            assertEquals(beforeHistory, countHistory(conn, "bob"));
            assertEquals(0, fetchHitCount(conn, pwId));
        }
    }

    private Connection openConnection() throws SQLException {
        Path dbPath = tempDir.resolve("pam-auth-" + dbCounter.incrementAndGet() + ".sqlite");
        return Db.open(dbPath);
    }

    private String invokeDoAuth(Connection conn, String username, String password) {
        try {
            return (String) DO_AUTH_METHOD.invoke(handler, conn, username, password);
        } catch (ReflectiveOperationException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private void insertUser(Connection conn, String username, int blockCount) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO user_config(username, block_count) VALUES(?, ?)")) {
            ps.setString(1, username);
            ps.setInt(2, blockCount);
            ps.executeUpdate();
        }
    }

    private int insertPassword(Connection conn, String username, String password) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO password_pool(username, pw_hash, pw_hint, hit_count, blocked) VALUES(?, ?, ?, 0, 0)",
                Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, username);
            ps.setString(2, hash(password));
            ps.setString(3, password.length() >= 2 ? password.substring(0, 1) + "*****" + password.charAt(password.length() - 1)
                    : "****");
            ps.executeUpdate();
            try (ResultSet rs = ps.getGeneratedKeys()) {
                assertTrue(rs.next());
                return rs.getInt(1);
            }
        }
    }

    private void insertHistory(Connection conn, String username, String password, long createdAt) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO password_history(username, pw_hash, pw_hint, created_at) VALUES(?, ?, ?, ?)")) {
            ps.setString(1, username);
            ps.setString(2, hash(password));
            ps.setString(3, "hist");
            ps.setLong(4, createdAt);
            ps.executeUpdate();
        }
    }

    private int countHistory(Connection conn, String username) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT COUNT(*) FROM password_history WHERE username=?")) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }

    private int fetchHitCount(Connection conn, int pwId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT hit_count FROM password_pool WHERE id=?")) {
            ps.setInt(1, pwId);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }

    private String hash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hashed);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
