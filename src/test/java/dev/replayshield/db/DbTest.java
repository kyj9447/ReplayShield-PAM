package dev.replayshield.db;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DbTest {

    @TempDir
    Path tempDir;

    @Test
    void openCreatesSchemaAndPreservesExistingData() throws Exception {
        Path dbPath = tempDir.resolve("dbtest.sqlite");

        try (Connection conn = Db.open(dbPath)) {
            assertTrue(Files.exists(dbPath));
            assertTrue(hasTable(conn, "user_config"));
            assertTrue(hasTable(conn, "password_pool"));
            assertTrue(hasTable(conn, "password_history"));
        }

        try (Connection conn = Db.open(dbPath)) {
            insertUser(conn, "alice", 2);
        }

        try (Connection conn = Db.open(dbPath);
                PreparedStatement ps = conn.prepareStatement(
                        "SELECT block_count FROM user_config WHERE username=?")) {
            ps.setString(1, "alice");
            try (ResultSet rs = ps.executeQuery()) {
                assertTrue(rs.next());
                assertEquals(2, rs.getInt(1));
            }
        }
    }

    private boolean hasTable(Connection conn, String tableName) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?")) {
            ps.setString(1, tableName);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
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
}
