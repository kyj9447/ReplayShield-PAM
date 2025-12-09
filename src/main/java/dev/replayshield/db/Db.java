package dev.replayshield.db;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import dev.replayshield.util.ReplayShieldException;
import dev.replayshield.util.ReplayShieldException.ErrorType;

public class Db {

    public static Connection open(Path dbPath) {
        try {
            // 클래스 로드
            Class.forName("org.sqlite.JDBC");

            boolean newDb = !Files.exists(dbPath) || Files.size(dbPath) == 0;
            String url = "jdbc:sqlite:" + dbPath.toAbsolutePath();
            Connection conn = DriverManager.getConnection(url);

            if (newDb) {
                initSchema(conn);
            } else {
                ensureSchema(conn);
            }

            return conn;
        } catch (ReplayShieldException exception) {
            throw exception;
        } catch (IOException | ClassNotFoundException | SQLException exception) {
            throw new ReplayShieldException(ErrorType.DATABASE_ACCESS, "Failed to open SQLite database", exception);
        }
    }

    private static void ensureSchema(Connection conn) {
        try (Statement st = conn.createStatement();
                ResultSet rs = st.executeQuery(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='user_config'")) {
            if (!rs.next()) {
                initSchema(conn);
            }
        } catch (SQLException exception) {
            throw new ReplayShieldException(ErrorType.DATABASE_ACCESS, "Failed to validate database schema", exception);
        }
    }

    private static void initSchema(Connection conn) {
        try (Statement st = conn.createStatement()) {
            st.execute("""
                        CREATE TABLE IF NOT EXISTS user_config (
                            username TEXT PRIMARY KEY,
                            block_count INTEGER NOT NULL
                        )
                    """);

            st.execute("""
                        CREATE TABLE IF NOT EXISTS password_pool (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL,
                            pw_hash TEXT NOT NULL,
                            pw_hint TEXT NOT NULL,
                            hit_count INTEGER NOT NULL DEFAULT 0,
                            blocked INTEGER NOT NULL DEFAULT 0,
                            FOREIGN KEY(username) REFERENCES user_config(username)
                        )
                    """);

            st.execute("""
                        CREATE TABLE IF NOT EXISTS password_history (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL,
                            pw_hash TEXT NOT NULL,
                            pw_hint TEXT NOT NULL,
                            created_at INTEGER NOT NULL,
                            FOREIGN KEY(username) REFERENCES user_config(username)
                        )
                    """);
        } catch (SQLException exception) {
            throw new ReplayShieldException(ErrorType.DATABASE_ACCESS, "Failed to initialize database schema",
                    exception);
        }
    }
}
