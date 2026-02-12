package dev.replayshield.db;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

import dev.replayshield.util.ReplayShieldException;
import dev.replayshield.util.ReplayShieldException.ErrorType;

public class Db {

    public static Connection open(Path dbPath) {
        try {
            String url = "jdbc:sqlite:" + dbPath.toAbsolutePath();
            Connection conn = DriverManager.getConnection(url);

            initSchema(conn);

            return conn;
        } catch (ReplayShieldException exception) {
            throw exception;
        } catch (SQLException exception) {
            throw new ReplayShieldException(ErrorType.DATABASE_ACCESS, "Failed to open SQLite database", exception);
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
                            last_use INTEGER NOT NULL DEFAULT 0,
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
