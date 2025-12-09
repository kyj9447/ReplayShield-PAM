package dev.replayshield.db;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.SQLException;

import dev.replayshield.security.EncryptDecrypt;
import dev.replayshield.util.PathResolver;
import dev.replayshield.util.ReplayShieldException;
import dev.replayshield.util.ReplayShieldException.ErrorType;

public final class SecureDbSession {

    private SecureDbSession() {
    }

    public static DbSession openReadOnly(byte[] key) {
        Path encFile = PathResolver.getEncryptedDbFile().toPath();
        if (!Files.exists(encFile)) {
            throw new ReplayShieldException(ErrorType.INITIALIZATION, "Encrypted DB not found. Run init first.");
        }

        Path tmp = PathResolver.createMemoryDbTempFile();
        try {
            EncryptDecrypt.decryptFile(key, encFile, tmp);
            Connection conn = Db.open(tmp);
            return new DbSession(key, encFile, tmp, conn, false);
        } catch (ReplayShieldException exception) {
            deleteQuietly(tmp);
            throw exception;
        } catch (Exception exception) {
            deleteQuietly(tmp);
            throw new ReplayShieldException(ErrorType.DATABASE_ACCESS, "Failed to open read-only DB session",
                    exception);
        }
    }

    public static DbSession openWritable(byte[] key) {
        Path encFile = PathResolver.getEncryptedDbFile().toPath();
        Path tmp = PathResolver.createMemoryDbTempFile();

        try {
            if (Files.exists(encFile)) {
                EncryptDecrypt.decryptFile(key, encFile, tmp);
            }
            Connection conn = Db.open(tmp);
            return new DbSession(key, encFile, tmp, conn, true);
        } catch (ReplayShieldException exception) {
            deleteQuietly(tmp);
            throw exception;
        } catch (Exception exception) {
            deleteQuietly(tmp);
            throw new ReplayShieldException(ErrorType.DATABASE_ACCESS, "Failed to open writable DB session", exception);
        }
    }

    public static final class DbSession implements AutoCloseable {
        private final byte[] key;
        private final Path encFile;
        private final Path tmpFile;
        private final Connection connection;
        private final boolean writable;
        private boolean closed;

        private DbSession(byte[] key, Path encFile, Path tmpFile, Connection connection, boolean writable) {
            this.key = key;
            this.encFile = encFile;
            this.tmpFile = tmpFile;
            this.connection = connection;
            this.writable = writable;
        }

        public Connection connection() {
            if (closed) {
                throw new ReplayShieldException(ErrorType.DATABASE_ACCESS, "Secure DB session already closed.");
            }
            return connection;
        }

        // AutoCloseable에 의해 try ()문 종료시 해당 메서드 호출됨
        @Override
        public void close() {
            if (closed) {
                return;
            }
            closed = true;
            ReplayShieldException pending = null;
            try {
                connection.close();
            } catch (SQLException exception) {
                pending = new ReplayShieldException(
                        ErrorType.DATABASE_ACCESS,
                        "Failed to close SQLite connection",
                        exception);
            }

            if (writable) {
                try {
                    EncryptDecrypt.encryptFile(key, tmpFile, encFile);
                } catch (ReplayShieldException exception) {
                    pending = append(pending, exception);
                } catch (Exception exception) {
                    pending = append(pending,
                            new ReplayShieldException(
                                    ErrorType.DATABASE_ACCESS,
                                    "Failed to persist encrypted DB",
                                    exception));
                }
            }

            try {
                Files.deleteIfExists(tmpFile);
            } catch (IOException exception) {
                pending = append(pending,
                        new ReplayShieldException(
                                ErrorType.SYSTEM_ENVIRONMENT,
                                "Failed to delete temporary database file",
                                exception));
            }

            if (pending != null) {
                throw pending;
            }
        }

        private static ReplayShieldException append(ReplayShieldException existing, ReplayShieldException next) {
            if (existing == null) {
                return next;
            }
            existing.addSuppressed(next);
            return existing;
        }
    }

    private static void deleteQuietly(Path tmp) {
        try {
            Files.deleteIfExists(tmp);
        } catch (IOException ignored) {
        }
    }
}
