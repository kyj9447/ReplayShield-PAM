package dev.replayshield.task;

import java.io.Console;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import dev.replayshield.db.SecureDbSession;
import dev.replayshield.db.SecureDbSession.DbSession;
import dev.replayshield.security.AdminKeyHolder;
import dev.replayshield.security.KeyLoader;
import dev.replayshield.security.PasswordCodec;
import dev.replayshield.server.PamAuthHandler;
import dev.replayshield.util.AsciiTable;
import dev.replayshield.util.CliUtils;
import dev.replayshield.util.PathResolver;
import dev.replayshield.util.ReplayShieldException;
import dev.replayshield.util.ReplayShieldException.ErrorType;

public final class ManageTask {

    private ManageTask() {} // 인스턴스 생성 금지

    private static final Console CONSOLE = System.console();
    private static final int MIN_PASSWORD_POOL_SIZE = 3;
    private static final String USERNAME_INVALID_MESSAGE =
            "Username contains unsupported characters. Use letters, digits, '.', '_' or '-'.";

    private static String promptValidatedUsername(String prompt) {
        while (true) {
            System.out.print(prompt);
            String username = CONSOLE.readLine().trim();
            if ("CANCEL".equalsIgnoreCase(username)) {
                return null;
            }
            if (username.isEmpty()) {
                System.out.println("Username required.");
                continue;
            }
            try {
                // Validate characters; path itself is not used here.
                PathResolver.getUserEncryptedDbFile(username);
                return username;
            } catch (ReplayShieldException exception) {
                System.out.println(USERNAME_INVALID_MESSAGE);
            }
        }
    }

    public static void manageAddUser(byte[] key)
            throws SQLException, NoSuchAlgorithmException, ReplayShieldException {
        CliUtils.consoleClear("[ Add New User ]");
        String username;
        while (true) {
            username = promptValidatedUsername("New username (type CANCEL to cancel): ");
            if (username == null) {
                CliUtils.consoleClear(null);
                return;
            }
            boolean exists = PathResolver.userEncryptedDbExists(username);
            boolean existsInInactive = PathResolver.userEncryptedDbExistsInInactive(username);
            if (exists) {
                System.out.println("Username already exists. Choose another.");
            } else if (existsInInactive) {
                System.out.println("Username exists in inactive DB archive. Restore or remove it first.");
            } else {
                break;
            }
        }

        System.out.println("Enter at least " + MIN_PASSWORD_POOL_SIZE + " passwords (blank line to finish):");
        List<char[]> pwList = new ArrayList<>();
        while (true) {
            System.out.print("Password #" + (pwList.size() + 1) + ": ");
            char[] input = CONSOLE.readPassword();
            if (input.length == 0) {
                if (pwList.size() < MIN_PASSWORD_POOL_SIZE) {
                    System.out.println("At least " + MIN_PASSWORD_POOL_SIZE + " passwords are required.");
                    continue;
                }
                break;
            }
            System.out.print("Re-enter to confirm: ");
            char[] confirm = CONSOLE.readPassword();
            if (!Arrays.equals(input, confirm)) {
                System.out.println("Passwords did not match. Please try again.");
                Arrays.fill(input, '\0');
                Arrays.fill(confirm, '\0');
                continue;
            }
            Arrays.fill(confirm, '\0');

            boolean duplicate = false;
            for (char[] existing : pwList) {
                if (Arrays.equals(existing, input)) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) {
                System.out.println("This password was already entered. Please use a different one.");
                Arrays.fill(input, '\0');
                continue;
            }

            pwList.add(input);
        }

        int maxPwCount = pwList.size();
        int blockCount;
        while (true) {
            String prompt = "Block count (1 ~ " + (maxPwCount - 1) + "): ";
            blockCount = CliUtils.readInt(prompt);
            if (blockCount >= 1 && blockCount < maxPwCount) {
                break;
            }
            System.out.println("block_count must be between 1 and " + (maxPwCount - 1));
        }

        Path userDbFile = PathResolver.getUserEncryptedDbFile(username).toPath();
        try (DbSession session = SecureDbSession.openWritable(key, userDbFile)) {
            Connection conn = session.connection();
            try (PreparedStatement ps = conn.prepareStatement("""
                    INSERT INTO user_config(username, block_count)
                    VALUES(?, ?)
                    """)) {
                ps.setString(1, username);
                ps.setInt(2, blockCount);
                ps.executeUpdate();
            }
            try (PreparedStatement ps = conn.prepareStatement("""
                    INSERT INTO password_pool(username, pw_hash, pw_hint, hit_count, blocked)
                    VALUES(?, ?, ?, 0, 0)
                    """)) {
                for (char[] pw : pwList) {
                    String hash = PasswordCodec.hashPassword(pw);
                    String hint = PasswordCodec.makeHint(pw);
                    ps.setString(1, username);
                    ps.setString(2, hash);
                    ps.setString(3, hint);
                    ps.executeUpdate();
                }
            }
            CliUtils.consoleClear("[ User created : " + username + " ]");
        }

        for (char[] pw : pwList) {
            Arrays.fill(pw, '\0');
        }
    }

    public static void manageDeleteUser(byte[] key) {
        CliUtils.consoleClear("[ Delete User ]");
        while (true) {
            String username = promptValidatedUsername("Username to delete (type CANCEL to cancel): ");
            if (username == null) {
                CliUtils.consoleClear(null);
                return;
            }
            if (!PathResolver.userEncryptedDbExists(username)) {
                System.out.println("User not found.");
                continue;
            }
            System.out.print("Type DELETE to confirm removal of '" + username + "': ");
            String confirm = CONSOLE.readLine().trim();
            if (!"DELETE".equalsIgnoreCase(confirm)) {
                CliUtils.consoleClear("[ Deletion aborted. ]");
                return;
            }
            Path userDbFile = PathResolver.getUserEncryptedDbFile(username).toPath();
            try {
                Files.deleteIfExists(userDbFile);
            } catch (IOException exception) {
                throw new ReplayShieldException(
                        ErrorType.SYSTEM_ENVIRONMENT,
                        "Failed to delete user encrypted DB: " + userDbFile,
                        exception);
            }
            CliUtils.consoleClear("[ User deleted: " + username + " ]");
            return;
        }
    }

    public static void manageUserMenu(byte[] key)
            throws SQLException, ReplayShieldException, NoSuchAlgorithmException {
        String username;
        while (true) {
            username = promptValidatedUsername("Target username (type CANCEL to cancel): ");
            if (username == null) {
                CliUtils.consoleClear(null);
                return;
            }
            if (PathResolver.userEncryptedDbExists(username)) {
                CliUtils.consoleClear(null);
                break;
            }
            System.out.println("User not found.");
        }

        boolean running = true;
        while (running) {
            System.out.println("[ Manage User: " + username + " ]");
            String prompt = "1) Show PW pool\n2) Add password\n3) Delete password\n4) Change block_count\n0) Back\n>";
            int sel = CliUtils.readInt(prompt);
            switch (sel) {
                case 1 -> showUserPwPool(key, username);
                case 2 -> addUserPassword(key, username);
                case 3 -> deleteUserPassword(key, username);
                case 4 -> changeUserBlockCount(key, username);
                case 0 -> running = false;
                default -> System.out.println("Unknown menu.");
            }
        }
        CliUtils.consoleClear(null);
    }

    public static void manageChangeAdminPassword(byte[] key) {
        byte[] updated = KeyLoader.changeAdminPassword(key);
        if (updated != null) {
            AdminKeyHolder.setKey(updated);
        }
        CliUtils.consoleClear("Admin password updated.");
    }

    private static void showUserPwPool(byte[] key, String username) throws SQLException, ReplayShieldException {
        Path userDbFile = PathResolver.getUserEncryptedDbFile(username).toPath();
        try (SecureDbSession.DbSession session = SecureDbSession.openReadOnly(key, userDbFile)) {
        CliUtils.consoleClear(null);
            Connection conn = session.connection();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            try (PreparedStatement ps = conn.prepareStatement("""
                    SELECT id, pw_hint, hit_count, blocked, last_use
                    FROM password_pool
                    WHERE username=?
                    ORDER BY id
                    """)) {
                ps.setString(1, username);
                try (ResultSet rs = ps.executeQuery()) {
                    AsciiTable table = AsciiTable.columnBuilder()
                            .addColumn("ID", 4, AsciiTable.Align.RIGHT)
                            .addColumn("HINT", 10, AsciiTable.Align.LEFT)
                            .addColumn("HIT", 5, AsciiTable.Align.RIGHT)
                            .addColumn("BLOCKED", 7, AsciiTable.Align.CENTER)
                            .addColumn("LAST USE", 17, AsciiTable.Align.LEFT)
                            .build();
                    while (rs.next()) {
                        long lastUseValue = rs.getLong("last_use");
                        String lastUse = lastUseValue > 0
                                ? sdf.format(new Date(lastUseValue))
                                : "-";
                        table.addRow(
                                String.valueOf(rs.getInt("id")),
                                rs.getString("pw_hint"),
                                String.valueOf(rs.getInt("hit_count")),
                                rs.getInt("blocked") == 1 ? "YES" : "NO",
                                lastUse);
                    }
                    System.out.println();
                    System.out.println(table.render());
                    System.out.println();
                }
            }
        }
    }

    private static void addUserPassword(byte[] key, String username)
            throws SQLException, NoSuchAlgorithmException, ReplayShieldException {
        CliUtils.consoleClear("[ Manage User: " + username + " ]");
        Path userDbFile = PathResolver.getUserEncryptedDbFile(username).toPath();

        try (SecureDbSession.DbSession session = SecureDbSession.openWritable(key, userDbFile)) {
            Connection conn = session.connection();
            Set<String> existingHashes = new HashSet<>();
            try (PreparedStatement selectPs = conn.prepareStatement(
                    "SELECT pw_hash FROM password_pool WHERE username=?");
                    PreparedStatement insertPs = conn.prepareStatement("""
                            INSERT INTO password_pool(username, pw_hash, pw_hint, hit_count, blocked)
                            VALUES(?, ?, ?, 0, 0)
                            """)) {
                selectPs.setString(1, username);
                try (ResultSet rs = selectPs.executeQuery()) {
                    while (rs.next()) {
                        existingHashes.add(rs.getString(1));
                    }
                }

                while (true) {
                    System.out.print("New password: ");
                    char[] pw = CONSOLE.readPassword();

                    if (pw.length == 0) {
                        System.out.println("Password cannot be empty.");
                        continue;
                    }

                    System.out.print("Confirm password: ");
                    char[] confirm = CONSOLE.readPassword();
                    if (!Arrays.equals(pw, confirm)) {
                        System.out.println("Passwords do not match.");
                        Arrays.fill(pw, '\0');
                        Arrays.fill(confirm, '\0');
                        continue;
                    }
                    Arrays.fill(confirm, '\0');

                    String newHash = PasswordCodec.hashPassword(pw);
                    if (existingHashes.contains(newHash)) {
                        System.out.println("This password is already registered. Enter a different one.");
                        Arrays.fill(pw, '\0');
                        continue;
                    }

                    String hint = PasswordCodec.makeHint(pw);
                    Arrays.fill(pw, '\0');

                    insertPs.setString(1, username);
                    insertPs.setString(2, newHash);
                    insertPs.setString(3, hint);
                    insertPs.executeUpdate();

                    CliUtils.consoleClear("[ Password added. ]");
                    return;
                }
            }
        }
    }

    private static void deleteUserPassword(byte[] key, String username)
            throws SQLException, ReplayShieldException {
        Path userDbFile = PathResolver.getUserEncryptedDbFile(username).toPath();

        int id;
        while (true) {
            showUserPwPool(key, username);
            id = CliUtils.readInt("Password ID to delete (0 to cancel): ");
            if (id == 0) {
                CliUtils.consoleClear("[ Deletion canceled. ]");
                return;
            }
            if (id > 0) {
                try (SecureDbSession.DbSession session = SecureDbSession.openWritable(key, userDbFile)) {
                    Connection conn = session.connection();
                    int passwordCount;
                    int blockCount;

                    try (PreparedStatement ps = conn.prepareStatement("""
                            SELECT COUNT(*) FROM password_pool WHERE username=?
                            """)) {
                        ps.setString(1, username);
                        try (ResultSet rs = ps.executeQuery()) {
                            rs.next();
                            passwordCount = rs.getInt(1);
                        }
                    }

                    try (PreparedStatement ps = conn.prepareStatement("""
                            SELECT block_count FROM user_config WHERE username=?
                            """)) {
                        ps.setString(1, username);
                        try (ResultSet rs = ps.executeQuery()) {
                            if (!rs.next()) {
                                CliUtils.consoleClear("[ User not found. ]");
                                return;
                            }
                            blockCount = rs.getInt(1);
                        }
                    }

                    if (passwordCount <= MIN_PASSWORD_POOL_SIZE) {
                        CliUtils.consoleClear("[ Need at least " + MIN_PASSWORD_POOL_SIZE + " passwords per user. ]");
                        return;
                    }
                    if (blockCount <= 1) {
                        CliUtils.consoleClear("[ block_count cannot be reduced below 1. ]");
                        return;
                    }

                    int newBlockCount = blockCount - 1;
                    boolean originalAutoCommit = conn.getAutoCommit();
                    conn.setAutoCommit(false);
                    try {
                        int deleted;
                        try (PreparedStatement ps = conn.prepareStatement("""
                                DELETE FROM password_pool
                                WHERE id = ? AND username = ?
                                """)) {
                            ps.setInt(1, id);
                            ps.setString(2, username);
                            deleted = ps.executeUpdate();
                        }
                        if (deleted > 0) {
                            try (PreparedStatement ps = conn.prepareStatement("""
                                    UPDATE user_config SET block_count=? WHERE username=?
                                    """)) {
                                ps.setInt(1, newBlockCount);
                                ps.setString(2, username);
                                ps.executeUpdate();
                            }
                            PamAuthHandler.refreshBlockedState(conn, username, newBlockCount);
                            conn.commit();
                            CliUtils.consoleClear("[ Password deleted. block_count=" + newBlockCount + " ]");
                            return;
                        }
                        conn.rollback();
                        System.out.println("No such password for this user.");
                    } catch (SQLException exception) {
                        conn.rollback();
                        throw exception;
                    } finally {
                        conn.setAutoCommit(originalAutoCommit);
                    }
                }
            } else {
                System.out.println("ID must be positive.");
            }
        }
    }

    private static void changeUserBlockCount(byte[] key, String username)
            throws SQLException, ReplayShieldException {
        Path userDbFile = PathResolver.getUserEncryptedDbFile(username).toPath();

        try (SecureDbSession.DbSession session = SecureDbSession.openWritable(key, userDbFile)) {
            Connection conn = session.connection();
            int pwCount;
            try (PreparedStatement ps = conn.prepareStatement("""
                    SELECT COUNT(*) FROM password_pool WHERE username=?
                    """)) {
                ps.setString(1, username);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    pwCount = rs.getInt(1);
                }
            }
            if (pwCount <= 1) {
                System.out.println("Need at least 2 passwords to set block_count.");
                return;
            }
            int bc;
            while (true) {
                String prompt = "New block_count (1 ~ " + (pwCount - 1) + "): ";
                bc = CliUtils.readInt(prompt);
                if (bc >= 1 && bc < pwCount) {
                    break;
                }
                System.out.println("block_count must be between 1 and " + (pwCount - 1));
            }

            try (PreparedStatement ps = conn.prepareStatement("""
                    UPDATE user_config SET block_count=? WHERE username=?
                    """)) {
                ps.setInt(1, bc);
                ps.setString(2, username);
                ps.executeUpdate();
            }
            PamAuthHandler.refreshBlockedState(conn, username, bc);
            CliUtils.consoleClear("block_count updated.");
        }
    }

}
