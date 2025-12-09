package dev.replayshield;

import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

import dev.replayshield.db.SecureDbSession;
import dev.replayshield.security.AdminKeyHolder;
import dev.replayshield.security.KeyLoader;
import dev.replayshield.server.HttpAuthServer;
import dev.replayshield.util.PathResolver;
import dev.replayshield.util.ReplayShieldException;

public class Main {

    // 콘솔 선언
    public static final Console CONSOLE = System.console();

    public static void main(String[] args) {

        // 콘솔 사용 가능 먼저 확인
        if (CONSOLE == null) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.CONFIGURATION,
                    "Interactive console required (TTY not detected)");
        }

        // 종료용 server 변수
        HttpAuthServer server = null;

        try {
            // /dev/shm이 tmpfs이고 사용 가능한지 먼저 확인
            PathResolver.ensureMemoryFsAvailable();
            PathResolver.ensureBaseDirs();

            // 도움말 출력
            if (args.length == 0 || "--help".equals(args[0]) || "help".equals(args[0])) {
                System.out.println(USAGE);
                return;
            }

            // ======= 모드 분기 =======
            switch (args[0]) {
                case "init" ->
                    runInitMode();
                case "manage" ->
                    runManageMode();
                case "serve" ->
                    server = runServerMode(); // server 인스턴스 받음 (종료용)
                case "debugdb" ->
                    // ============[TEST]==============
                    runDebugDbDump();
                default -> {
                    System.err.println("Unknown command. Use --help.");
                }
            }

        } catch (ReplayShieldException | IOException | NoSuchAlgorithmException | NumberFormatException
                | SQLException exception) {
            System.err.println("[FATAL] " + exception.getMessage());
        } finally {
            if (server != null) {
                server.stop(1); // 필요에 따라 delay 지정
            }
            AdminKeyHolder.clear();
        }
    }

    private static final String USAGE = """
            Usage: replayshield <command>
              init      Initialize admin credentials and database
              manage    Open administrator CLI
              serve     Start HTTP auth server
              debugdb   Dump database contents (debug/test)
            """;

    // ================================
    // INIT 모드
    // ================================
    private static void runInitMode() throws IOException {
        System.out.println("=== ReplayShield Initial Setup ===");

        boolean saltExists = KeyLoader.saltExists(); // salt파일 존재 확인
        boolean encDbExists = PathResolver.getEncryptedDbFile().exists(); // db파일 존재 확인

        try (Scanner sc = new Scanner(System.in)) {
            if (saltExists || encDbExists) {
                System.out.println("""
                        ██╗    ██╗ █████╗ ██████╗ ███╗   ██╗███╗   ██╗██╗███╗   ██╗ ██████╗
                        ██║    ██║██╔══██╗██╔══██╗████╗  ██║████╗  ██║██║████╗  ██║██╔════╝
                        ██║ █╗ ██║███████║██████╔╝██╔██╗ ██║██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
                        ██║███╗██║██╔══██║██╔═██║ ██║╚██╗██║██║╚██╗██║██║██║╚██╗██║██║   ██║
                        ╚███╔███╔╝██║  ██║██║ ╚██╗██║ ╚████║██║ ╚████║██║██║ ╚████║╚██████╔╝
                         ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝
                            """);
                System.out.println("WARNING: ReplayShield is already initialized.");
                System.out.println("This will DELETE existing:");
                System.out.println("  - /etc/replayshield/salt.bin");
                System.out.println("  - /var/lib/replayshield/secure.db.enc");
                System.out.println("All user data and PW pools will be permanently lost.");
                System.out.print("Are you sure you want to reinitialize? (yes/no): ");

                String answer = sc.nextLine().trim().toLowerCase();
                if (!"yes".equals(answer)) {
                    System.out.println("Initialization aborted.");
                    return;
                }

                Files.deleteIfExists(PathResolver.getSaltFile().toPath());
                Files.deleteIfExists(PathResolver.getEncryptedDbFile().toPath());
            }

            if (KeyLoader.initializeAdminPassword()) {
                System.out.println("Initialization complete.");
                System.out.println("Run 'replayshield serve' to start the server.");
            } else {
                System.out.println("Initialization aborted.");
            }
        }
    }

    // ================================
    // SERVER 모드
    // ================================
    private static HttpAuthServer runServerMode() throws IOException {
        System.out.println("=== ReplayShield Server Mode ===");
        byte[] key = KeyLoader.verifyAdminPassword();
        AdminKeyHolder.setKey(key);

        int port = 8080;
        HttpAuthServer server = new HttpAuthServer(port, key);
        server.start();
        System.out.println("ReplayShield server running on port " + port);
        System.out.println("Use Ctrl+C to stop.");
        return server; // main()에 서버 종료용으로 인스턴스 반환
    }

    // ================================
    // MANAGE 모드 (관리자 CLI)
    // ================================
    private static void runManageMode() throws SQLException, ReplayShieldException, NoSuchAlgorithmException {
        System.out.println("=== ReplayShield Manage CLI ===");
        byte[] key = KeyLoader.verifyAdminPassword();
        AdminKeyHolder.setKey(key);

        Scanner sc = new Scanner(System.in);
        boolean running = true;

        while (running) {
            System.out.println();
            System.out.println("1) Add new user");
            System.out.println("2) Manage user");
            System.out.println("3) Debug DB dump");
            System.out.println("0) Exit");
            System.out.print("> ");
            String sel = sc.nextLine().trim();

            switch (sel) {
                case "1" ->
                    manageAddUser(key, sc);
                case "2" ->
                    manageUserMenu(key, sc);
                case "3" ->
                    runDebugDbDumpInternal(key);
                case "0" ->
                    running = false;
                default ->
                    System.out.println("Unknown menu.");
            }
        }
    }

    private static void manageAddUser(byte[] key, Scanner sc)
            throws SQLException, NoSuchAlgorithmException, ReplayShieldException {
        System.out.print("New username: ");
        String username = sc.nextLine().trim();
        if (username.isEmpty()) {
            System.out.println("Username cannot be empty.");
            return;
        }

        // 비밀번호 최소 3개 이상
        System.out.println("Enter at least 3 passwords (blank line to finish):");
        java.util.List<String> pwList = new java.util.ArrayList<>();
        while (true) {
            System.out.print("Password #" + (pwList.size() + 1) + ": ");
            String pw = sc.nextLine();
            if (pw.isEmpty()) {
                if (pwList.size() < 3) {
                    System.out.println("At least 3 passwords are required.");
                    continue;
                } else {
                    break;
                }
            }
            pwList.add(pw);
        }

        int maxPwCount = pwList.size();
        System.out.print("Block count (0 ~ " + (maxPwCount - 1) + "): ");
        int blockCount = Integer.parseInt(sc.nextLine().trim());
        if (blockCount < 0 || blockCount >= maxPwCount) {
            System.out.println("block_count must be between 0 and " + (maxPwCount - 1));
            return;
        }

        try (SecureDbSession.DbSession session = SecureDbSession.openWritable(key)) {
            var conn = session.connection();
            try (var ps = conn.prepareStatement("""
                        INSERT INTO user_config(username, block_count)
                        VALUES(?, ?)
                    """)) {
                ps.setString(1, username);
                ps.setInt(2, blockCount);
                ps.executeUpdate();
            }

            for (String pw : pwList) {
                String hash = PamAuthPasswordUtil.hashPassword(pw);
                String hint = PamAuthPasswordUtil.makeHint(pw);
                try (var ps = conn.prepareStatement("""
                            INSERT INTO password_pool(username, pw_hash, pw_hint, hit_count, blocked)
                            VALUES(?, ?, ?, 0, 0)
                        """)) {
                    ps.setString(1, username);
                    ps.setString(2, hash);
                    ps.setString(3, hint);
                    ps.executeUpdate();
                }
            }
            System.out.println("User created: " + username);
        }
    }

    private static void manageUserMenu(byte[] key, Scanner sc)
            throws SQLException, ReplayShieldException, NoSuchAlgorithmException {
        System.out.print("Target username: ");
        String username = sc.nextLine().trim();
        if (username.isEmpty()) {
            System.out.println("Username required.");
            return;
        }

        boolean exists;
        try (SecureDbSession.DbSession session = SecureDbSession.openReadOnly(key)) {
            var conn = session.connection();
            try (var ps = conn.prepareStatement("SELECT block_count FROM user_config WHERE username=?")) {
                ps.setString(1, username);
                try (var rs = ps.executeQuery()) {
                    if (rs.next()) {
                        System.out.println("User: " + username + ", block_count=" + rs.getInt(1));
                        exists = true;
                    } else {
                        exists = false;
                    }
                }
            }
        }

        if (!exists) {
            System.out.println("User not found.");
            return;
        }

        boolean running = true;
        while (running) {
            System.out.println();
            System.out.println("[Manage User: " + username + "]");
            System.out.println("1) Show PW pool");
            System.out.println("2) Add password");
            System.out.println("3) Delete password");
            System.out.println("4) Change block_count");
            System.out.println("0) Back");
            System.out.print("> ");
            String sel = sc.nextLine().trim();

            switch (sel) {
                case "1" ->
                    showUserPwPool(key, username);
                case "2" ->
                    addUserPassword(key, username, sc);
                case "3" ->
                    deleteUserPassword(key, username, sc);
                case "4" ->
                    changeUserBlockCount(key, username, sc);
                case "0" ->
                    running = false;
                default ->
                    System.out.println("Unknown menu.");
            }
        }
    }

    private static void showUserPwPool(byte[] key, String username) throws SQLException, ReplayShieldException {
        try (SecureDbSession.DbSession session = SecureDbSession.openReadOnly(key)) {
            var conn = session.connection();
            try (var ps = conn.prepareStatement("""
                        SELECT id, pw_hint, hit_count, blocked
                        FROM password_pool
                        WHERE username=?
                        ORDER BY id
                    """)) {
                ps.setString(1, username);
                try (var rs = ps.executeQuery()) {
                    System.out.println("ID   | HINT       | HIT  | BLOCKED");
                    while (rs.next()) {
                        System.out.printf("%-4d | %-10s | %-4d | %s%n",
                                rs.getInt("id"),
                                rs.getString("pw_hint"),
                                rs.getInt("hit_count"),
                                rs.getInt("blocked") == 1 ? "YES" : "NO");
                    }
                }
            }
        }
    }

    private static void addUserPassword(byte[] key, String username, Scanner sc)
            throws SQLException, NoSuchAlgorithmException, ReplayShieldException {
        System.out.print("New password: ");
        String pw = sc.nextLine();
        if (pw.isEmpty()) {
            System.out.println("Password cannot be empty.");
            return;
        }

        try (SecureDbSession.DbSession session = SecureDbSession.openWritable(key)) {
            var conn = session.connection();
            String hash = PamAuthPasswordUtil.hashPassword(pw);
            String hint = PamAuthPasswordUtil.makeHint(pw);
            try (var ps = conn.prepareStatement("""
                        INSERT INTO password_pool(username, pw_hash, pw_hint, hit_count, blocked)
                        VALUES(?, ?, ?, 0, 0)
                    """)) {
                ps.setString(1, username);
                ps.setString(2, hash);
                ps.setString(3, hint);
                ps.executeUpdate();
            }
            System.out.println("Password added.");
        }
    }

    private static void deleteUserPassword(byte[] key, String username, Scanner sc)
            throws SQLException, ReplayShieldException {
        System.out.print("Password ID to delete: ");
        int id = Integer.parseInt(sc.nextLine().trim());

        try (SecureDbSession.DbSession session = SecureDbSession.openWritable(key)) {
            var conn = session.connection();
            try (var ps = conn.prepareStatement("""
                        DELETE FROM password_pool
                        WHERE id = ? AND username = ?
                    """)) {
                ps.setInt(1, id);
                ps.setString(2, username);
                int n = ps.executeUpdate();
                if (n > 0) {
                    System.out.println("Password deleted.");
                } else {
                    System.out.println("No such password for this user.");
                }
            }
        }
    }

    private static void changeUserBlockCount(byte[] key, String username, Scanner sc)
            throws SQLException, ReplayShieldException {
        // 현재 PW 갯수 확인
        int pwCount;
        try (SecureDbSession.DbSession session = SecureDbSession.openReadOnly(key)) {
            var conn = session.connection();
            try (var ps = conn.prepareStatement("""
                        SELECT COUNT(*) FROM password_pool WHERE username=?
                    """)) {
                ps.setString(1, username);
                try (var rs = ps.executeQuery()) {
                    rs.next();
                    pwCount = rs.getInt(1);
                }
            }
        }

        if (pwCount <= 1) {
            System.out.println("Need at least 2 passwords to set block_count.");
            return;
        }

        System.out.print("New block_count (0 ~ " + (pwCount - 1) + "): ");
        int bc = Integer.parseInt(sc.nextLine().trim());

        if (bc < 0 || bc >= pwCount) {
            System.out.println("block_count must be between 0 and " + (pwCount - 1));
            return;
        }

        try (SecureDbSession.DbSession session = SecureDbSession.openWritable(key)) {
            var conn = session.connection();
            try (var ps = conn.prepareStatement("""
                        UPDATE user_config SET block_count=? WHERE username=?
                    """)) {
                ps.setInt(1, bc);
                ps.setString(2, username);
                ps.executeUpdate();
                System.out.println("block_count updated.");
            }
        }
    }

    // ================================
    // DEBUG DB (테스트용)
    // ================================
    private static void runDebugDbDump() throws SQLException, ReplayShieldException {
        System.out.println("=== ReplayShield DB Debug Dump ===");
        byte[] key = KeyLoader.verifyAdminPassword();
        AdminKeyHolder.setKey(key);
        runDebugDbDumpInternal(key);
    }

    private static void runDebugDbDumpInternal(byte[] key) throws SQLException, ReplayShieldException {
        try (SecureDbSession.DbSession session = SecureDbSession.openReadOnly(key)) {
            var conn = session.connection();
            try (Statement st = conn.createStatement()) {
                System.out.println("--------------------------------------------------");
                System.out.println("TABLE: user_config");
                System.out.println("--------------------------------------------------");
                try (ResultSet rs = st.executeQuery(
                        "SELECT username, block_count FROM user_config ORDER BY username")) {
                    while (rs.next()) {
                        System.out.printf("USER=%-20s | block_count=%d%n",
                                rs.getString(1), rs.getInt(2));
                    }
                }

                System.out.println();
                System.out.println("--------------------------------------------------");
                System.out.println("TABLE: password_pool");
                System.out.println("--------------------------------------------------");
                try (ResultSet rs = st.executeQuery("""
                            SELECT id, username, pw_hash, pw_hint, hit_count, blocked
                            FROM password_pool
                            ORDER BY username, id
                        """)) {
                    while (rs.next()) {
                        System.out.printf(
                                "ID=%-4d USER=%-15s HASH=%s%n   HINT=%s | hit=%d | blocked=%s%n",
                                rs.getInt("id"),
                                rs.getString("username"),
                                rs.getString("pw_hash"),
                                rs.getString("pw_hint"),
                                rs.getInt("hit_count"),
                                rs.getInt("blocked") == 1 ? "YES" : "NO");
                    }
                }

                System.out.println();
                System.out.println("--------------------------------------------------");
                System.out.println("TABLE: password_history");
                System.out.println("--------------------------------------------------");
                try (ResultSet rs = st.executeQuery("""
                            SELECT id, username, pw_hash, pw_hint, created_at
                            FROM password_history
                            ORDER BY id
                        """)) {
                    while (rs.next()) {
                        long ts = rs.getLong("created_at");
                        String time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                                .format(new Date(ts));
                        System.out.printf(
                                "ID=%-4d USER=%-15s HASH=%s%n   HINT=%s | time=%s%n",
                                rs.getInt("id"),
                                rs.getString("username"),
                                rs.getString("pw_hash"),
                                rs.getString("pw_hint"),
                                time);
                    }
                }

                System.out.println("=== END OF DEBUG DUMP ===");
            }
        }
    }

    // ================================
    // 내부 유틸 (비밀번호 해시/힌트)
    // ================================
    static class PamAuthPasswordUtil {

        static String hashPassword(String pw) throws NoSuchAlgorithmException {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(pw.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        }

        static String makeHint(String pw) {
            if (pw == null || pw.length() == 0) {
                return "****";
            }
            if (pw.length() == 1) {
                return pw.charAt(0) + "***";
            }
            char first = pw.charAt(0);
            char last = pw.charAt(pw.length() - 1);
            return first + "*****" + last;
        }
    }
}
