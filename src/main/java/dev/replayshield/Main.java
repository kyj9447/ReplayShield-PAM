package dev.replayshield;

import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import dev.replayshield.db.SecureDbSession;
import dev.replayshield.db.SecureDbSession.DbSession;
import dev.replayshield.security.AdminKeyHolder;
import dev.replayshield.security.KeyLoader;
import dev.replayshield.server.HttpAuthServer;
import dev.replayshield.util.PathResolver;
import dev.replayshield.util.ReplayShieldException;
import dev.replayshield.util.ReplayShieldException.ErrorType;

public class Main {

    // 콘솔 선언
    public static final Console CONSOLE = System.console();

    public static void main(String[] args) {

        // sudo 검사
        if (!"root".equals(System.getProperty("user.name"))) {
            throw new ReplayShieldException(ErrorType.CONFIGURATION,
                    "This command must be run as root (sudo).");
        }

        // 종료용 server 변수
        HttpAuthServer server = null;

        // 메인 플로우 실행
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
                case "init" -> {
                    // 콘솔 사용 가능 먼저 확인
                    if (CONSOLE == null) {
                        throw new ReplayShieldException(
                                ReplayShieldException.ErrorType.CONFIGURATION,
                                "Interactive console required (TTY not detected)");
                    }
                    runInitMode();
                }
                case "manage" -> {
                    // 콘솔 사용 가능 먼저 확인
                    if (CONSOLE == null) {
                        throw new ReplayShieldException(
                                ReplayShieldException.ErrorType.CONFIGURATION,
                                "Interactive console required (TTY not detected)");
                    }
                    runManageMode();
                }
                case "serve" ->
                    server = runServerMode(); // server 인스턴스 받음 (종료용)
                case "debugdb" ->
                    // ============[TEST]==============
                    runDebugDbDump();
                default -> {
                    System.err.println("Unknown command. Use --help.");
                }
            }

        } catch (ReplayShieldException e) {
            if (e.getType() == ErrorType.SYSTEM_ENVIRONMENT) {
                System.err.println("[FATAL] " + e.getMessage());
            } else {
                System.err.println("[ERROR] " + e.getMessage());
            }
        } catch (IOException | NoSuchAlgorithmException | NumberFormatException
                | SQLException exception) {
            System.err.println("[ERROR] " + exception.getMessage());
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

            // String answer = sc.nextLine().trim().toLowerCase();
            String answer = CONSOLE.readLine().toLowerCase();
            if (!"yes".equals(answer)) {
                System.out.println("Initialization aborted.");
                return;
            }

            // 파일 삭제
            Files.deleteIfExists(PathResolver.getSaltFile().toPath());
            Files.deleteIfExists(PathResolver.getEncryptedDbFile().toPath());
        }

        // 실제 init 진행
        if (KeyLoader.initializeAdminPassword()) {
            System.out.println("Initialization complete.");
            System.out.println("Run 'replayshield serve' to start the server.");
            System.out.println("or 'systemctl restart replayshield' to apply changes.");
        } else {
            System.out.println("Initialization aborted.");
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

        // Scanner sc = new Scanner(System.in);
        boolean running = true;

        while (running) {
            String prompt = "1) Add new user\n2) Manage user\n3) Debug DB dump\n0) Exit\n>";
            int sel = readInt(prompt);

            switch (sel) {
                case 1 ->
                    manageAddUser(key);
                case 2 ->
                    manageUserMenu(key);
                case 3 ->
                    runDebugDbDumpInternal(key);
                case 0 ->
                    running = false;
                default ->
                    System.out.println("Unknown menu.");
            }
        }
        System.out.println("Exiting...");
    }

    private static void manageAddUser(byte[] key)
            throws SQLException, NoSuchAlgorithmException, ReplayShieldException {

        String username;
        while (true) {
            System.out.print("New username (type CANCEL to cancel): ");
            username = CONSOLE.readLine().trim();
            if ("CANCEL".equalsIgnoreCase(username)) {
                return;
            }
            if (username.isEmpty()) {
                System.out.println("Username cannot be empty.");
                continue;
            }

            // username 중복검사
            boolean exists;
            try (SecureDbSession.DbSession session = SecureDbSession.openReadOnly(key);
                    PreparedStatement ps = session.connection()
                            .prepareStatement("SELECT 1 FROM user_config WHERE username=?")) {
                ps.setString(1, username);
                try (ResultSet rs = ps.executeQuery()) {
                    exists = rs.next();
                }
            }

            if (exists) {
                System.out.println("Username already exists. Choose another.");
            } else {
                break;
            }
        }

        // 비밀번호 최소 3개 이상
        System.out.println("Enter at least 3 passwords (blank line to finish):");
        List<char[]> pwList = new ArrayList<>();

        while (true) {
            System.out.print("Password #" + (pwList.size() + 1) + ": ");
            char[] input = CONSOLE.readPassword();
            if (input.length == 0) {
                if (pwList.size() < 3) {
                    System.out.println("At least 3 passwords are required.");
                    continue;
                }
                break;
            }

            // 중복검사
            boolean duplicate = pwList.stream()
                    .anyMatch(existing -> Arrays.equals(existing, input));
            if (duplicate) {
                System.out.println("This password was already entered. Please use a different one.");
                Arrays.fill(input, '\0'); // 즉시 삭제
                continue;
            }

            // 목록에 추가
            pwList.add(input);
        }

        // block 수 지정
        int maxPwCount = pwList.size();
        int blockCount;

        while (true) {
            String prompt = "Block count (0 ~ " + (maxPwCount - 1) + "): ";
            blockCount = readInt(prompt);
            if (blockCount >= 0 && blockCount < maxPwCount) {
                break; // 올바른 범위면 반복 종료
            }
            System.out.println("block_count must be between 0 and " + (maxPwCount - 1));
        }

        // DB 저장 진행
        try (DbSession session = SecureDbSession.openWritable(key)) {
            Connection conn = session.connection();
            try (PreparedStatement ps = conn.prepareStatement("""
                        INSERT INTO user_config(username, block_count)
                        VALUES(?, ?)
                    """)) {
                ps.setString(1, username);
                ps.setInt(2, blockCount);
                ps.executeUpdate();
            }

            for (char[] pw : pwList) {
                String hash = PamAuthPasswordUtil.hashPassword(pw);
                String hint = PamAuthPasswordUtil.makeHint(pw);
                try (PreparedStatement ps = conn.prepareStatement("""
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

        // 입력한 암호 삭제
        for (char[] pw : pwList) {
            Arrays.fill(pw, '\0');
        }
    }

    private static void manageUserMenu(byte[] key)
            throws SQLException, ReplayShieldException, NoSuchAlgorithmException {
        String username;
        while (true) {
            System.out.print("Target username (type CANCEL to cancel): ");
            username = CONSOLE.readLine().trim();
            if ("CANCEL".equalsIgnoreCase(username)) {
                return; // 사용자 취소
            }
            if (username.isEmpty()) {
                System.out.println("Username required.");
                continue;
            }

            boolean exists;
            try (SecureDbSession.DbSession session = SecureDbSession.openReadOnly(key);
                    PreparedStatement ps = session.connection()
                            .prepareStatement("SELECT 1 FROM user_config WHERE username=?")) {
                ps.setString(1, username);
                try (ResultSet rs = ps.executeQuery()) {
                    exists = rs.next();
                }
            }

            if (exists) {
                break; // 루프 탈출, 해당 사용자로 다음 단계 진행
            }
            System.out.println("User not found.");
        }

        boolean running = true;
        while (running) {
            System.out.println();
            System.out.println("[Manage User: " + username + "]");
            String prompt = "1) Show PW pool\n2) Add password\n3) Delete password\n4) Change block_count\n0) Back\n> \n\n\n";
            int sel = readInt(prompt);

            switch (sel) {
                case 1 ->
                    showUserPwPool(key, username);
                case 2 ->
                    addUserPassword(key, username);
                case 3 ->
                    deleteUserPassword(key, username);
                case 4 ->
                    changeUserBlockCount(key, username);
                case 0 ->
                    running = false;
                default ->
                    System.out.println("Unknown menu.");
            }
        }
    }

    private static void showUserPwPool(byte[] key, String username) throws SQLException, ReplayShieldException {
        try (SecureDbSession.DbSession session = SecureDbSession.openReadOnly(key)) {
            Connection conn = session.connection();
            try (PreparedStatement ps = conn.prepareStatement("""
                        SELECT id, pw_hint, hit_count, blocked
                        FROM password_pool
                        WHERE username=?
                        ORDER BY id
                    """)) {
                ps.setString(1, username);
                try (ResultSet rs = ps.executeQuery()) {
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

    private static void addUserPassword(byte[] key, String username)
            throws SQLException, NoSuchAlgorithmException, ReplayShieldException {

        // 1) 기존 해시 목록 수집
        Set<String> existingHashes = new HashSet<>();
        try (var session = SecureDbSession.openReadOnly(key);
                var ps = session.connection().prepareStatement(
                        "SELECT pw_hash FROM password_pool WHERE username=?")) {
            ps.setString(1, username);
            try (var rs = ps.executeQuery()) {
                while (rs.next()) {
                    existingHashes.add(rs.getString(1));
                }
            }
        }

        // 2) 새 암호 입력
        char[] pw;
        while (true) {
            System.out.print("New password: ");
            pw = CONSOLE.readPassword();

            // 길이검사
            if (pw.length == 0) {
                System.out.println("Password cannot be empty.");
                continue;
            }

            // 중복검사
            String newHash = PamAuthPasswordUtil.hashPassword(pw);
            if (existingHashes.contains(newHash)) {
                System.out.println("This password is already registered. Enter a different one.");
                Arrays.fill(pw, '\0'); // 즉시 삭제
                continue;
            }

            // 새 암호 INSERT
            String hint = PamAuthPasswordUtil.makeHint(pw);
            Arrays.fill(pw, '\0'); // 사용 후 지우기
            // 3) writable 세션에서 INSERT
            try (var session = SecureDbSession.openWritable(key);
                    var ps = session.connection().prepareStatement("""
                                INSERT INTO password_pool(username, pw_hash, pw_hint, hit_count, blocked)
                                VALUES(?, ?, ?, 0, 0)
                            """)) {
                ps.setString(1, username);
                ps.setString(2, newHash);
                ps.setString(3, hint);
                ps.executeUpdate();
            }
            System.out.println("Password added.");
            break;
        }
    }

    private static void deleteUserPassword(byte[] key, String username)
            throws SQLException, ReplayShieldException {

        // 삭제 대상 암호 선택
        int id;
        while (true) {
            // PW Pool 먼저 출력
            showUserPwPool(key, username);

            id = readInt("Password ID to delete (0 to cancel): ");

            if (id == 0) {
                System.out.println("Deletion canceled.");
                return;
            }

            if (id > 0) {
                try (SecureDbSession.DbSession session = SecureDbSession.openWritable(key)) {
                    Connection conn = session.connection();
                    try (PreparedStatement ps = conn.prepareStatement("""
                                DELETE FROM password_pool
                                WHERE id = ? AND username = ?
                            """)) {
                        ps.setInt(1, id);
                        ps.setString(2, username);
                        int n = ps.executeUpdate(); // 삭제된 행 수
                        if (n > 0) {
                            System.out.println("Password deleted.");
                        } else {
                            System.out.println("No such password for this user.");
                        }
                    }
                }
            }

            System.out.println("ID must be positive.");
        }

    }

    private static void changeUserBlockCount(byte[] key, String username)
            throws SQLException, ReplayShieldException {
        // 현재 PW 갯수 확인
        int pwCount;
        try (SecureDbSession.DbSession session = SecureDbSession.openReadOnly(key)) {
            Connection conn = session.connection();
            try (PreparedStatement ps = conn.prepareStatement("""
                        SELECT COUNT(*) FROM password_pool WHERE username=?
                    """)) {
                ps.setString(1, username);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    pwCount = rs.getInt(1);
                }
            }
        }

        // DB 오류 등으로 해당 사용자의 암호가 2개 미만인 경우 return
        if (pwCount <= 1) {
            System.out.println("Need at least 2 passwords to set block_count.");
            return;
        }

        int bc;
        while (true) {
            String prompt = "New block_count (1 ~ " + (pwCount - 1) + "): ";
            bc = readInt(prompt);
            if (bc >= 1 && bc < pwCount) {
                break; // 조건 만족 시 탈출
            }
            System.out.println("block_count must be between 1 and " + (pwCount - 1));
        }

        // DB UPDATE
        try (DbSession session = SecureDbSession.openWritable(key)) {
            Connection conn = session.connection();
            try (PreparedStatement ps = conn.prepareStatement("""
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
            Connection conn = session.connection();
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
    // 내부 유틸
    // ================================
    // 비밀번호 해시/힌트용
    static class PamAuthPasswordUtil {

        static String hashPassword(char[] pw) throws NoSuchAlgorithmException {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] bytes = new String(pw).getBytes(StandardCharsets.UTF_8);
            byte[] digest = md.digest(bytes);
            Arrays.fill(bytes, (byte) 0); // 사용 후 지우기
            return Base64.getEncoder().encodeToString(digest);
        }

        static String makeHint(char[] pw) {
            // if (pw == null || pw.length == 0) {
            // return "****";
            // }
            // if (pw.length == 1) {
            // return pw[0] + "***";
            // }

            // 길이정보 삭제
            char first = pw[0];
            char last = pw[pw.length - 1];
            return first + "*****" + last;
        }
    }

    // 숫자 입력받기용 헬퍼 함수
    private static int readInt(String prompt) {
        System.out.print(prompt);
        while (true) {
            String line = CONSOLE.readLine().trim();
            try {
                return Integer.parseInt(line);
            } catch (NumberFormatException e) {
                System.out.println("Invalid number. Please enter an integer.");
            }
        }
    }

}
