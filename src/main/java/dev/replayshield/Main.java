package dev.replayshield;

import java.io.Console;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import dev.replayshield.db.SecureDbSession;
import dev.replayshield.security.AdminKeyHolder;
import dev.replayshield.security.KeyLoader;
import dev.replayshield.server.HttpAuthServer;
import dev.replayshield.task.ManageTask;
import dev.replayshield.task.ServerTask;
import dev.replayshield.util.AsciiTable;
import dev.replayshield.util.BenchmarkUtils;
import dev.replayshield.util.CliUtils;
import dev.replayshield.util.ErrorReporter;
import dev.replayshield.util.PathResolver;
import dev.replayshield.util.ReplayShieldException;
import dev.replayshield.util.ReplayShieldException.ErrorType;

public class Main {

    public static final Console CONSOLE = System.console();

    private static final String USAGE = """
            Usage: replayshield <command>
            init : admin credentials and database
            manage : administrator CLI
            serve : Start HTTP auth server
            password : Cache admin password in RAM for headless serve
            benchmark : compare single-db vs per-user-db auth flow
            """;

    // main() 함수: 핵심 처리 로직 실행
    public static void main(String[] args) {

        // critical 오류 로깅 핸들러
        Thread.setDefaultUncaughtExceptionHandler(
                (thread, throwable) -> ErrorReporter.logFatal("Thread " + thread.getName(), throwable));

        // 루트 권한 확인
        if (!"root".equals(System.getProperty("user.name"))) {
            System.err.println("This command must be run as root (sudo).");
            return;
        }

        // 서버 인스턴스
        HttpAuthServer server = null;

        try {
            // 파일 시스템 및 기본 디렉토리 준비
            PathResolver.ensureMemoryFsAvailable();
            PathResolver.ensureBaseDirs();

            // --help
            if (args.length == 0 || "--help".equals(args[0]) || "help".equals(args[0])) {
                System.out.println(USAGE);
                return;
            }

            // 나머지 명령어 처리
            switch (args[0]) {
                case "init" -> {
                    CliUtils.requireInteractiveConsole();
                    runInitMode();
                }
                case "manage" -> {
                    CliUtils.requireInteractiveConsole();
                    runManageMode();
                }
                case "serve" -> {
                    // 서버 모드 실행
                    server = runServerMode();

                    // 메인 스레드 대기
                    synchronized (server) {
                        try {
                            server.wait();
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            System.out.println("Main thread interrupted. Signaling server to stop.");
                        }
                    }
                }
                case "password" -> {
                    CliUtils.requireInteractiveConsole();
                    cacheAdminPassword();
                }
                case "benchmark" -> runBenchmarkMode(args);
                default -> System.err.println("Unknown command. Use --help.");
            }
        } catch (ReplayShieldException exception) {
            if (exception.getType() == ErrorType.SYSTEM_ENVIRONMENT) {
                ErrorReporter.logFatal("main", exception);
            } else {
                ErrorReporter.logError("main", exception);
            }
        } catch (IOException | NoSuchAlgorithmException | NumberFormatException
                | SQLException exception) {
            ErrorReporter.logError("main", exception);
        } finally {
            // 서버 정리
            if (server != null) {
                server.stop(1);
            }
            AdminKeyHolder.clear();
        }
    }

    // ================================
    // INIT 모드
    // ================================
    private static void runInitMode() throws IOException {

        // 기존 데이터 확인
        boolean saltExists = KeyLoader.saltExists();
        boolean userDbExists = PathResolver.hasAnyUserEncryptedDb();
        boolean markerExists = PathResolver.getAdminMarkerFile().exists();

        // 경고 및 재초기화
        if (saltExists || userDbExists || markerExists) {
            System.out.println("""
                    ██╗    ██╗  █████╗ ██████╗ ███╗   ██╗███╗   ██╗██╗███╗   ██╗ ██████╗
                    ██║    ██║ ██╔══██╗██╔══██╗████╗  ██║████╗  ██║██║████╗  ██║██╔════╝
                    ██║ █╗ ██║ ███████║██████╔╝██╔██╗ ██║██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
                    ██║███╗██║ ██╔══██║██╔═██║ ██║╚██╗██║██║╚██╗██║██║██║╚██╗██║██║   ██║
                    ╚███╔███╔╝ ██║  ██║██║ ╚██╗██║ ╚████║██║ ╚████║██║██║ ╚████║╚██████╔╝
                     ╚══╝╚══╝  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝
                    """);
            System.out.println("WARNING: ReplayShield is already initialized.");
            System.out.println("This will DELETE existing:");
            System.out.println("- /etc/replayshield/salt.bin");
            System.out.println("- /var/lib/replayshield/users/*.db.enc");
            System.out.println("- /var/lib/replayshield/users/inactive/*.db.enc");
            System.out.println("- /var/lib/replayshield/admin.marker");
            System.out.println("All user data and PW pools will be permanently lost.");
            System.out.print("Are you sure you want to reinitialize? (yes/no): ");

            // 초기화 사용자 확인
            String answer = CONSOLE.readLine().toLowerCase();
            if (!"yes".equals(answer)) {
                System.out.println("Initialization aborted.");
                return;
            }

            // 기존 파일 삭제
            Files.deleteIfExists(PathResolver.getSaltFile().toPath());
            PathResolver.deleteAllUserEncryptedDbs();
            PathResolver.deleteAdminMarkerIfExists();
        }

        // 초기화 수행
        if (KeyLoader.initializeAdminPassword()) {
            System.out.println("Initialization complete.");
            System.out.println("Run 'replayshield serve' to start the server.");
            System.out.println("or 'systemctl restart replayshield' to apply changes.");
        } else {
            System.out.println("Initialization aborted.");
        }
    }

    // ================================
    // MANAGE 모드 (관리자 CLI)
    // ================================
    private static void runManageMode() throws SQLException, ReplayShieldException, NoSuchAlgorithmException {

        // Admin 키 입력받아서 메모리에 로드
        byte[] key = KeyLoader.verifyAdminPassword();
        AdminKeyHolder.setKey(key);

        // 관리 메뉴 (루프)
        CliUtils.consoleClear(null);
        boolean running = true;
        while (running) {
            String prompt = """
                    1) Add new user
                    2) Manage user
                    3) Delete user
                    4) Change admin password
                    9) DB dump
                    0) Exit
                    >""";
            int sel = CliUtils.readInt(prompt);
            switch (sel) {
                case 1 -> ManageTask.manageAddUser(key);
                case 2 -> ManageTask.manageUserMenu(key);
                case 3 -> ManageTask.manageDeleteUser(key);
                case 4 -> ManageTask.manageChangeAdminPassword(key);
                case 9 -> manageDebugDbDumpInternal(key);
                case 0 -> running = false; // 종료
                default -> System.out.println("Unknown menu.");
            }
        }
        System.out.println("Exiting...");
    }

    // ================================
    // SERVER 모드
    // ================================
    private static HttpAuthServer runServerMode() throws IOException {

        // 서버 사용자와 DB 파일 이름 불일치 정리
        ServerTask.moveUnknownUserDbsToInactive();

        // Admin 키 캐시에서 읽기
        byte[] key = ServerTask.tryConsumeCachedAdminKey();
        if (key == null) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.CONFIGURATION,
                    "No cached admin password found. Run 'replayshield password' before starting the server.");
        }

        // 서버 시작
        AdminKeyHolder.setKey(key);
        int port = HttpAuthServer.DEFAULT_PORT;
        HttpAuthServer server = new HttpAuthServer(port, key);
        server.start();
        System.out.println("ReplayShield server running on port " + port);
        System.out.println("Use Ctrl+C to stop.");
        return server;
    }

    // ================================
    // PASSWORD 모드
    // ================================
    private static void cacheAdminPassword() {

        // 현재 Admin 키 확인
        CliUtils.consoleClear("[ Cache Admin Password ]");
        byte[] key = KeyLoader.verifyAdminPassword();
        Path cachePath = PathResolver.getAdminKeyCacheFile().toPath();

        try {
            Path parent = cachePath.getParent();
            if (parent != null && !Files.exists(parent)) {
                Files.createDirectories(parent);
            }
            Files.write(cachePath, key);
            try {
                Files.setPosixFilePermissions(cachePath, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException ignored) {
            }
            System.out.println("Admin password cached in RAM: " + cachePath);
            System.out.println("Run 'sudo systemctl start replayshield' before the next reboot to reuse it.");
        } catch (IOException exception) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                    "Failed to cache admin password.",
                    exception);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    // ================================
    // BENCHMARK 모드
    // ================================
    private static void runBenchmarkMode(String[] args) throws IOException, SQLException, NoSuchAlgorithmException {
        BenchmarkUtils.runBenchmarkMode(args);
    }

    // ================================
    // DEBUG DB (테스트용)
    // ================================
    private static void manageDebugDbDumpInternal(byte[] key) throws SQLException, ReplayShieldException {
        CliUtils.consoleClear(null);
        List<String> usernames = PathResolver.listUserEncryptedDbUsernames();
        if (usernames.isEmpty()) {
            System.out.println("No users found.");
            return;
        }

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        for (String username : usernames) {
            Path userDbFile = PathResolver.getUserEncryptedDbFile(username).toPath();
            System.out.println("==================================================");
            System.out.println("USER DB: " + username + " (" + userDbFile + ")");
            System.out.println("==================================================");

            try (SecureDbSession.DbSession session = SecureDbSession.openReadOnly(key, userDbFile)) {
                Connection conn = session.connection();

                System.out.println("--------------------------------------------------");
                System.out.println("TABLE: user_config");
                System.out.println("--------------------------------------------------");
                try (PreparedStatement ps = conn.prepareStatement(
                        "SELECT username, block_count FROM user_config ORDER BY username");
                        ResultSet rs = ps.executeQuery()) {
                    AsciiTable table = AsciiTable.columnBuilder()
                            .addColumn("USER", 20, AsciiTable.Align.LEFT)
                            .addColumn("block_count", 12, AsciiTable.Align.RIGHT)
                            .build();
                    while (rs.next()) {
                        table.addRow(
                                rs.getString(1),
                                String.valueOf(rs.getInt(2)));
                    }
                    System.out.println(table.render());
                }
                System.out.println();

                System.out.println("--------------------------------------------------");
                System.out.println("TABLE: password_pool");
                System.out.println("--------------------------------------------------");
                try (PreparedStatement ps = conn.prepareStatement("""
                        SELECT id, username, pw_hash, pw_hint, hit_count, blocked, last_use
                        FROM password_pool
                        ORDER BY id
                        """);
                        ResultSet rs = ps.executeQuery()) {
                    AsciiTable table = AsciiTable.columnBuilder()
                            .addColumn("ID", 4, AsciiTable.Align.RIGHT)
                            .addColumn("USER", 15, AsciiTable.Align.LEFT)
                            .addColumn("PW HASH", 44, AsciiTable.Align.LEFT)
                            .addColumn("HINT", 10, AsciiTable.Align.LEFT)
                            .addColumn("HIT", 5, AsciiTable.Align.RIGHT)
                            .addColumn("BLOCKED", 7, AsciiTable.Align.CENTER)
                            .addColumn("LAST USE", 17, AsciiTable.Align.LEFT)
                            .build();
                    while (rs.next()) {
                        long lastUseValue = rs.getLong("last_use");
                        String lastUse = lastUseValue > 0 ? sdf.format(new Date(lastUseValue)) : "-";
                        table.addRow(
                                String.valueOf(rs.getInt("id")),
                                rs.getString("username"),
                                rs.getString("pw_hash"),
                                rs.getString("pw_hint"),
                                String.valueOf(rs.getInt("hit_count")),
                                rs.getInt("blocked") == 1 ? "YES" : "NO",
                                lastUse);
                    }
                    System.out.println(table.render());
                }
                System.out.println();

                System.out.println("--------------------------------------------------");
                System.out.println("TABLE: password_history");
                System.out.println("--------------------------------------------------");
                try (PreparedStatement ps = conn.prepareStatement("""
                        SELECT id, username, pw_hash, pw_hint, created_at
                        FROM password_history
                        ORDER BY id
                        """);
                        ResultSet rs = ps.executeQuery()) {
                    AsciiTable table = AsciiTable.columnBuilder()
                            .addColumn("ID", 4, AsciiTable.Align.RIGHT)
                            .addColumn("USER", 15, AsciiTable.Align.LEFT)
                            .addColumn("PW HASH", 44, AsciiTable.Align.LEFT)
                            .addColumn("HINT", 10, AsciiTable.Align.LEFT)
                            .addColumn("TIME", 19, AsciiTable.Align.LEFT)
                            .build();
                    while (rs.next()) {
                        long ts = rs.getLong("created_at");
                        String time = sdf.format(new Date(ts));
                        table.addRow(
                                String.valueOf(rs.getInt("id")),
                                rs.getString("username"),
                                rs.getString("pw_hash"),
                                rs.getString("pw_hint"),
                                time);
                    }
                    System.out.println(table.render());
                }
                System.out.println();
            }
        }

        System.out.println("=== END OF DEBUG DUMP ===");
    }
}
