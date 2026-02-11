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
            benchmark : measure auth flow (isolated benchmark DB)
            """;

    // main() 함수: 핵심 처리 로직 실행
    public static void main(String[] args) {
        Thread.setDefaultUncaughtExceptionHandler(
                (thread, throwable) -> ErrorReporter.logFatal("Thread " + thread.getName(), throwable));

        CliUtils.consoleClear();

        if (!"root".equals(System.getProperty("user.name"))) {
            System.err.println("This command must be run as root (sudo).");
            return;
        }

        HttpAuthServer server = null;

        try {
            PathResolver.ensureMemoryFsAvailable();
            PathResolver.ensureBaseDirs();

            if (args.length == 0 || "--help".equals(args[0]) || "help".equals(args[0])) {
                System.out.println(USAGE);
                return;
            }

            switch (args[0]) {
                case "init" -> {
                    if (CONSOLE == null) {
                        throw new ReplayShieldException(
                                ReplayShieldException.ErrorType.CONFIGURATION,
                                "Interactive console required (TTY not detected)");
                    }
                    runInitMode();
                }
                case "manage" -> {
                    if (CONSOLE == null) {
                        throw new ReplayShieldException(
                                ReplayShieldException.ErrorType.CONFIGURATION,
                                "Interactive console required (TTY not detected)");
                    }
                    runManageMode();
                }
                case "serve" -> {
                    server = runServerMode();
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
                    if (CONSOLE == null) {
                        throw new ReplayShieldException(
                                ReplayShieldException.ErrorType.CONFIGURATION,
                                "Interactive console required (TTY not detected)");
                    }
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
        boolean saltExists = KeyLoader.saltExists();
        boolean userDbExists = PathResolver.hasAnyUserEncryptedDb();
        boolean markerExists = PathResolver.getAdminMarkerFile().exists();
        boolean legacyDbExists = Files.exists(Path.of("/var/lib/replayshield/secure.db.enc"));
        if (saltExists || userDbExists || markerExists || legacyDbExists) {
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
            System.out.println("- /var/lib/replayshield/secure.db.enc (legacy)");
            System.out.println("All user data and PW pools will be permanently lost.");
            System.out.print("Are you sure you want to reinitialize? (yes/no): ");

            String answer = CONSOLE.readLine().toLowerCase();
            if (!"yes".equals(answer)) {
                System.out.println("Initialization aborted.");
                return;
            }

            Files.deleteIfExists(PathResolver.getSaltFile().toPath());
            PathResolver.deleteAllUserEncryptedDbs();
            PathResolver.deleteAdminMarkerIfExists();
            Files.deleteIfExists(Path.of("/var/lib/replayshield/secure.db.enc"));
        }

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
        byte[] key = KeyLoader.verifyAdminPassword();
        AdminKeyHolder.setKey(key);
        CliUtils.consoleClear();

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
                case 0 -> running = false;
                default -> System.out.println("Unknown menu.");
            }
        }
        System.out.println("Exiting...");
    }

    // ================================
    // DEBUG DB (테스트용)
    // ================================
    private static void manageDebugDbDumpInternal(byte[] key) throws SQLException, ReplayShieldException {
        CliUtils.consoleClear();
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

    // ================================
    // SERVER 모드
    // ================================
    private static HttpAuthServer runServerMode() throws IOException {
        byte[] key = ServerTask.tryConsumeCachedAdminKey();
        if (key == null) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.CONFIGURATION,
                    "No cached admin password found. Run 'replayshield password' before starting the server.");
        }
        ServerTask.moveUnknownUserDbsToInactive();
        AdminKeyHolder.setKey(key);
        int port = 4444;
        HttpAuthServer server = new HttpAuthServer(port, key);
        server.start();
        System.out.println("ReplayShield server running on port " + port);
        System.out.println("Use Ctrl+C to stop.");
        return server;
    }

    // ================================
    // BENCHMARK 모드
    // ================================
    public static void runBenchmarkMode(String[] args) throws IOException, SQLException, NoSuchAlgorithmException {
        if (BenchmarkUtils.containsArg(args, "--help") || BenchmarkUtils.containsArg(args, "-h")) {
            System.out.println("""
                    Usage: replayshield benchmark [options]
                      --warmup=<N>           Warmup iterations (default: 5)
                      --iterations=<N>       Measured iterations (default: 500)
                    """);
            return;
        }

        BenchmarkUtils.BenchmarkOptions options = BenchmarkUtils.parseBenchmarkOptions(args);
        CliUtils.consoleClear("[ Benchmark ]");
        System.out.println("mode       : test-db");
        System.out.println("warmup     : " + options.warmup());
        System.out.println("iterations : " + options.iterations());
        System.out.println("admin auth : not required (internal benchmark key)");
        System.out.println("scope      : handleHttpPost end-to-end (request -> PASS/FAIL)");
        System.out.println("dataset    : 1 user x 100 passwords");
        System.out.println();

        byte[] key = BenchmarkUtils.createBenchmarkKey();
        BenchmarkUtils.BenchmarkContext context = null;
        try {
            context = BenchmarkUtils.prepareBenchmarkContext(key);
            System.out.println("target user: " + context.username());
            System.out.println("test login : " + context.username() + " / " + context.password());
            System.out.println("test db    : " + context.tempEncFile());
            System.out.println();

            for (int i = 0; i < options.warmup(); i++) {
                BenchmarkUtils.runAuthBenchmarkIteration(context);
            }

            long[] totalSamples = new long[options.iterations()];
            long[] requestReadSamples = new long[options.iterations()];
            long[] formParseSamples = new long[options.iterations()];
            long[] authTotalSamples = new long[options.iterations()];
            long[] decryptSamples = new long[options.iterations()];
            long[] authLogicSamples = new long[options.iterations()];
            long[] encryptSamples = new long[options.iterations()];
            int passCount = 0;
            int failCount = 0;
            int otherCount = 0;

            for (int i = 0; i < options.iterations(); i++) {
                BenchmarkUtils.BenchmarkIteration iter = BenchmarkUtils.runAuthBenchmarkIteration(context);
                totalSamples[i] = iter.totalNanos();
                requestReadSamples[i] = iter.requestReadNanos();
                formParseSamples[i] = iter.formParseNanos();
                authTotalSamples[i] = iter.authTotalNanos();
                decryptSamples[i] = iter.decryptNanos();
                authLogicSamples[i] = iter.authLogicNanos();
                encryptSamples[i] = iter.encryptNanos();

                if ("PASS".equals(iter.result())) {
                    passCount++;
                } else if ("FAIL".equals(iter.result())) {
                    failCount++;
                } else {
                    otherCount++;
                }
            }

            BenchmarkUtils.BenchmarkSummary totalSummary = BenchmarkUtils.summarizeBenchmark(totalSamples);
            BenchmarkUtils.BenchmarkSummary requestReadSummary = BenchmarkUtils.summarizeBenchmark(requestReadSamples);
            BenchmarkUtils.BenchmarkSummary formParseSummary = BenchmarkUtils.summarizeBenchmark(formParseSamples);
            BenchmarkUtils.BenchmarkSummary authTotalSummary = BenchmarkUtils.summarizeBenchmark(authTotalSamples);
            BenchmarkUtils.BenchmarkSummary decryptSummary = BenchmarkUtils.summarizeBenchmark(decryptSamples);
            BenchmarkUtils.BenchmarkSummary authSummary = BenchmarkUtils.summarizeBenchmark(authLogicSamples);
            BenchmarkUtils.BenchmarkSummary encryptSummary = BenchmarkUtils.summarizeBenchmark(encryptSamples);

            System.out.println("Benchmark complete.");
            System.out.printf("result     : PASS=%d FAIL=%d OTHER=%d%n", passCount, failCount, otherCount);
            System.out.println();
            BenchmarkUtils.printBenchmarkSummary("end-to-end", totalSummary);
            BenchmarkUtils.printBenchmarkSummary("request-read", requestReadSummary);
            BenchmarkUtils.printBenchmarkSummary("form-parse", formParseSummary);
            BenchmarkUtils.printBenchmarkSummary("auth-total", authTotalSummary);
            BenchmarkUtils.printBenchmarkSummary("decrypt", decryptSummary);
            BenchmarkUtils.printBenchmarkSummary("auth-logic", authSummary);
            BenchmarkUtils.printBenchmarkSummary("encrypt", encryptSummary);
        } finally {
            if (context != null && context.tempEncFile() != null) {
                Path tempEncFile = context.tempEncFile();
                boolean deleted = BenchmarkUtils.deleteQuietly(tempEncFile);
                if (deleted) {
                    System.out.println("cleanup    : deleted " + tempEncFile);
                } else {
                    System.out.println("cleanup    : no file deleted " + tempEncFile);
                }
            }
            Arrays.fill(key, (byte) 0);
        }
    }

    // ================================
    // PASSWORD 모드
    // ================================
    private static void cacheAdminPassword() {
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
}
