package dev.replayshield;

import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
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

import dev.replayshield.db.Db;
import dev.replayshield.db.SecureDbSession;
import dev.replayshield.db.SecureDbSession.DbSession;
import dev.replayshield.security.AdminKeyHolder;
import dev.replayshield.security.EncryptDecrypt;
import dev.replayshield.security.KeyLoader;
import dev.replayshield.server.HttpAuthServer;
import dev.replayshield.server.PamAuthHandler;
import dev.replayshield.util.AsciiTable;
import dev.replayshield.util.ErrorReporter;
import dev.replayshield.util.PathResolver;
import dev.replayshield.util.ReplayShieldException;
import dev.replayshield.util.ReplayShieldException.ErrorType;

public class Main {

    // 콘솔 선언
    public static final Console CONSOLE = System.console();
    private static final int MIN_PASSWORD_POOL_SIZE = 3;
    private static final int DEFAULT_BENCH_WARMUP = 5;
    private static final int DEFAULT_BENCH_ITERATIONS = 50;
    private static final int TEST_BENCH_PASSWORD_POOL_SIZE = 100;

    public static void main(String[] args) {
        Thread.setDefaultUncaughtExceptionHandler(
                (thread, throwable) -> ErrorReporter.logFatal("Thread " + thread.getName(), throwable));

        consoleClear();

        // sudo 검사
        if (!"root".equals(System.getProperty("user.name"))) {
            System.err.println("This command must be run as root (sudo).");
            return;
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
                case "serve" -> {
                    server = runServerMode(); // server 인스턴스 받음 (종료용)

                    // 서버 유지
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

                    // 콘솔 사용 가능 먼저 확인
                    if (CONSOLE == null) {
                        throw new ReplayShieldException(
                                ReplayShieldException.ErrorType.CONFIGURATION,
                                "Interactive console required (TTY not detected)");
                    }
                    cacheAdminPassword();
                }
                case "benchmark" -> {
                    if (CONSOLE == null) {
                        throw new ReplayShieldException(
                                ReplayShieldException.ErrorType.CONFIGURATION,
                                "Interactive console required (TTY not detected)");
                    }
                    runBenchmarkMode(args);
                }
                default -> {
                    System.err.println("Unknown command. Use --help.");
                }
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
            // System.out.println("FINALLY Check");
            if (server != null) {
                server.stop(1); // 필요에 따라 delay 지정
            }
            AdminKeyHolder.clear();
        }
    }

    private static final String USAGE = """
            Usage: replayshield <command>
            init : admin credentials and database
            manage : administrator CLI
            serve : Start HTTP auth server
            password : Cache admin password in RAM for headless serve
            benchmark : measure auth flow (actual DB or test DB)
            """;

    // ================================
    // INIT 모드
    // ================================
    private static void runInitMode() throws IOException {
        boolean saltExists = KeyLoader.saltExists(); // salt파일 존재 확인
        boolean encDbExists = PathResolver.getEncryptedDbFile().exists(); // db파일 존재 확인
        if (saltExists || encDbExists) {
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
            System.out.println("- /var/lib/replayshield/secure.db.enc");
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
        byte[] key = tryConsumeCachedAdminKey();
        if (key == null) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.CONFIGURATION,
                    "No cached admin password found. Run 'replayshield password' before starting the server.");
        }
        AdminKeyHolder.setKey(key);
        int port = 4444;
        HttpAuthServer server = new HttpAuthServer(port, key);
        server.start();
        System.out.println("ReplayShield server running on port " + port);
        System.out.println("Use Ctrl+C to stop.");
        return server; // main()에 서버 종료용으로 인스턴스 반환
    }

    private enum BenchmarkMode {
        ACTUAL_DB,
        TEST_DB
    }

    private record BenchmarkOptions(BenchmarkMode mode, int warmup, int iterations) {
    }

    private record BenchmarkContext(PamAuthHandler handler, String username, String password, Path tempEncFile) {
    }

    private record BenchmarkIteration(
            long totalNanos,
            long decryptNanos,
            long authLogicNanos,
            long encryptNanos,
            String result) {
    }

    private record BenchmarkSummary(
            long minNanos,
            long p50Nanos,
            long p95Nanos,
            long p99Nanos,
            long maxNanos,
            long totalNanos,
            double avgNanos,
            double throughputOpsPerSec) {
    }

    private static void runBenchmarkMode(String[] args) throws IOException, SQLException, NoSuchAlgorithmException {
        if (containsArg(args, "--help") || containsArg(args, "-h")) {
            System.out.println("""
                    Usage: replayshield benchmark [options]
                      --mode=actual|test     Benchmark mode (default: test)
                      --warmup=<N>           Warmup iterations (default: 5)
                      --iterations=<N>       Measured iterations (default: 50)
                    """);
            return;
        }

        BenchmarkOptions options = parseBenchmarkOptions(args);
        consoleClear("[ Benchmark ]");
        System.out.println("mode       : " + toBenchmarkModeLabel(options.mode()));
        System.out.println("warmup     : " + options.warmup());
        System.out.println("iterations : " + options.iterations());
        System.out.println();

        byte[] key = KeyLoader.verifyAdminPassword();
        BenchmarkContext context = null;
        try {
            context = prepareBenchmarkContext(options.mode(), key);
            System.out.println("target user: " + context.username());
            if (options.mode() == BenchmarkMode.TEST_DB) {
                System.out.println("test db    : " + context.tempEncFile());
            }
            System.out.println();

            for (int i = 0; i < options.warmup(); i++) {
                runAuthBenchmarkIteration(context);
            }

            long[] totalSamples = new long[options.iterations()];
            long[] decryptSamples = new long[options.iterations()];
            long[] authLogicSamples = new long[options.iterations()];
            long[] encryptSamples = new long[options.iterations()];
            int passCount = 0;
            int failCount = 0;
            int otherCount = 0;

            for (int i = 0; i < options.iterations(); i++) {
                BenchmarkIteration iter = runAuthBenchmarkIteration(context);
                totalSamples[i] = iter.totalNanos();
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

            BenchmarkSummary totalSummary = summarizeBenchmark(totalSamples);
            BenchmarkSummary decryptSummary = summarizeBenchmark(decryptSamples);
            BenchmarkSummary authSummary = summarizeBenchmark(authLogicSamples);
            BenchmarkSummary encryptSummary = summarizeBenchmark(encryptSamples);

            System.out.println("Benchmark complete.");
            System.out.printf("result     : PASS=%d FAIL=%d OTHER=%d%n", passCount, failCount, otherCount);
            System.out.println();
            printBenchmarkSummary("end-to-end", totalSummary);
            printBenchmarkSummary("decrypt", decryptSummary);
            printBenchmarkSummary("auth-logic", authSummary);
            printBenchmarkSummary("encrypt", encryptSummary);
            if (options.mode() == BenchmarkMode.ACTUAL_DB) {
                System.out.println("note       : actual mode updates real DB state (history/hit_count/last_use).");
            }
        } finally {
            if (context != null && context.tempEncFile() != null) {
                deleteQuietly(context.tempEncFile());
            }
            Arrays.fill(key, (byte) 0);
        }
    }

    private static BenchmarkOptions parseBenchmarkOptions(String[] args) {
        BenchmarkMode mode = BenchmarkMode.TEST_DB;
        int warmup = DEFAULT_BENCH_WARMUP;
        int iterations = DEFAULT_BENCH_ITERATIONS;

        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if (arg.startsWith("--mode=")) {
                mode = parseBenchmarkMode(arg.substring("--mode=".length()));
                continue;
            }
            if (arg.startsWith("--warmup=")) {
                warmup = parseNonNegativeIntOption("warmup", arg.substring("--warmup=".length()));
                continue;
            }
            if (arg.startsWith("--iterations=")) {
                iterations = parsePositiveIntOption("iterations", arg.substring("--iterations=".length()));
                continue;
            }
            throw new ReplayShieldException(
                    ErrorType.CONFIGURATION,
                    "Unknown benchmark option: " + arg + " (use 'replayshield benchmark --help').");
        }

        return new BenchmarkOptions(mode, warmup, iterations);
    }

    private static BenchmarkMode parseBenchmarkMode(String value) {
        String normalized = value.trim().toLowerCase();
        return switch (normalized) {
            case "actual", "actual-db" -> BenchmarkMode.ACTUAL_DB;
            case "test", "test-db", "mock" -> BenchmarkMode.TEST_DB;
            default -> throw new ReplayShieldException(
                    ErrorType.CONFIGURATION,
                    "Invalid benchmark mode: " + value + " (expected actual|test)");
        };
    }

    private static int parseNonNegativeIntOption(String name, String raw) {
        int parsed;
        try {
            parsed = Integer.parseInt(raw.trim());
        } catch (NumberFormatException exception) {
            throw new ReplayShieldException(
                    ErrorType.CONFIGURATION,
                    "Invalid integer for --" + name + ": " + raw,
                    exception);
        }
        if (parsed < 0) {
            throw new ReplayShieldException(
                    ErrorType.CONFIGURATION,
                    "--" + name + " must be >= 0");
        }
        return parsed;
    }

    private static int parsePositiveIntOption(String name, String raw) {
        int parsed = parseNonNegativeIntOption(name, raw);
        if (parsed == 0) {
            throw new ReplayShieldException(
                    ErrorType.CONFIGURATION,
                    "--" + name + " must be >= 1");
        }
        return parsed;
    }

    private static String toBenchmarkModeLabel(BenchmarkMode mode) {
        return switch (mode) {
            case ACTUAL_DB -> "actual-db";
            case TEST_DB -> "test-db";
        };
    }

    private static BenchmarkContext prepareBenchmarkContext(BenchmarkMode mode, byte[] key)
            throws IOException, SQLException, NoSuchAlgorithmException {
        switch (mode) {
            case ACTUAL_DB -> {
                Path encFile = PathResolver.getEncryptedDbFile().toPath();
                if (!Files.exists(encFile)) {
                    throw new ReplayShieldException(ErrorType.INITIALIZATION, "Encrypted DB not found. Run init first.");
                }
                System.out.print("Benchmark username: ");
                String username = CONSOLE.readLine().trim();
                if (username.isEmpty()) {
                    throw new ReplayShieldException(ErrorType.CONFIGURATION, "Benchmark username is required.");
                }
                System.out.print("Benchmark password: ");
                char[] passwordChars = CONSOLE.readPassword();
                if (passwordChars == null || passwordChars.length == 0) {
                    throw new ReplayShieldException(ErrorType.CONFIGURATION, "Benchmark password is required.");
                }
                String password = new String(passwordChars);
                Arrays.fill(passwordChars, '\0');
                PamAuthHandler handler = new PamAuthHandler(key);
                return new BenchmarkContext(handler, username, password, null);
            }
            case TEST_DB -> {
                Path memoryDir = PathResolver.getMemoryDbDir().toPath();
                if (!Files.exists(memoryDir)) {
                    Files.createDirectories(memoryDir);
                }
                Path testEncFile = Files.createTempFile(memoryDir, "replayshield-bench-", ".enc");
                String username = "bench_user";
                String password = "bench_password";
                setupMockEncryptedDb(key, testEncFile, username, password);
                PamAuthHandler handler = new PamAuthHandler(key, testEncFile);
                return new BenchmarkContext(handler, username, password, testEncFile);
            }
        }
        throw new ReplayShieldException(ErrorType.CONFIGURATION, "Unsupported benchmark mode: " + mode);
    }

    private static void setupMockEncryptedDb(byte[] key, Path targetEncFile, String username, String password)
            throws SQLException, NoSuchAlgorithmException {
        Path plainDb = PathResolver.createMemoryDbTempFile();
        char[] passwordChars = password.toCharArray();
        try {
            try (Connection conn = Db.open(plainDb)) {
                try (PreparedStatement ps = conn.prepareStatement("""
                        INSERT INTO user_config(username, block_count)
                        VALUES(?, ?)
                        """)) {
                    ps.setString(1, username);
                    ps.setInt(2, 0);
                    ps.executeUpdate();
                }

                // baseline benchmark password (used in benchmark requests)
                try (PreparedStatement ps = conn.prepareStatement("""
                        INSERT INTO password_pool(username, pw_hash, pw_hint, hit_count, blocked, last_use)
                        VALUES(?, ?, ?, 0, 0, 0)
                        """)) {
                    String hash = PamAuthPasswordUtil.hashPassword(passwordChars);
                    String hint = PamAuthPasswordUtil.makeHint(passwordChars);
                    ps.setString(1, username);
                    ps.setString(2, hash);
                    ps.setString(3, hint);
                    ps.executeUpdate();
                }

                // additional mock passwords to expand the pool size
                try (PreparedStatement ps = conn.prepareStatement("""
                        INSERT INTO password_pool(username, pw_hash, pw_hint, hit_count, blocked, last_use)
                        VALUES(?, ?, ?, 0, 0, 0)
                        """)) {
                    for (int i = 1; i < TEST_BENCH_PASSWORD_POOL_SIZE; i++) {
                        String candidate = "bench_password_" + i;
                        char[] candidateChars = candidate.toCharArray();
                        try {
                            String hash = PamAuthPasswordUtil.hashPassword(candidateChars);
                            String hint = PamAuthPasswordUtil.makeHint(candidateChars);
                            ps.setString(1, username);
                            ps.setString(2, hash);
                            ps.setString(3, hint);
                            ps.executeUpdate();
                        } finally {
                            Arrays.fill(candidateChars, '\0');
                        }
                    }
                }
            }

            EncryptDecrypt.encryptFile(key, plainDb, targetEncFile);
        } finally {
            Arrays.fill(passwordChars, '\0');
            deleteQuietly(plainDb);
        }
    }

    private static BenchmarkIteration runAuthBenchmarkIteration(BenchmarkContext context) throws SQLException {
        // 이전 iteration 잔여 메트릭 제거
        SecureDbSession.consumeLastIoMetrics();

        long started = System.nanoTime();
        String result = context.handler().authenticate(context.username(), context.password());
        long ended = System.nanoTime();

        SecureDbSession.SessionIoMetrics ioMetrics = SecureDbSession.consumeLastIoMetrics();
        if (ioMetrics == null) {
            throw new ReplayShieldException(
                    ErrorType.DATABASE_ACCESS,
                    "Benchmark failed to capture decrypt/encrypt timings.");
        }

        long totalNanos = ended - started;
        long decryptNanos = ioMetrics.decryptNanos();
        long encryptNanos = ioMetrics.encryptNanos();
        long authLogicNanos = totalNanos - decryptNanos - encryptNanos;
        if (authLogicNanos < 0) {
            authLogicNanos = 0L;
        }

        return new BenchmarkIteration(totalNanos, decryptNanos, authLogicNanos, encryptNanos, result);
    }

    private static void printBenchmarkSummary(String label, BenchmarkSummary summary) {
        System.out.println("[" + label + "]");
        System.out.printf("  total      : %.3f ms%n", nanosToMillis(summary.totalNanos()));
        System.out.printf("  avg        : %.3f ms%n", nanosToMillis(summary.avgNanos()));
        System.out.printf("  min        : %.3f ms%n", nanosToMillis(summary.minNanos()));
        System.out.printf("  p50        : %.3f ms%n", nanosToMillis(summary.p50Nanos()));
        System.out.printf("  p95        : %.3f ms%n", nanosToMillis(summary.p95Nanos()));
        System.out.printf("  p99        : %.3f ms%n", nanosToMillis(summary.p99Nanos()));
        System.out.printf("  max        : %.3f ms%n", nanosToMillis(summary.maxNanos()));
        System.out.printf("  throughput : %.2f ops/s%n", summary.throughputOpsPerSec());
        System.out.println();
    }

    private static BenchmarkSummary summarizeBenchmark(long[] samplesNanos) {
        long[] sorted = Arrays.copyOf(samplesNanos, samplesNanos.length);
        Arrays.sort(sorted);

        long totalNanos = 0L;
        for (long sample : samplesNanos) {
            totalNanos += sample;
        }

        double avgNanos = totalNanos / (double) samplesNanos.length;
        double throughputOpsPerSec = totalNanos == 0
                ? 0.0
                : (samplesNanos.length * 1_000_000_000.0) / totalNanos;

        return new BenchmarkSummary(
                sorted[0],
                percentileNanos(sorted, 0.50),
                percentileNanos(sorted, 0.95),
                percentileNanos(sorted, 0.99),
                sorted[sorted.length - 1],
                totalNanos,
                avgNanos,
                throughputOpsPerSec);
    }

    private static long percentileNanos(long[] sortedSamples, double percentile) {
        int index = (int) Math.ceil(percentile * sortedSamples.length) - 1;
        if (index < 0) {
            index = 0;
        }
        if (index >= sortedSamples.length) {
            index = sortedSamples.length - 1;
        }
        return sortedSamples[index];
    }

    private static double nanosToMillis(long nanos) {
        return nanos / 1_000_000.0;
    }

    private static double nanosToMillis(double nanos) {
        return nanos / 1_000_000.0;
    }

    private static boolean containsArg(String[] args, String target) {
        for (String arg : args) {
            if (target.equals(arg)) {
                return true;
            }
        }
        return false;
    }

    private static void cacheAdminPassword() {
        consoleClear("[ Cache Admin Password ]");
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

    private static byte[] tryConsumeCachedAdminKey() {
        Path cachePath = PathResolver.getAdminKeyCacheFile().toPath();
        if (!Files.exists(cachePath)) {
            return null;
        }
        try {
            byte[] key = Files.readAllBytes(cachePath);
            Files.deleteIfExists(cachePath);
            if (key.length == 0) {
                return null;
            }
            return key;
        } catch (IOException exception) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                    "Failed to read cached admin password.",
                    exception);
        }
    }

    // ================================
    // MANAGE 모드 (관리자 CLI)
    // ================================
    private static void runManageMode() throws SQLException, ReplayShieldException, NoSuchAlgorithmException {
        byte[] key = KeyLoader.verifyAdminPassword();
        AdminKeyHolder.setKey(key);
        consoleClear();

        // Scanner sc = new Scanner(System.in);
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
            int sel = readInt(prompt);
            switch (sel) {
                case 1 ->
                    manageAddUser(key);
                case 2 ->
                    manageUserMenu(key);
                case 3 ->
                    manageDeleteUser(key);
                case 4 ->
                    manageChangeAdminPassword(key);
                case 9 ->
                    manageDebugDbDumpInternal(key);
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
        consoleClear("[ Add New User ]");
        String username;
        while (true) {
            System.out.print("New username (type CANCEL to cancel): ");
            username = CONSOLE.readLine().trim();
            if ("CANCEL".equalsIgnoreCase(username)) {
                consoleClear();
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
            String prompt = "Block count (1 ~ " + (maxPwCount - 1) + "): ";
            blockCount = readInt(prompt);
            if (blockCount >= 1 && blockCount < maxPwCount) {
                break; // 올바른 범위면 반복 종료
            }
            System.out.println("block_count must be between 1 and " + (maxPwCount - 1));
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
            consoleClear("[ User created : " + username + " ]");
        }

        // 입력한 암호 삭제
        for (char[] pw : pwList) {
            Arrays.fill(pw, '\0');
        }
    }

    private static void manageDeleteUser(byte[] key) throws SQLException, ReplayShieldException {
        consoleClear("[ Delete User ]");
        while (true) {
            System.out.print("Username to delete (type CANCEL to cancel): ");
            String username = CONSOLE.readLine().trim();
            if ("CANCEL".equalsIgnoreCase(username)) {
                consoleClear();
                return;
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
            if (!exists) {
                System.out.println("User not found.");
                continue;
            }
            System.out.print("Type DELETE to confirm removal of '" + username + "': ");
            String confirm = CONSOLE.readLine().trim();
            if (!"DELETE".equalsIgnoreCase(confirm)) {
                consoleClear("[ Deletion aborted. ]");
                return;
            }
            try (DbSession session = SecureDbSession.openWritable(key)) {
                Connection conn = session.connection();
                boolean originalAutoCommit = conn.getAutoCommit();
                conn.setAutoCommit(false);
                try {
                    try (PreparedStatement ps = conn.prepareStatement(
                            "DELETE FROM password_pool WHERE username=?")) {
                        ps.setString(1, username);
                        ps.executeUpdate();
                    }
                    try (PreparedStatement ps = conn.prepareStatement(
                            "DELETE FROM password_history WHERE username=?")) {
                        ps.setString(1, username);
                        ps.executeUpdate();
                    }
                    try (PreparedStatement ps = conn.prepareStatement(
                            "DELETE FROM user_config WHERE username=?")) {
                        ps.setString(1, username);
                        ps.executeUpdate();
                    }
                    conn.commit();
                } catch (SQLException exception) {
                    conn.rollback();
                    throw exception;
                } finally {
                    conn.setAutoCommit(originalAutoCommit);
                }
            }
            consoleClear("[ User deleted: " + username + " ]");
            return;
        }
    }

    private static void manageUserMenu(byte[] key)
            throws SQLException, ReplayShieldException, NoSuchAlgorithmException {
        String username;
        while (true) {
            System.out.print("Target username (type CANCEL to cancel): ");
            username = CONSOLE.readLine().trim();
            if ("CANCEL".equalsIgnoreCase(username)) {
                consoleClear();
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
                consoleClear();
                break; // 루프 탈출, 해당 사용자로 다음 단계 진행
            }
            System.out.println("User not found.");
        }
        boolean running = true;
        while (running) {
            System.out.println("[ Manage User: " + username + " ]");
            String prompt = "1) Show PW pool\n2) Add password\n3) Delete password\n4) Change block_count\n0) Back\n>";
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
        consoleClear();
    }

    private static void showUserPwPool(byte[] key, String username) throws SQLException, ReplayShieldException {
        try (SecureDbSession.DbSession session = SecureDbSession.openReadOnly(key)) {
            consoleClear();
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
        consoleClear("[ Manage User: " + username + " ]");
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

            // 2중 확인
            System.out.print("Confirm password: ");
            char[] confirm = CONSOLE.readPassword();
            if (!Arrays.equals(pw, confirm)) {
                System.out.println("Passwords do not match.");
                Arrays.fill(pw, '\0');
                Arrays.fill(confirm, '\0');
                continue;
            }
            Arrays.fill(confirm, '\0');

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
            try (var session = SecureDbSession.openWritable(key); var ps = session.connection().prepareStatement("""
                    INSERT INTO password_pool(username, pw_hash, pw_hint, hit_count, blocked)
                    VALUES(?, ?, ?, 0, 0)
                    """)) {
                ps.setString(1, username);
                ps.setString(2, newHash);
                ps.setString(3, hint);
                ps.executeUpdate();
            }
            consoleClear("[ Password added. ]");
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
                consoleClear("[ Deletion canceled. ]");
                return;
            }
            if (id > 0) {
                int passwordCount;
                int blockCount;
                try (SecureDbSession.DbSession session = SecureDbSession.openReadOnly(key)) {
                    Connection conn = session.connection();

                    // 현재 패스워드 풀 갯수 체크
                    try (PreparedStatement ps = conn.prepareStatement("""
                            SELECT COUNT(*) FROM password_pool WHERE username=?
                            """)) {
                        ps.setString(1, username);
                        try (ResultSet rs = ps.executeQuery()) {
                            rs.next();
                            passwordCount = rs.getInt(1);
                        }
                    }

                    // 현재 블록 카운트 체크
                    try (PreparedStatement ps = conn.prepareStatement("""
                            SELECT block_count FROM user_config WHERE username=?
                            """)) {
                        ps.setString(1, username);
                        try (ResultSet rs = ps.executeQuery()) {
                            if (!rs.next()) {
                                consoleClear("[ User not found. ]");
                                return;
                            }
                            blockCount = rs.getInt(1);
                        }
                    }

                }

                // 최소조건 만족 체크
                if (passwordCount <= MIN_PASSWORD_POOL_SIZE) {
                    consoleClear("[ Need at least " + MIN_PASSWORD_POOL_SIZE + " passwords per user. ]");
                    return;
                }
                if (blockCount <= 1) {
                    consoleClear("[ block_count cannot be reduced below 1. ]");
                    return;
                }

                int newBlockCount = blockCount - 1;

                // 결과 저장
                try (SecureDbSession.DbSession session = SecureDbSession.openWritable(key)) {
                    Connection conn = session.connection();
                    boolean originalAutoCommit = conn.getAutoCommit(); // 자동커밋상태 기록
                    conn.setAutoCommit(false); // 자동커밋 끔
                    try {

                        // 1. 패스워드 풀 삭제 시도
                        int deleted;
                        try (PreparedStatement ps = conn.prepareStatement("""
                                DELETE FROM password_pool
                                WHERE id = ? AND username = ?
                                """)) {
                            ps.setInt(1, id);
                            ps.setString(2, username);
                            deleted = ps.executeUpdate(); // 삭제된 행 수
                        }
                        // 2. 블록 카운트 감소 및 커밋 시도
                        if (deleted > 0) {
                            try (PreparedStatement ps = conn.prepareStatement("""
                                    UPDATE user_config SET block_count=? WHERE username=?
                                    """)) {
                                ps.setInt(1, newBlockCount);
                                ps.setString(2, username);
                                ps.executeUpdate();
                            }
                            // block 대상 계산
                            PamAuthHandler.refreshBlockedState(conn, username, newBlockCount);
                            conn.commit(); // DB 커밋
                            consoleClear("[ Password deleted. block_count=" + newBlockCount + " ]");
                            return;
                        }
                        // 삭제 실패시 롤백
                        conn.rollback();
                        System.out.println("No such password for this user.");
                    } catch (SQLException exception) {
                        // 예외 발생시 롤백
                        conn.rollback();
                        throw exception;
                    } finally {
                        conn.setAutoCommit(originalAutoCommit); // 원래 자동커밋 상태로 복원
                    }
                }
            } else {
                System.out.println("ID must be positive.");
            }
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
            }
            PamAuthHandler.refreshBlockedState(conn, username, bc);
            consoleClear("block_count updated.");
        }
    }

    // ================================
    // DEBUG DB (테스트용)
    // ================================
    private static void manageDebugDbDumpInternal(byte[] key) throws SQLException, ReplayShieldException {
        consoleClear();
        try (SecureDbSession.DbSession session = SecureDbSession.openReadOnly(key)) {
            Connection conn = session.connection();
            try (Statement st = conn.createStatement()) {
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                System.out.println("--------------------------------------------------");
                System.out.println("TABLE: user_config");
                System.out.println("--------------------------------------------------");
                try (ResultSet rs = st.executeQuery(
                        "SELECT username, block_count FROM user_config ORDER BY username")) {
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
                try (ResultSet rs = st.executeQuery("""
                        SELECT id, username, pw_hash, pw_hint, hit_count, blocked, last_use
                        FROM password_pool
                        ORDER BY username, id
                        """)) {
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
                try (ResultSet rs = st.executeQuery("""
                        SELECT id, username, pw_hash, pw_hint, created_at
                        FROM password_history
                        ORDER BY id
                        """)) {
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
                System.out.println("\n=== END OF DEBUG DUMP ===");
            }
        }
    }

    // 암호 변경
    private static void manageChangeAdminPassword(byte[] key) throws SQLException, ReplayShieldException {
        byte[] updated = KeyLoader.changeAdminPassword(key);
        if (updated != null) {
            AdminKeyHolder.setKey(updated);
        }
        consoleClear("Admin password updated.");
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

    public static void deleteQuietly(Path tmp) {
        try {
            Files.deleteIfExists(tmp);
        } catch (IOException ignored) {
        }
    }

    private static void consoleClear() {
        try {
            new ProcessBuilder("clear").inheritIO().start().waitFor();
        } catch (IOException | InterruptedException ignored) {
        }
        System.out.println("=== ReplayShield Manage CLI ===");
    }

    private static void consoleClear(String payload) {
        try {
            new ProcessBuilder("clear").inheritIO().start().waitFor();
        } catch (IOException | InterruptedException ignored) {
        }
        System.out.println("=== ReplayShield Manage CLI ===");
        if (payload != null) {
            System.out.println(payload);
        }
    }
}
