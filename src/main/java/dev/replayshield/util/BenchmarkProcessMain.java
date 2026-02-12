package dev.replayshield.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpPrincipal;

import dev.replayshield.db.Db;
import dev.replayshield.security.EncryptDecrypt;
import dev.replayshield.security.PasswordCodec;
import dev.replayshield.server.HttpAuthServer;
import dev.replayshield.server.PamAuthHandler;
import dev.replayshield.util.ReplayShieldException.ErrorType;

public final class BenchmarkProcessMain {

    private enum BenchmarkStorageMode {
        SINGLE_DB,
        PER_USER_DB
    }

    private record BenchmarkOptions(
            int warmupIterations,
            int measureIterations,
            int users) {
    }

    private record BenchmarkContext(
            BenchmarkStorageMode mode,
            PamAuthHandler[] handlers,
            String[] usernames,
            String[] passwords,
            Path sampleDbFile,
            int dbFileCount,
            Path perUserDbDir,
            Path[] cleanupFiles) {
    }

    private record BenchmarkIteration(
            long totalNanos,
            String result) {
    }

    private record BenchmarkSummary(
            double avgNanos,
            double medianNanos,
            double minNanos,
            double maxNanos) {
    }

    private record BenchmarkRunResult(
            BenchmarkStorageMode mode,
            BenchmarkSummary totalSummary,
            int passCount,
            int failCount,
            int otherCount) {
    }

    private BenchmarkProcessMain() {
    }

    // ===========================================================================
    // 벤치마크 서브 프로세스 진입점
    // ===========================================================================
    public static void main(String[] args) {
        byte[] key = null;
        BenchmarkContext singleContext = null;
        BenchmarkContext perUserContext = null;
        try {

            // 벤치마크용 옵션 파싱
            BenchmarkUtils.BenchmarkOptions parsed = BenchmarkUtils.parseBenchmarkOptions(args, 0);
            if (parsed.usersList().length != 1) {
                throw new ReplayShieldException(
                        ErrorType.CONFIGURATION,
                        "Benchmark process entry requires --users=<N>.");
            }
            BenchmarkOptions options = new BenchmarkOptions(
                    parsed.warmupIterations(),
                    parsed.measureIterations(),
                    parsed.usersList()[0]);
            int warmupRequestsPerMode = options.warmupIterations();
            int measureRequestsPerMode = options.measureIterations();
            int users = options.users();

            // 키 준비
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            key = sha256.digest(BenchmarkUtils.BENCHMARK_INTERNAL_KEY_SEED.getBytes(StandardCharsets.UTF_8));

            // 벤치마크 컨텍스트 준비
            singleContext = prepareBenchmarkContext(BenchmarkStorageMode.SINGLE_DB, key, users);
            perUserContext = prepareBenchmarkContext(BenchmarkStorageMode.PER_USER_DB, key, users);

            int targetUserIndex = users - 1;

            // 워밍업 실행 ( 결과 수집 안함 )
            for (int i = 0; i < warmupRequestsPerMode; i++) {
                if ((i & 1) == 0) {
                    runAuthBenchmarkIteration(singleContext, targetUserIndex);
                    runAuthBenchmarkIteration(perUserContext, targetUserIndex);
                } else {
                    runAuthBenchmarkIteration(perUserContext, targetUserIndex);
                    runAuthBenchmarkIteration(singleContext, targetUserIndex);
                }
            }

            // 본 측정 실행 ( 결과 수집 )
            BenchmarkCollector singleCollector = new BenchmarkCollector(measureRequestsPerMode);
            BenchmarkCollector perUserCollector = new BenchmarkCollector(measureRequestsPerMode);
            for (int i = 0; i < measureRequestsPerMode; i++) {
                if ((i & 1) == 0) {
                    singleCollector.accept(runAuthBenchmarkIteration(singleContext, targetUserIndex));
                    perUserCollector.accept(runAuthBenchmarkIteration(perUserContext, targetUserIndex));
                } else {
                    perUserCollector.accept(runAuthBenchmarkIteration(perUserContext, targetUserIndex));
                    singleCollector.accept(runAuthBenchmarkIteration(singleContext, targetUserIndex));
                }
            }

            // 결과 집계 및 출력
            BenchmarkRunResult singleDbResult = singleCollector.toRunResult(BenchmarkStorageMode.SINGLE_DB);
            BenchmarkRunResult perUserDbResult = perUserCollector.toRunResult(BenchmarkStorageMode.PER_USER_DB);

            double singleAvgMs = singleDbResult.totalSummary().avgNanos() / 1_000_000.0;
            double singleMedianMs = singleDbResult.totalSummary().medianNanos() / 1_000_000.0;
            double singleMinMs = singleDbResult.totalSummary().minNanos() / 1_000_000.0;
            double singleMaxMs = singleDbResult.totalSummary().maxNanos() / 1_000_000.0;
            double perUserAvgMs = perUserDbResult.totalSummary().avgNanos() / 1_000_000.0;
            double perUserMedianMs = perUserDbResult.totalSummary().medianNanos() / 1_000_000.0;
            double perUserMinMs = perUserDbResult.totalSummary().minNanos() / 1_000_000.0;
            double perUserMaxMs = perUserDbResult.totalSummary().maxNanos() / 1_000_000.0;
            System.out.printf(Locale.ROOT,
                    "%s users=%d single(avg=%.3f,med=%.3f,min=%.3f,max=%.3f) peruser(avg=%.3f,med=%.3f,min=%.3f,max=%.3f)%n%n",
                    BenchmarkUtils.BENCHMARK_RESULT_PREFIX,
                    users,
                    singleAvgMs,
                    singleMedianMs,
                    singleMinMs,
                    singleMaxMs,
                    perUserAvgMs,
                    perUserMedianMs,
                    perUserMinMs,
                    perUserMaxMs);

        } catch (IOException | SQLException | NoSuchAlgorithmException | ReplayShieldException exception) {
            ErrorReporter.logError("benchmark-process", exception);
            System.exit(1);
        } finally {

            // 파일 정리
            BenchmarkContext[] cleanupTargets = new BenchmarkContext[] { singleContext, perUserContext };
            for (BenchmarkContext cleanupTarget : cleanupTargets) {
                if (cleanupTarget == null) {
                    continue;
                }
                for (Path file : cleanupTarget.cleanupFiles()) {
                    if (file != null) {
                        deleteQuietly(file);
                    }
                }
            }

            // 메모리 정리
            if (key != null) {
                Arrays.fill(key, (byte) 0);
            }
        }
    }

    // ===========================================================================
    // 벤치마크 컨텍스트 생성
    // ============================================================================
    private static BenchmarkContext prepareBenchmarkContext(
            BenchmarkStorageMode mode,
            byte[] key,
            int userCount) throws IOException, SQLException, NoSuchAlgorithmException {

        // 메모리 DB 디렉터리 준비
        Path memoryDir = PathResolver.getMemoryDbDir().toPath();
        if (!Files.exists(memoryDir)) {
            Files.createDirectories(memoryDir);
        }

        // 벤치마크 컨텍스트 준비
        if (mode == BenchmarkStorageMode.SINGLE_DB) { // 단일 DB 모드

            // 단일 암호화 DB 파일 생성
            Path encFile = Files.createTempFile(memoryDir, "replayshield-bench-single-", ".enc");
            boolean prepared = false;

            try {

                // 모의 암호화 DB 파일 설정
                setupMockEncryptedDb(key, encFile, 0, userCount);
                PamAuthHandler handler = new PamAuthHandler(key, encFile);
                // 벤치마크용 사용자 이름 및 비밀번호 배열 생성
                String[] usernames = buildBenchmarkUsernames(userCount);
                String[] passwords = buildBenchmarkPasswords(userCount);
                PamAuthHandler[] handlers = new PamAuthHandler[userCount];
                for (int i = 0; i < userCount; i++) {
                    handlers[i] = handler;
                }
                prepared = true;

                // 벤치마크 컨텍스트 반환
                return new BenchmarkContext(
                        BenchmarkStorageMode.SINGLE_DB,
                        handlers,
                        usernames,
                        passwords,
                        encFile,
                        1,
                        null,
                        new Path[] { encFile });
            } finally {
                if (!prepared) {
                    deleteQuietly(encFile);
                }
            }
        } else { // 사용자별 DB 모드

            // 사용자별 암호화 DB 파일 생성
            Path[] userFiles = new Path[userCount];
            Path userDbDir = null;
            boolean prepared = false;

            try {

                // 폴더 내 사용자 수 만큼 파일 DB 파일 생성
                userDbDir = Files.createTempDirectory(memoryDir, "replayshield-bench-users-");
                for (int userIndex = 0; userIndex < userCount; userIndex++) {
                    String username = "bench_u" + userIndex;
                    Path userFile = userDbDir.resolve(username + BenchmarkUtils.BENCHMARK_USER_DB_SUFFIX);
                    userFiles[userIndex] = userFile;
                    setupMockEncryptedDb(key, userFile, userIndex, userIndex + 1);
                }

                String[] usernames = buildBenchmarkUsernames(userCount);
                String[] passwords = buildBenchmarkPasswords(userCount);
                PamAuthHandler[] handlers = new PamAuthHandler[userCount];
                for (int userIndex = 0; userIndex < userCount; userIndex++) {
                    handlers[userIndex] = new PamAuthHandler(key, userFiles[userIndex]);
                }
                Path[] cleanupFiles = new Path[userFiles.length + 1];
                System.arraycopy(userFiles, 0, cleanupFiles, 0, userFiles.length);
                cleanupFiles[userFiles.length] = userDbDir;

                prepared = true;
                return new BenchmarkContext(
                        BenchmarkStorageMode.PER_USER_DB,
                        handlers,
                        usernames,
                        passwords,
                        userFiles[0],
                        userCount,
                        userDbDir,
                        cleanupFiles);
            } finally {
                if (!prepared) {
                    for (Path file : userFiles) {
                        if (file != null) {
                            deleteQuietly(file);
                        }
                    }
                    if (userDbDir != null) {
                        deleteQuietly(userDbDir);
                    }
                }
            }
        }
    }

    // ============================================================================
    // 모의 DB 설정
    // ============================================================================
    private static void setupMockEncryptedDb(
            byte[] key,
            Path targetEncFile,
            int startUserIndex,
            int endUserIndexExclusive) throws SQLException, NoSuchAlgorithmException {

        // 평문 DB 파일 생성
        Path plainDb = PathResolver.createMemoryDbTempFile();
        try {
            // DB 내용 채우기
            populateMockPlainDb(plainDb, startUserIndex, endUserIndexExclusive);
            // 평문 DB 파일 암호화
            EncryptDecrypt.encryptFile(key, plainDb, targetEncFile);
        } finally {
            deleteQuietly(plainDb);
        }
    }

    // DB 내용 채우기
    private static void populateMockPlainDb(
            Path plainDb,
            int startUserIndex,
            int endUserIndexExclusive) throws SQLException, NoSuchAlgorithmException {
        try (Connection conn = Db.open(plainDb);
                PreparedStatement userConfigPs = conn.prepareStatement("""
                        INSERT INTO user_config(username, block_count)
                        VALUES(?, ?)
                        """);
                PreparedStatement passwordPoolPs = conn.prepareStatement("""
                        INSERT INTO password_pool(username, pw_hash, pw_hint, hit_count, blocked, last_use)
                        VALUES(?, ?, ?, 0, 0, 0)
                        """)) {
            for (int userIndex = startUserIndex; userIndex < endUserIndexExclusive; userIndex++) {
                String username = "bench_u" + userIndex;
                userConfigPs.setString(1, username);
                userConfigPs.setInt(2, 0);
                userConfigPs.executeUpdate();

                for (int passwordIndex = 0; passwordIndex < BenchmarkUtils.FIXED_BENCH_PASSWORD_POOL_SIZE; passwordIndex++) {
                    String candidate = "bench_u" + userIndex + "_pw" + passwordIndex + "_Aa1!";
                    String hash = PasswordCodec.hashPassword(candidate);
                    char[] hintChars = candidate.toCharArray();
                    String hint = PasswordCodec.makeHint(hintChars);
                    Arrays.fill(hintChars, '\0');
                    passwordPoolPs.setString(1, username);
                    passwordPoolPs.setString(2, hash);
                    passwordPoolPs.setString(3, hint);
                    passwordPoolPs.executeUpdate();
                }
            }
        }
    }

    // ============================================================================
    // 단위 벤치마크 인증 실행 ( 1회 )
    // ============================================================================
    private static BenchmarkIteration runAuthBenchmarkIteration(BenchmarkContext context, int targetUserIndex)
            throws SQLException {
        long cycleStarted = System.nanoTime();
        String username = context.usernames()[targetUserIndex];
        String password = context.passwords()[targetUserIndex];
        PamAuthHandler handler = context.handlers()[targetUserIndex];
        if (context.mode() == BenchmarkStorageMode.PER_USER_DB) {
            if (context.perUserDbDir() == null) {
                throw new ReplayShieldException(
                        ErrorType.DATABASE_ACCESS,
                        "Per-user benchmark context is missing perUserDbDir.");
            }
            File directory = context.perUserDbDir().toFile();
            File[] files = directory.listFiles((dir, name) -> name.endsWith(BenchmarkUtils.BENCHMARK_USER_DB_SUFFIX));
            if (files == null) {
                throw new ReplayShieldException(
                        ErrorType.DATABASE_ACCESS,
                        "Failed to scan per-user benchmark directory: " + context.perUserDbDir());
            }
            String target = username + BenchmarkUtils.BENCHMARK_USER_DB_SUFFIX;
            boolean found = false;
            for (File file : files) {
                if (target.equals(file.getName())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw new ReplayShieldException(
                        ErrorType.DATABASE_ACCESS,
                        "Benchmark user DB file not found during directory scan: " + target);
            }
        }

        String encodedUsername = URLEncoder.encode(username, StandardCharsets.UTF_8);
        String encodedPassword = URLEncoder.encode(password, StandardCharsets.UTF_8);
        String requestBody = "username=" + encodedUsername + "&password=" + encodedPassword;
        BenchmarkHttpExchange exchange = new BenchmarkHttpExchange(requestBody);
        String result;
        try {
            result = handler.handleHttpPost(exchange);
        } finally {
            exchange.close();
        }

        return new BenchmarkIteration(System.nanoTime() - cycleStarted, result);
    }

    // ============================================================================
    // 보조 클래스
    // ============================================================================

    private static final class BenchmarkCollector {
        private final long[] totalSamples;
        private int passCount;
        private int failCount;
        private int otherCount;
        private int cursor;

        private BenchmarkCollector(int iterations) {
            this.totalSamples = new long[iterations];
            this.passCount = 0;
            this.failCount = 0;
            this.otherCount = 0;
            this.cursor = 0;
        }

        private void accept(BenchmarkIteration iteration) {
            totalSamples[cursor] = iteration.totalNanos();

            switch (iteration.result()) {
                case "PASS" -> passCount++;
                case "FAIL" -> failCount++;
                case null, default -> otherCount++;
            }
            cursor++;
        }

        private BenchmarkRunResult toRunResult(BenchmarkStorageMode mode) {
            long[] sorted = Arrays.copyOf(totalSamples, totalSamples.length);
            Arrays.sort(sorted);

            long totalNanos = 0L;
            for (long sample : totalSamples) {
                totalNanos += sample;
            }

            double avgNanos = totalNanos / (double) totalSamples.length;
            int mid = sorted.length / 2;
            double medianNanos;
            if ((sorted.length & 1) == 0) {
                medianNanos = (sorted[mid - 1] + sorted[mid]) / 2.0;
            } else {
                medianNanos = sorted[mid];
            }
            double minNanos = sorted[0];
            double maxNanos = sorted[sorted.length - 1];
            return new BenchmarkRunResult(
                    mode,
                    new BenchmarkSummary(avgNanos, medianNanos, minNanos, maxNanos),
                    passCount,
                    failCount,
                    otherCount);
        }
    }

    private static final class BenchmarkHttpExchange extends HttpExchange {
        private final Headers requestHeaders = new Headers();
        private final Headers responseHeaders = new Headers();
        private final Map<String, Object> attributes = new HashMap<>();
        private InputStream requestBody;
        private OutputStream responseBody;
        private int responseCode = -1;

        private BenchmarkHttpExchange(String requestBody) {
            this.requestBody = new ByteArrayInputStream(requestBody.getBytes(StandardCharsets.UTF_8));
            this.responseBody = new ByteArrayOutputStream();
            this.requestHeaders.add("Content-Type", "application/x-www-form-urlencoded");
        }

        @Override
        public Headers getRequestHeaders() {
            return requestHeaders;
        }

        @Override
        public Headers getResponseHeaders() {
            return responseHeaders;
        }

        @Override
        public URI getRequestURI() {
            return URI.create("/auth");
        }

        @Override
        public String getRequestMethod() {
            return "POST";
        }

        @Override
        public HttpContext getHttpContext() {
            return null;
        }

        @Override
        public void close() {
            try {
                requestBody.close();
            } catch (IOException ignored) {
            }
            try {
                responseBody.close();
            } catch (IOException ignored) {
            }
        }

        @Override
        public InputStream getRequestBody() {
            return requestBody;
        }

        @Override
        public OutputStream getResponseBody() {
            return responseBody;
        }

        @Override
        public void sendResponseHeaders(int responseCode, long responseLength) {
            this.responseCode = responseCode;
        }

        @Override
        public InetSocketAddress getRemoteAddress() {
            return new InetSocketAddress("127.0.0.1", 0);
        }

        @Override
        public int getResponseCode() {
            return responseCode;
        }

        @Override
        public InetSocketAddress getLocalAddress() {
            return new InetSocketAddress("127.0.0.1", HttpAuthServer.DEFAULT_PORT);
        }

        @Override
        public String getProtocol() {
            return "HTTP/1.1";
        }

        @Override
        public Object getAttribute(String name) {
            return attributes.get(name);
        }

        @Override
        public void setAttribute(String name, Object value) {
            attributes.put(name, value);
        }

        @Override
        public void setStreams(InputStream in, OutputStream out) {
            if (in != null) {
                this.requestBody = in;
            }
            if (out != null) {
                this.responseBody = out;
            }
        }

        @Override
        public HttpPrincipal getPrincipal() {
            return null;
        }
    }

    // ============================================================================
    // 유틸리티
    // ============================================================================

    // 삭제 유틸
    private static boolean deleteQuietly(Path target) {
        try {
            return Files.deleteIfExists(target);
        } catch (IOException ignored) {
            return false;
        }
    }

    // 사용자 이름 배열 생성
    private static String[] buildBenchmarkUsernames(int userCount) {
        String[] usernames = new String[userCount];
        for (int userIndex = 0; userIndex < userCount; userIndex++) {
            usernames[userIndex] = "bench_u" + userIndex;
        }
        return usernames;
    }

    // 비밀번호 배열 생성
    private static String[] buildBenchmarkPasswords(int userCount) {
        String[] passwords = new String[userCount];
        for (int userIndex = 0; userIndex < userCount; userIndex++) {
            passwords[userIndex] = "bench_u" + userIndex + "_pw"
                    + BenchmarkUtils.BENCHMARK_TARGET_PASSWORD_INDEX + "_Aa1!";
        }
        return passwords;
    }
}
