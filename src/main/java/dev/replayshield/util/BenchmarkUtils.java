package dev.replayshield.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
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
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpPrincipal;

import dev.replayshield.db.Db;
import dev.replayshield.db.SecureDbSession;
import dev.replayshield.security.EncryptDecrypt;
import dev.replayshield.server.PamAuthHandler;
import dev.replayshield.util.ReplayShieldException.ErrorType;

public final class BenchmarkUtils {

    private static final int DEFAULT_BENCH_WARMUP = 5;
    private static final int DEFAULT_BENCH_ITERATIONS = 500;
    private static final int TEST_BENCH_USER_COUNT = 10;
    private static final int TEST_BENCH_PASSWORD_POOL_SIZE = 100;
    private static final int BENCHMARK_TARGET_USER_INDEX = 0;
    private static final int BENCHMARK_TARGET_PASSWORD_INDEX = 0;
    private static final String BENCHMARK_INTERNAL_KEY_SEED = "ReplayShieldBenchmarkInternalKeyV1";

    private BenchmarkUtils() {
    }

    private record BenchmarkOptions(int warmup, int iterations) {
    }

    private record BenchmarkContext(PamAuthHandler handler, String username, String password, Path tempEncFile) {
    }

    private record BenchmarkIteration(
            long totalNanos,
            long requestReadNanos,
            long formParseNanos,
            long authTotalNanos,
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

    public static void runBenchmarkMode(String[] args) throws IOException, SQLException, NoSuchAlgorithmException {
        if (containsArg(args, "--help") || containsArg(args, "-h")) {
            System.out.println("""
                    Usage: replayshield benchmark [options]
                      --warmup=<N>           Warmup iterations (default: 5)
                      --iterations=<N>       Measured iterations (default: 500)
                    """);
            return;
        }

        BenchmarkOptions options = parseBenchmarkOptions(args);
        consoleClear("[ Benchmark ]");
        System.out.println("mode       : test-db");
        System.out.println("warmup     : " + options.warmup());
        System.out.println("iterations : " + options.iterations());
        System.out.println("admin auth : not required (internal benchmark key)");
        System.out.println("scope      : handleHttpPost end-to-end (request -> PASS/FAIL)");
        System.out.println();

        byte[] key = createBenchmarkKey();
        BenchmarkContext context = null;
        try {
            context = prepareBenchmarkContext(key);
            System.out.println("target user: " + context.username());
            System.out.println("test login : " + context.username() + " / " + context.password());
            System.out.println("test db    : " + context.tempEncFile());
            System.out.println();

            for (int i = 0; i < options.warmup(); i++) {
                runAuthBenchmarkIteration(context);
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
                BenchmarkIteration iter = runAuthBenchmarkIteration(context);
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

            BenchmarkSummary totalSummary = summarizeBenchmark(totalSamples);
            BenchmarkSummary requestReadSummary = summarizeBenchmark(requestReadSamples);
            BenchmarkSummary formParseSummary = summarizeBenchmark(formParseSamples);
            BenchmarkSummary authTotalSummary = summarizeBenchmark(authTotalSamples);
            BenchmarkSummary decryptSummary = summarizeBenchmark(decryptSamples);
            BenchmarkSummary authSummary = summarizeBenchmark(authLogicSamples);
            BenchmarkSummary encryptSummary = summarizeBenchmark(encryptSamples);

            System.out.println("Benchmark complete.");
            System.out.printf("result     : PASS=%d FAIL=%d OTHER=%d%n", passCount, failCount, otherCount);
            System.out.println();
            printBenchmarkSummary("end-to-end", totalSummary);
            printBenchmarkSummary("request-read", requestReadSummary);
            printBenchmarkSummary("form-parse", formParseSummary);
            printBenchmarkSummary("auth-total", authTotalSummary);
            printBenchmarkSummary("decrypt", decryptSummary);
            printBenchmarkSummary("auth-logic", authSummary);
            printBenchmarkSummary("encrypt", encryptSummary);
        } finally {
            if (context != null && context.tempEncFile() != null) {
                Path tempEncFile = context.tempEncFile();
                boolean deleted = deleteQuietly(tempEncFile);
                if (deleted) {
                    System.out.println("cleanup    : deleted " + tempEncFile);
                } else {
                    System.out.println("cleanup    : no file deleted " + tempEncFile);
                }
            }
            Arrays.fill(key, (byte) 0);
        }
    }

    private static BenchmarkOptions parseBenchmarkOptions(String[] args) {
        int warmup = DEFAULT_BENCH_WARMUP;
        int iterations = DEFAULT_BENCH_ITERATIONS;

        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
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

        return new BenchmarkOptions(warmup, iterations);
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

    private static BenchmarkContext prepareBenchmarkContext(byte[] key)
            throws IOException, SQLException, NoSuchAlgorithmException {
        Path memoryDir = PathResolver.getMemoryDbDir().toPath();
        if (!Files.exists(memoryDir)) {
            Files.createDirectories(memoryDir);
        }
        Path testEncFile = Files.createTempFile(memoryDir, "replayshield-bench-", ".enc");
        boolean prepared = false;
        try {
            String username = benchmarkUsername(BENCHMARK_TARGET_USER_INDEX);
            String password = benchmarkPassword(BENCHMARK_TARGET_USER_INDEX, BENCHMARK_TARGET_PASSWORD_INDEX);
            setupMockEncryptedDb(key, testEncFile);
            PamAuthHandler handler = new PamAuthHandler(key, testEncFile);
            prepared = true;
            return new BenchmarkContext(handler, username, password, testEncFile);
        } finally {
            if (!prepared) {
                deleteQuietly(testEncFile);
            }
        }
    }

    private static void setupMockEncryptedDb(byte[] key, Path targetEncFile)
            throws SQLException, NoSuchAlgorithmException {
        Path plainDb = PathResolver.createMemoryDbTempFile();
        try {
            try (Connection conn = Db.open(plainDb);
                    PreparedStatement userConfigPs = conn.prepareStatement("""
                            INSERT INTO user_config(username, block_count)
                            VALUES(?, ?)
                            """);
                    PreparedStatement passwordPoolPs = conn.prepareStatement("""
                            INSERT INTO password_pool(username, pw_hash, pw_hint, hit_count, blocked, last_use)
                            VALUES(?, ?, ?, 0, 0, 0)
                            """)) {
                for (int userIndex = 0; userIndex < TEST_BENCH_USER_COUNT; userIndex++) {
                    String username = benchmarkUsername(userIndex);
                    userConfigPs.setString(1, username);
                    userConfigPs.setInt(2, 0);
                    userConfigPs.executeUpdate();

                    for (int passwordIndex = 0; passwordIndex < TEST_BENCH_PASSWORD_POOL_SIZE; passwordIndex++) {
                        String candidate = benchmarkPassword(userIndex, passwordIndex);
                        char[] candidateChars = candidate.toCharArray();
                        try {
                            String hash = hashPassword(candidateChars);
                            String hint = makeHint(candidateChars);
                            passwordPoolPs.setString(1, username);
                            passwordPoolPs.setString(2, hash);
                            passwordPoolPs.setString(3, hint);
                            passwordPoolPs.executeUpdate();
                        } finally {
                            Arrays.fill(candidateChars, '\0');
                        }
                    }
                }
            }

            EncryptDecrypt.encryptFile(key, plainDb, targetEncFile);
        } finally {
            deleteQuietly(plainDb);
        }
    }

    private static String benchmarkUsername(int userIndex) {
        return "bench_user_" + userIndex;
    }

    private static String benchmarkPassword(int userIndex, int passwordIndex) {
        return "bench_password_" + userIndex + "_" + passwordIndex;
    }

    private static byte[] createBenchmarkKey() throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        return sha256.digest(BENCHMARK_INTERNAL_KEY_SEED.getBytes(StandardCharsets.UTF_8));
    }

    // 벤치마크용 사이클 1회 실행
    private static BenchmarkIteration runAuthBenchmarkIteration(BenchmarkContext context) throws SQLException {
        PamAuthHandler.consumeLastHttpFlowMetrics();
        SecureDbSession.consumeLastIoMetrics();

        // handleHttpPost() 전체 플로우(요청 바디 읽기/파싱/인증) 측정한다.
        String requestBody = buildFormRequestBody(context.username(), context.password());
        BenchmarkHttpExchange exchange = new BenchmarkHttpExchange(requestBody);
        String result;
        try {
            // HTTP 핸들러 진입점부터 PASS/FAIL 반환까지 1회 실행
            result = context.handler().handleHttpPost(exchange);
        } finally {
            // 매 iteration마다 exchange 리소스를 정리
            exchange.close();
        }

        // handleHttpPost() 내부에서 수집한 구간별 메트릭(total/read/parse/auth)을 회수
        PamAuthHandler.HttpFlowMetrics flowMetrics = PamAuthHandler.consumeLastHttpFlowMetrics();
        if (flowMetrics == null) {
            throw new ReplayShieldException(
                    ErrorType.PAM_AUTH,
                    "Benchmark failed to capture request/read/parse timings.");
        }

        // SecureDbSession이 기록한 복호화/재암호화 시간 메트릭을 회수
        SecureDbSession.SessionIoMetrics ioMetrics = SecureDbSession.consumeLastIoMetrics();
        if (ioMetrics == null) {
            throw new ReplayShieldException(
                    ErrorType.DATABASE_ACCESS,
                    "Benchmark failed to capture decrypt/encrypt timings.");
        }

        // HTTP 전체 처리 시간(요청 진입 ~ 최종 결과 반환)
        long totalNanos = flowMetrics.totalNanos();
        long requestReadNanos = flowMetrics.readBodyNanos();
        long formParseNanos = flowMetrics.parseFormNanos();
        long authTotalNanos = flowMetrics.authenticateNanos();
        long decryptNanos = ioMetrics.decryptNanos();
        long encryptNanos = ioMetrics.encryptNanos();
        long authLogicNanos = authTotalNanos - decryptNanos - encryptNanos;

        // 시계 오차/측정 분해 오차로 음수가 나올 수 있어 0으로 보정
        if (authLogicNanos < 0) {
            authLogicNanos = 0L;
        }

        // iteration 1회의 측정 결과를 불변 record로 반환
        return new BenchmarkIteration(
                totalNanos,
                requestReadNanos,
                formParseNanos,
                authTotalNanos,
                decryptNanos,
                authLogicNanos,
                encryptNanos,
                result);
    }

    private static String buildFormRequestBody(String username, String password) {
        String encodedUsername = URLEncoder.encode(username, StandardCharsets.UTF_8);
        String encodedPassword = URLEncoder.encode(password, StandardCharsets.UTF_8);
        return "username=" + encodedUsername + "&password=" + encodedPassword;
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

    private static String hashPassword(char[] password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] bytes = new String(password).getBytes(StandardCharsets.UTF_8);
        byte[] digest = md.digest(bytes);
        Arrays.fill(bytes, (byte) 0);
        return Base64.getEncoder().encodeToString(digest);
    }

    private static String makeHint(char[] password) {
        char first = password[0];
        char last = password[password.length - 1];
        return first + "*****" + last;
    }

    private static boolean deleteQuietly(Path target) {
        try {
            return Files.deleteIfExists(target);
        } catch (IOException ignored) {
            return false;
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
            return new InetSocketAddress("127.0.0.1", 4444);
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
