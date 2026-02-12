package dev.replayshield.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.replayshield.util.ReplayShieldException.ErrorType;

public final class BenchmarkUtils {

    // Shared benchmark constants (also used by benchmark child process).
    static final int FIXED_BENCH_PASSWORD_POOL_SIZE = 10;
    static final int DEFAULT_BENCH_WARMUP_ITERATIONS = 100;
    static final int DEFAULT_BENCH_MEASURE_ITERATIONS = 1000;
    static final String DEFAULT_BENCH_USERS_LIST = "1,10,100,1000,10000";
    static final int BENCHMARK_TARGET_PASSWORD_INDEX = 0;
    static final String BENCHMARK_USER_DB_SUFFIX = ".db.enc";
    static final String BENCHMARK_INTERNAL_KEY_SEED = "ReplayShieldBenchmarkInternalKeyV1";
    static final String BENCHMARK_RESULT_PREFIX = "BENCH_RESULT";
    private static final Pattern BENCHMARK_RESULT_PATTERN = Pattern.compile(
            "^" + BENCHMARK_RESULT_PREFIX
                    + "\\s+users=(\\d+)\\s+single\\(avg=([0-9]+(?:\\.[0-9]+)?),med=([0-9]+(?:\\.[0-9]+)?),min=([0-9]+(?:\\.[0-9]+)?),max=([0-9]+(?:\\.[0-9]+)?)\\)"
                    + "\\s+peruser\\(avg=([0-9]+(?:\\.[0-9]+)?),med=([0-9]+(?:\\.[0-9]+)?),min=([0-9]+(?:\\.[0-9]+)?),max=([0-9]+(?:\\.[0-9]+)?)\\)$");

    private BenchmarkUtils() {
    }

    record BenchmarkOptions(
            int warmupIterations,
            int measureIterations,
            int[] usersList) {
    }

    private record BenchmarkScenarioResult(
            int users,
            double singleAvgMs,
            double singleMedianMs,
            double singleMinMs,
            double singleMaxMs,
            double perUserAvgMs,
            double perUserMedianMs,
            double perUserMinMs,
            double perUserMaxMs) {
    }

    // =======================================================================
    // 벤치마크 오케스트레이터
    // =======================================================================
    public static void runBenchmarkMode(String[] args) throws IOException, SQLException, NoSuchAlgorithmException {
        // --help 인자
        boolean hasHelpArg = false;
        for (String arg : args) {
            if ("--help".equals(arg) || "-h".equals(arg)) {
                hasHelpArg = true;
                break;
            }
        }
        if (hasHelpArg) {
            System.out.println(String.format("""
                    Usage: replayshield benchmark [options]
                      --warmup=<N>           Warmup iterations per mode (default: %d)
                      --measure=<N>          Measured requests per mode (default: %d)
                      --users-list=<CSV>     User-count sweep (default: %s)
                      --users=<N>            Single user-count override
                    """, DEFAULT_BENCH_WARMUP_ITERATIONS, DEFAULT_BENCH_MEASURE_ITERATIONS,
                    DEFAULT_BENCH_USERS_LIST));
            return;
        }

        // 인자 파싱
        BenchmarkOptions options = parseBenchmarkOptions(args, 1);

        // 벤치마크 시작
        // 벤치마크 시나리오 출력
        String usersLabel;
        if (options.usersList().length == 1) {
            usersLabel = Integer.toString(options.usersList()[0]);
        } else {
            StringBuilder usersBuilder = new StringBuilder();
            for (int i = 0; i < options.usersList().length; i++) {
                if (i > 0) {
                    usersBuilder.append(',');
                }
                usersBuilder.append(options.usersList()[i]);
            }
            usersLabel = usersBuilder.toString();
        }

        CliUtils.consoleClear("[ Benchmark ]");
        System.out.println("============================================================================");
        System.out.println("mode       : compare single-db vs per-user-db");
        System.out.println("execution  : parent(runBenchmarkMode) + child(BenchmarkProcessMain)");
        System.out.println("warmup     : " + options.warmupIterations() + " iterations per mode");
        System.out.println("measure    : " + options.measureIterations() + " requests per mode");
        System.out.println("users      : " + usersLabel);
        System.out.println("passwords  : " + FIXED_BENCH_PASSWORD_POOL_SIZE + " per user");
        System.out.println("scope      : one auth cycle end-to-end");
        System.out.println("metrics    : avg, median, min, max");
        System.out.println("order      : alternating modes (single-first, then per-first)");
        System.out.println("============================================================================");
        System.out.println();

        // 서브 프로세스 준비
        String javaBinary = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        String classPath = System.getProperty("java.class.path");

        // users-list 길이만큼 벤치마크 시나리오 실행
        // =========================================================================
        List<BenchmarkScenarioResult> scenarioResults = new ArrayList<>();
        for (int users : options.usersList()) {
            System.out.printf("user=%d benchmarking...%n", users);

            // 서브 프로세스에 전달할 커맨드 구성
            List<String> command = new ArrayList<>();
            command.add(javaBinary);
            command.add("-cp");
            command.add(classPath);
            command.add("dev.replayshield.util.BenchmarkProcessMain");
            command.add("--warmup=" + options.warmupIterations());
            command.add("--measure=" + options.measureIterations());
            command.add("--users=" + users);

            // 서브 프로세스 실행 구성
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true); // stderr를 stdout으로 통합

            BenchmarkScenarioResult parsedScenarioResult = null; // 결과 저장용
            Process process = processBuilder.start(); // 서브 프로세스 실행

            // 서브 프로세스 출력 읽기
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                    BenchmarkScenarioResult parsed = tryParseMachineScenarioResult(line);
                    if (parsed != null) {
                        parsedScenarioResult = parsed;
                    }
                }
            }

            // 서브 프로세스 종료 처리
            int exitCode;
            try {
                exitCode = process.waitFor();
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new ReplayShieldException(
                        ErrorType.SYSTEM_ENVIRONMENT,
                        "Benchmark child process interrupted.",
                        exception);
            }

            if (exitCode != 0) {
                throw new ReplayShieldException(
                        ErrorType.SYSTEM_ENVIRONMENT,
                        "Benchmark child process failed for users=" + users + " (exit code=" + exitCode + ").");
            }
            if (parsedScenarioResult == null) {
                throw new ReplayShieldException(
                        ErrorType.SYSTEM_ENVIRONMENT,
                        "Benchmark child process did not return scenario result for users=" + users + ".");
            }

            // 결과 리스트에 추가
            scenarioResults.add(parsedScenarioResult);
        }
        // =========================================================================

        // 벤치마크 결과 요약 출력
        System.out.println("[Scaling Summary]");
        for (BenchmarkScenarioResult scenario : scenarioResults) {
            System.out.printf(
                    "  users=%d single(avg=%.3f ms,med=%.3f ms,min=%.3f ms,max=%.3f ms) peruser(avg=%.3f ms,med=%.3f ms,min=%.3f ms,max=%.3f ms)%n",
                    scenario.users(),
                    scenario.singleAvgMs(),
                    scenario.singleMedianMs(),
                    scenario.singleMinMs(),
                    scenario.singleMaxMs(),
                    scenario.perUserAvgMs(),
                    scenario.perUserMedianMs(),
                    scenario.perUserMinMs(),
                    scenario.perUserMaxMs());
        }
        System.out.println();
    }

    // =======================================================================
    // 유틸리티
    // =======================================================================

    // =======================================================================
    // 벤치마크 옵션 파싱
    // =======================================================================
    static BenchmarkOptions parseBenchmarkOptions(String[] args, int startIndex) {
        int warmupIterations = DEFAULT_BENCH_WARMUP_ITERATIONS;
        int measureIterations = DEFAULT_BENCH_MEASURE_ITERATIONS;
        int[] usersList = parseUsersListOption(DEFAULT_BENCH_USERS_LIST);

        for (int i = startIndex; i < args.length; i++) {
            String arg = args[i];
            if ("--help".equals(arg) || "-h".equals(arg)) {
                continue;
            }
            if (arg.startsWith("--warmup=")) {
                warmupIterations = parseIntOption("warmup", arg.substring("--warmup=".length()), 0);
                continue;
            }
            if (arg.startsWith("--measure=")) {
                measureIterations = parseIntOption("measure", arg.substring("--measure=".length()), 1);
                continue;
            }
            if (arg.startsWith("--users-list=")) {
                usersList = parseUsersListOption(arg.substring("--users-list=".length()));
                continue;
            }
            if (arg.startsWith("--users=")) {
                int users = parseIntOption("users", arg.substring("--users=".length()), 1);
                usersList = new int[] { users };
                continue;
            }
            throw new ReplayShieldException(
                    ErrorType.CONFIGURATION,
                    "Unknown benchmark option: " + arg + " (use 'replayshield benchmark --help').");
        }

        return new BenchmarkOptions(warmupIterations, measureIterations, usersList);
    }

    // =======================================================================
    // 유저 리스트 파싱
    // =======================================================================
    private static int[] parseUsersListOption(String raw) {
        String trimmed = raw == null ? "" : raw.trim();
        if (trimmed.isEmpty()) {
            throw new ReplayShieldException(
                    ErrorType.CONFIGURATION,
                    "--users-list must contain at least one positive integer.");
        }

        String[] tokens = trimmed.split(",");
        int[] parsed = new int[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            parsed[i] = parseIntOption("users-list", tokens[i].trim(), 1);
        }
        return parsed;
    }

    // =======================================================================
    // 정수 옵션 검증 파싱
    // =======================================================================
    private static int parseIntOption(String name, String raw, int minValue) {
        int parsed;
        try {
            parsed = Integer.parseInt(raw.trim());
        } catch (NumberFormatException exception) {
            throw new ReplayShieldException(
                    ErrorType.CONFIGURATION,
                    "Invalid integer for --" + name + ": " + raw,
                    exception);
        }
        if (parsed < minValue) {
            throw new ReplayShieldException(
                    ErrorType.CONFIGURATION,
                    "--" + name + " must be >= " + minValue);
        }
        return parsed;
    }

    // =======================================================================
    // 결과 전체 파싱 ( stdout 파싱 )
    // =======================================================================
    private static BenchmarkScenarioResult tryParseMachineScenarioResult(String line) {
        if (!line.startsWith(BENCHMARK_RESULT_PREFIX + " ")) {
            return null;
        }

        Matcher matcher = BENCHMARK_RESULT_PATTERN.matcher(line.trim());
        if (!matcher.matches()) {
            throw new ReplayShieldException(
                    ErrorType.SYSTEM_ENVIRONMENT,
                    "Failed to parse benchmark child result line: " + line);
        }

        try {
            int users = Integer.parseInt(matcher.group(1));
            double singleAvgMs = Double.parseDouble(matcher.group(2));
            double singleMedianMs = Double.parseDouble(matcher.group(3));
            double singleMinMs = Double.parseDouble(matcher.group(4));
            double singleMaxMs = Double.parseDouble(matcher.group(5));
            double perUserAvgMs = Double.parseDouble(matcher.group(6));
            double perUserMedianMs = Double.parseDouble(matcher.group(7));
            double perUserMinMs = Double.parseDouble(matcher.group(8));
            double perUserMaxMs = Double.parseDouble(matcher.group(9));
            return new BenchmarkScenarioResult(
                    users,
                    singleAvgMs,
                    singleMedianMs,
                    singleMinMs,
                    singleMaxMs,
                    perUserAvgMs,
                    perUserMedianMs,
                    perUserMinMs,
                    perUserMaxMs);
        } catch (NumberFormatException exception) {
            throw new ReplayShieldException(
                    ErrorType.SYSTEM_ENVIRONMENT,
                    "Failed to parse benchmark child result line: " + line,
                    exception);
        }
    }

}
