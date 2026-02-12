package dev.replayshield.benchmark;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public final class FileLookupBenchmarkMock {

    private static final String FILE_SUFFIX = ".db.enc";
    private static final int DEFAULT_FILE_COUNT = 1000;
    private static final int DEFAULT_FILE_SIZE_BYTES = 4096;
    private static final int DEFAULT_WARMUP = 100;
    private static final int DEFAULT_ITERATIONS = 500;

    private enum TargetPosition {
        HEAD,
        MIDDLE,
        TAIL
    }

    private record BenchmarkConfig(
            int fileCount,
            int fileSizeBytes,
            int warmup,
            int iterations,
            TargetPosition targetPosition,
            boolean keepFiles) {
    }

    private record Dataset(
            Path root,
            Path targetFile,
            String targetFileName) {
    }

    private record BenchmarkSummary(
            long minNanos,
            long p50Nanos,
            long p95Nanos,
            long p99Nanos,
            long maxNanos,
            long totalNanos,
            double avgNanos,
            double throughputOpsPerSec,
            long guardValue) {
    }

    @FunctionalInterface
    private interface BenchmarkOp {
        long run() throws IOException;
    }

    private FileLookupBenchmarkMock() {
    }

    public static void main(String[] args) throws Exception {
        BenchmarkConfig config = parseArgs(args);
        if (config == null) {
            return;
        }

        Path tempRoot = Files.createTempDirectory("replayshield-filebench-");
        try {
            Dataset dataset = prepareDataset(tempRoot, config);

            System.out.println("=== File Lookup Benchmark Mock ===");
            System.out.println("directory  : " + dataset.root());
            System.out.println("files      : " + config.fileCount());
            System.out.println("file size  : " + config.fileSizeBytes() + " bytes");
            System.out.println("warmup     : " + config.warmup());
            System.out.println("iterations : " + config.iterations());
            System.out.println("target     : " + config.targetPosition() + " -> " + dataset.targetFileName());
            System.out.println();

            BenchmarkSummary directReadSummary = runBenchmark(
                    config,
                    () -> directRead(dataset.targetFile()));
            BenchmarkSummary listFindReadSummary = runBenchmark(
                    config,
                    () -> listFindAndRead(dataset.root(), dataset.targetFileName()));
            BenchmarkSummary listFindOnlySummary = runBenchmark(
                    config,
                    () -> listFindOnly(dataset.root(), dataset.targetFileName()));

            printSummary("direct-read", directReadSummary);
            printSummary("list-find-read", listFindReadSummary);
            printSummary("list-find-only", listFindOnlySummary);
            printComparison(directReadSummary, listFindReadSummary, listFindOnlySummary);
        } finally {
            if (config.keepFiles()) {
                System.out.println("Mock files kept at: " + tempRoot);
            } else {
                deleteDirectoryRecursively(tempRoot);
            }
        }
    }

    private static BenchmarkConfig parseArgs(String[] args) {
        int fileCount = DEFAULT_FILE_COUNT;
        int fileSizeBytes = DEFAULT_FILE_SIZE_BYTES;
        int warmup = DEFAULT_WARMUP;
        int iterations = DEFAULT_ITERATIONS;
        TargetPosition targetPosition = TargetPosition.TAIL;
        boolean keepFiles = false;

        for (String arg : args) {
            if ("-h".equals(arg) || "--help".equals(arg)) {
                printUsage();
                return null;
            }
            if ("--keep-files".equals(arg)) {
                keepFiles = true;
                continue;
            }
            if (arg.startsWith("--files=")) {
                fileCount = parsePositiveInt("files", arg.substring("--files=".length()));
                continue;
            }
            if (arg.startsWith("--size-bytes=")) {
                fileSizeBytes = parsePositiveInt("size-bytes", arg.substring("--size-bytes=".length()));
                continue;
            }
            if (arg.startsWith("--warmup=")) {
                warmup = parseNonNegativeInt("warmup", arg.substring("--warmup=".length()));
                continue;
            }
            if (arg.startsWith("--iterations=")) {
                iterations = parsePositiveInt("iterations", arg.substring("--iterations=".length()));
                continue;
            }
            if (arg.startsWith("--target=")) {
                targetPosition = parseTargetPosition(arg.substring("--target=".length()));
                continue;
            }
            throw new IllegalArgumentException("Unknown option: " + arg);
        }

        return new BenchmarkConfig(
                fileCount,
                fileSizeBytes,
                warmup,
                iterations,
                targetPosition,
                keepFiles);
    }

    private static int parsePositiveInt(String name, String raw) {
        int value = parseNonNegativeInt(name, raw);
        if (value <= 0) {
            throw new IllegalArgumentException("--" + name + " must be >= 1");
        }
        return value;
    }

    private static int parseNonNegativeInt(String name, String raw) {
        try {
            int value = Integer.parseInt(raw.trim());
            if (value < 0) {
                throw new IllegalArgumentException("--" + name + " must be >= 0");
            }
            return value;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("Invalid integer for --" + name + ": " + raw, exception);
        }
    }

    private static TargetPosition parseTargetPosition(String raw) {
        if ("head".equalsIgnoreCase(raw)) {
            return TargetPosition.HEAD;
        }
        if ("middle".equalsIgnoreCase(raw)) {
            return TargetPosition.MIDDLE;
        }
        if ("tail".equalsIgnoreCase(raw)) {
            return TargetPosition.TAIL;
        }
        throw new IllegalArgumentException("Invalid --target value: " + raw + " (use head|middle|tail)");
    }

    private static void printUsage() {
        System.out.println("""
                Usage: FileLookupBenchmarkMock [options]
                  --files=<N>          Number of mock files (default: 1000)
                  --size-bytes=<N>     Bytes per file (default: 4096)
                  --warmup=<N>         Warmup iterations (default: 100)
                  --iterations=<N>     Measured iterations (default: 500)
                  --target=<pos>       Target position: head|middle|tail (default: tail)
                  --keep-files         Keep generated files for inspection
                """);
    }

    private static Dataset prepareDataset(Path tempRoot, BenchmarkConfig config) throws IOException {
        Path datasetDir = tempRoot.resolve("mock-users");
        Files.createDirectories(datasetDir);

        for (int userIndex = 0; userIndex < config.fileCount(); userIndex++) {
            String fileName = buildFileName(userIndex);
            Path filePath = datasetDir.resolve(fileName);
            Files.write(filePath, buildFilePayload(userIndex, config.fileSizeBytes()));
        }

        int targetIndex = resolveTargetIndex(config.fileCount(), config.targetPosition());
        String targetFileName = buildFileName(targetIndex);
        Path targetFile = datasetDir.resolve(targetFileName);
        return new Dataset(datasetDir, targetFile, targetFileName);
    }

    private static String buildFileName(int userIndex) {
        return String.format("bench_u%05d%s", userIndex, FILE_SUFFIX);
    }

    private static byte[] buildFilePayload(int userIndex, int fileSizeBytes) {
        byte[] payload = new byte[fileSizeBytes];
        for (int i = 0; i < fileSizeBytes; i++) {
            payload[i] = (byte) ((userIndex + i) & 0xFF);
        }
        return payload;
    }

    private static int resolveTargetIndex(int fileCount, TargetPosition position) {
        if (position == TargetPosition.HEAD) {
            return 0;
        }
        if (position == TargetPosition.MIDDLE) {
            return fileCount / 2;
        }
        return fileCount - 1;
    }

    private static long directRead(Path targetFile) throws IOException {
        byte[] data = Files.readAllBytes(targetFile);
        return consumeBytes(data);
    }

    private static long listFindAndRead(Path dir, String targetFileName) throws IOException {
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*" + FILE_SUFFIX)) {
            for (Path entry : stream) {
                if (targetFileName.equals(entry.getFileName().toString())) {
                    byte[] data = Files.readAllBytes(entry);
                    return consumeBytes(data);
                }
            }
        }
        throw new IllegalStateException("Target file not found: " + targetFileName);
    }

    private static long listFindOnly(Path dir, String targetFileName) throws IOException {
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, "*" + FILE_SUFFIX)) {
            for (Path entry : stream) {
                if (targetFileName.equals(entry.getFileName().toString())) {
                    return entry.getFileName().toString().length();
                }
            }
        }
        throw new IllegalStateException("Target file not found: " + targetFileName);
    }

    private static long consumeBytes(byte[] data) {
        if (data.length == 0) {
            return 0L;
        }
        long sum = data.length;
        sum += Byte.toUnsignedInt(data[0]);
        sum += Byte.toUnsignedInt(data[data.length - 1]);
        return sum;
    }

    private static BenchmarkSummary runBenchmark(BenchmarkConfig config, BenchmarkOp operation) throws IOException {
        for (int i = 0; i < config.warmup(); i++) {
            operation.run();
        }

        long[] samples = new long[config.iterations()];
        long guard = 0L;
        for (int i = 0; i < config.iterations(); i++) {
            long started = System.nanoTime();
            guard += operation.run();
            samples[i] = System.nanoTime() - started;
        }

        long[] sortedSamples = Arrays.copyOf(samples, samples.length);
        Arrays.sort(sortedSamples);

        long total = 0L;
        for (long sample : samples) {
            total += sample;
        }
        double avg = total / (double) samples.length;
        double throughput = total == 0L ? 0.0 : (samples.length * 1_000_000_000.0) / total;

        return new BenchmarkSummary(
                sortedSamples[0],
                percentile(sortedSamples, 0.50),
                percentile(sortedSamples, 0.95),
                percentile(sortedSamples, 0.99),
                sortedSamples[sortedSamples.length - 1],
                total,
                avg,
                throughput,
                guard);
    }

    private static long percentile(long[] sortedSamples, double p) {
        int index = (int) Math.ceil(p * sortedSamples.length) - 1;
        if (index < 0) {
            index = 0;
        }
        if (index >= sortedSamples.length) {
            index = sortedSamples.length - 1;
        }
        return sortedSamples[index];
    }

    private static void printSummary(String label, BenchmarkSummary summary) {
        System.out.println("[" + label + "]");
        System.out.printf("  total      : %.3f ms%n", toMillis(summary.totalNanos()));
        System.out.printf("  avg        : %.3f ms%n", toMillis(summary.avgNanos()));
        System.out.printf("  min        : %.3f ms%n", toMillis(summary.minNanos()));
        System.out.printf("  p50        : %.3f ms%n", toMillis(summary.p50Nanos()));
        System.out.printf("  p95        : %.3f ms%n", toMillis(summary.p95Nanos()));
        System.out.printf("  p99        : %.3f ms%n", toMillis(summary.p99Nanos()));
        System.out.printf("  max        : %.3f ms%n", toMillis(summary.maxNanos()));
        System.out.printf("  throughput : %.2f ops/s%n", summary.throughputOpsPerSec());
        System.out.printf("  guard      : %d%n", summary.guardValue());
        System.out.println();
    }

    private static void printComparison(
            BenchmarkSummary directRead,
            BenchmarkSummary listFindRead,
            BenchmarkSummary listFindOnly) {
        System.out.println("[comparison]");
        printDelta(
                "list-find-read vs direct-read",
                directRead.avgNanos(),
                listFindRead.avgNanos());
        printDelta(
                "list-find-only vs direct-read",
                directRead.avgNanos(),
                listFindOnly.avgNanos());
        printDelta(
                "list-only overhead share",
                listFindRead.avgNanos(),
                listFindOnly.avgNanos());
        System.out.println();
    }

    private static void printDelta(String label, double baseNanos, double changedNanos) {
        double baseMillis = toMillis(baseNanos);
        double changedMillis = toMillis(changedNanos);
        double deltaPercent = 0.0;
        if (baseMillis > 0.0) {
            deltaPercent = ((changedMillis - baseMillis) / baseMillis) * 100.0;
        }
        System.out.printf("  %-30s base=%.3f ms, changed=%.3f ms, delta=%.2f%%%n",
                label + ":",
                baseMillis,
                changedMillis,
                deltaPercent);
    }

    private static double toMillis(long nanos) {
        return nanos / 1_000_000.0;
    }

    private static double toMillis(double nanos) {
        return nanos / 1_000_000.0;
    }

    private static void deleteDirectoryRecursively(Path dir) throws IOException {
        if (dir == null || !Files.exists(dir)) {
            return;
        }
        if (Files.isDirectory(dir)) {
            try (DirectoryStream<Path> children = Files.newDirectoryStream(dir)) {
                for (Path child : children) {
                    deleteDirectoryRecursively(child);
                }
            }
        }
        Files.deleteIfExists(dir);
    }
}
