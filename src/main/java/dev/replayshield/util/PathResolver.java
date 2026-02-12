package dev.replayshield.util;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public final class PathResolver {
    private static final String USER_DB_SUFFIX = ".db.enc";
    private static final String USERNAME_PATH_PATTERN = "^[A-Za-z0-9._-]+$";

    private PathResolver() {
    }

    public static File getSaltFile() {
        return new File("/etc/replayshield/salt.bin");
    }

    public static File getEncryptedDbDir() {
        return new File("/var/lib/replayshield/users");
    }

    public static File getInactiveEncryptedDbDir() {
        return new File(getEncryptedDbDir(), "inactive");
    }

    public static File getAdminMarkerFile() {
        return new File("/var/lib/replayshield/admin.marker");
    }

    public static File getUserEncryptedDbFile(String username) {
        String normalized = normalizeUsernameForPath(username);
        return new File(getEncryptedDbDir(), normalized + USER_DB_SUFFIX);
    }

    public static File getInactiveUserEncryptedDbFile(String username) {
        String normalized = normalizeUsernameForPath(username);
        return new File(getInactiveEncryptedDbDir(), normalized + USER_DB_SUFFIX);
    }

    public static boolean userEncryptedDbExists(String username) {
        return getUserEncryptedDbFile(username).exists();
    }

    public static boolean userEncryptedDbExistsInInactive(String username) {
        return getInactiveUserEncryptedDbFile(username).exists();
    }

    public static boolean hasAnyUserEncryptedDb() {
        File dir = getEncryptedDbDir();
        if (!dir.exists() || !dir.isDirectory()) {
            return false;
        }
        File[] files = dir.listFiles((d, name) -> name.endsWith(USER_DB_SUFFIX));
        return files != null && files.length > 0;
    }

    public static List<String> listUserEncryptedDbUsernames() {
        List<String> usernames = new ArrayList<>();
        File dir = getEncryptedDbDir();
        if (!dir.exists() || !dir.isDirectory()) {
            return usernames;
        }
        File[] files = dir.listFiles((d, name) -> name.endsWith(USER_DB_SUFFIX));
        if (files == null) {
            return usernames;
        }
        for (File file : files) {
            String name = file.getName();
            usernames.add(name.substring(0, name.length() - USER_DB_SUFFIX.length()));
        }
        usernames.sort(Comparator.naturalOrder());
        return usernames;
    }

    public static void deleteAllUserEncryptedDbs() {
        deleteUserDbFilesInDir(getEncryptedDbDir());
        deleteUserDbFilesInDir(getInactiveEncryptedDbDir());
    }

    private static void deleteUserDbFilesInDir(File dir) {
        if (!dir.exists() || !dir.isDirectory()) {
            return;
        }
        File[] files = dir.listFiles((d, name) -> name.endsWith(USER_DB_SUFFIX));
        if (files == null) {
            return;
        }
        for (File file : files) {
            try {
                Files.deleteIfExists(file.toPath());
            } catch (IOException exception) {
                throw new ReplayShieldException(
                        ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                        "ERROR: Unable to delete user encrypted DB: " + file.getAbsolutePath(),
                        exception);
            }
        }
    }

    public static Path moveUserEncryptedDbToInactive(String username) {
        File activeFile = getUserEncryptedDbFile(username);
        if (!activeFile.exists()) {
            return null;
        }

        File inactiveDir = getInactiveEncryptedDbDir();
        if (!inactiveDir.exists() && !inactiveDir.mkdirs()) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                    "ERROR: Unable to create inactive encrypted DB directory.");
        }

        Path source = activeFile.toPath();
        Path target = buildInactiveMoveTarget(username);
        try {
            return Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException atomicMoveFailure) {
            try {
                return Files.move(source, target);
            } catch (IOException exception) {
                throw new ReplayShieldException(
                        ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                        "ERROR: Unable to move user DB to inactive: " + source + " -> " + target,
                        exception);
            }
        }
    }

    private static Path buildInactiveMoveTarget(String username) {
        Path base = getInactiveUserEncryptedDbFile(username).toPath();
        if (!Files.exists(base)) {
            return base;
        }
        long now = System.currentTimeMillis();
        return getInactiveEncryptedDbDir().toPath().resolve(username + "." + now + USER_DB_SUFFIX);
    }

    private static String normalizeUsernameForPath(String username) {
        if (username == null) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.CONFIGURATION,
                    "ERROR: Username is required.");
        }
        String normalized = username.trim();
        if (normalized.isEmpty()) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.CONFIGURATION,
                    "ERROR: Username is required.");
        }
        if (!normalized.matches(USERNAME_PATH_PATTERN)) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.CONFIGURATION,
                    "ERROR: Username contains unsupported characters for DB path.");
        }
        return normalized;
    }

    public static File getMemoryDbDir() {
        return new File("/dev/shm/replayshield");
    }

    public static File getAdminKeyCacheFile() {
        return new File(getMemoryDbDir(), "admin.key");
    }

    public static Path createMemoryTempFile(String prefix, String suffix) {
        File dir = getMemoryDbDir();
        if (!dir.exists()) {
            if (!dir.mkdirs()) {
                throw new ReplayShieldException(
                        ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                        "ERROR: Failed to create " + dir.getAbsolutePath());
            }
        }
        try {
            Path dirPath = dir.toPath();
            Files.setPosixFilePermissions(dirPath, PosixFilePermissions.fromString("rwx------"));
            return Files.createTempFile(
                    dirPath,
                    prefix == null ? "replayshield" : prefix,
                    suffix == null ? ".tmp" : suffix);
        } catch (IOException exception) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                    "ERROR: Unable to create tmpfs temporary file.",
                    exception);
        }
    }

    // 메모리 영역에 [복호화된 DB]용 임시 파일 생성
    public static Path createMemoryDbTempFile() {
        return createMemoryTempFile("replayshield", ".db");
    }

    public static void writeAdminMarker(byte[] markerBytes) {
        Path markerPath = getAdminMarkerFile().toPath();
        try {
            Files.write(markerPath, markerBytes);
        } catch (IOException exception) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                    "ERROR: Failed to write admin marker file.",
                    exception);
        }
    }

    public static byte[] readAdminMarker() {
        Path markerPath = getAdminMarkerFile().toPath();
        try {
            return Files.readAllBytes(markerPath);
        } catch (IOException exception) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                    "ERROR: Failed to read admin marker file.",
                    exception);
        }
    }

    public static void deleteAdminMarkerIfExists() {
        try {
            Files.deleteIfExists(getAdminMarkerFile().toPath());
        } catch (IOException exception) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                    "ERROR: Failed to delete admin marker file.",
                    exception);
        }
    }

    // 필요 디렉터리 생성 확인
    public static void ensureBaseDirs() {
        if (!getSaltFile().getParentFile().exists() && !getSaltFile().getParentFile().mkdirs()) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                    "ERROR: Unable to create salt directory.");
        }
        if (!getEncryptedDbDir().exists() && !getEncryptedDbDir().mkdirs()) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                    "ERROR: Unable to create encrypted DB directory.");
        }
        if (!getInactiveEncryptedDbDir().exists() && !getInactiveEncryptedDbDir().mkdirs()) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                    "ERROR: Unable to create inactive encrypted DB directory.");
        }
        if (!getMemoryDbDir().exists() && !getMemoryDbDir().mkdirs()) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                    "ERROR: Unable to create /dev/shm/replayshield.");
        }
    }

    // 메모리 fs 사용 가능 확인
    public static void ensureMemoryFsAvailable() {

        // 1. 먼저 디렉터리 존재 확인
        File shm = new File("/dev/shm");
        if (!shm.exists() || !shm.isDirectory()) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                    "ERROR: /dev/shm does not exist or is not a directory. ReplayShield requires RAM-backed tmpfs.");
        }

        // 2. 해당 마운트가 실제로 tmpfs(메모리 기반 임시파티션)인지 확인
        try {
            String mounts = Files.readString(Path.of("/proc/mounts"));
            boolean isTmpfs = false;
            String[] mountLines = mounts.split("\n");
            for (String line : mountLines) {
                if (line.contains(" /dev/shm ") && line.contains("tmpfs")) {
                    isTmpfs = true;
                    break;
                }
            }
            if (!isTmpfs) {
                throw new ReplayShieldException(ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                        "ERROR: /dev/shm is NOT tmpfs (memory). ReplayShield cannot run on disk-backed /dev/shm.");
            }
        } catch (ReplayShieldException | IOException exception) {
            throw new ReplayShieldException(ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                    "ERROR: Unable to verify /dev/shm filesystem type.",
                    exception);
        }

        // 3. 메모리 fs 파일 생성, 삭제 테스트
        try {
            Path test = Path.of("/dev/shm/replayshield_test.tmp");
            Files.writeString(test, "test");
            Files.deleteIfExists(test);
        } catch (IOException exception) {
            throw new ReplayShieldException(ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                    "ERROR: /dev/shm is not writable. ReplayShield requires write access.",
                    exception);
        }
    }
}
