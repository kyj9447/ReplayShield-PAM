package dev.replayshield.util;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

public class PathResolver {

    public static File getSaltFile() {
        return new File("/etc/replayshield/salt.bin");
    }

    public static File getEncryptedDbFile() {
        return new File("/var/lib/replayshield/secure.db.enc");
    }

    public static File getMemoryDbDir() {
        return new File("/dev/shm/replayshield");
    }

    public static File getAdminKeyCacheFile() {
        return new File(getMemoryDbDir(), "admin.key");
    }

    // 메모리 영역에 [복호화된 DB]용 임시 파일 생성
    public static Path createMemoryDbTempFile() {
        File dir = getMemoryDbDir();
        if (!dir.exists()) { // 없으면
            if (!dir.mkdirs()) { // 만들기 - 실패하면 예외
                throw new ReplayShieldException(
                        ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                        "ERROR: Failed to create " + dir.getAbsolutePath());
            }
        }

        // 임시파일 생성 시도
        try {
            Path dirPath = dir.toPath();
            Files.setPosixFilePermissions(dirPath, PosixFilePermissions.fromString("rwx------"));
            return Files.createTempFile(dirPath, "replayshield", ".db"); // Path 반환

        } catch (IOException exception) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                    "ERROR: Unable to create tmpfs database file.",
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
        if (!getEncryptedDbFile().getParentFile().exists() && !getEncryptedDbFile().getParentFile().mkdirs()) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.SYSTEM_ENVIRONMENT,
                    "ERROR: Unable to create encrypted DB directory.");
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
            boolean isTmpfs = Files.readString(Path.of("/proc/mounts"))
                    .lines()
                    .anyMatch(line -> line.contains(" /dev/shm ") && line.contains("tmpfs"));
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
