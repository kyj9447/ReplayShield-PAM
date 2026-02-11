package dev.replayshield.task;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import dev.replayshield.util.PathResolver;
import dev.replayshield.util.ReplayShieldException;
import dev.replayshield.util.ReplayShieldException.ErrorType;

public final class ServerTask {

    private ServerTask() {} // 인스턴스 생성 금지

    public static void moveUnknownUserDbsToInactive() {
        Set<String> osUsers = loadOsUsers();
        List<String> dbUsers = PathResolver.listUserEncryptedDbUsernames();
        int movedCount = 0;

        for (String dbUser : dbUsers) {
            if (osUsers.contains(dbUser)) {
                continue;
            }
            Path movedPath = PathResolver.moveUserEncryptedDbToInactive(dbUser);
            if (movedPath != null) {
                movedCount++;
                System.out.println("Moved inactive user DB: " + dbUser + " -> " + movedPath);
            }
        }

        if (movedCount > 0) {
            System.out.println("Inactive user DB cleanup complete. moved=" + movedCount);
        }
    }

    public static byte[] tryConsumeCachedAdminKey() {
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

    private static Set<String> loadOsUsers() {
        Set<String> users = loadUsersWithGetent();
        if (!users.isEmpty()) {
            return users;
        }
        return loadUsersFromEtcPasswd();
    }

    private static Set<String> loadUsersWithGetent() {
        Set<String> users = new HashSet<>();
        Process process = null;
        try {
            process = new ProcessBuilder("getent", "passwd").start();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    int sep = line.indexOf(':');
                    if (sep > 0) {
                        users.add(line.substring(0, sep));
                    }
                }
            }
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                return new HashSet<>();
            }
            return users;
        } catch (IOException exception) {
            return new HashSet<>();
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new ReplayShieldException(
                    ErrorType.SYSTEM_ENVIRONMENT,
                    "Interrupted while loading OS users.",
                    exception);
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }

    private static Set<String> loadUsersFromEtcPasswd() {
        Set<String> users = new HashSet<>();
        Path passwdPath = Path.of("/etc/passwd");
        try {
            for (String line : Files.readAllLines(passwdPath, StandardCharsets.UTF_8)) {
                int sep = line.indexOf(':');
                if (sep > 0) {
                    users.add(line.substring(0, sep));
                }
            }
        } catch (IOException exception) {
            throw new ReplayShieldException(
                    ErrorType.SYSTEM_ENVIRONMENT,
                    "Failed to load OS users from /etc/passwd.",
                    exception);
        }
        return users;
    }
}
