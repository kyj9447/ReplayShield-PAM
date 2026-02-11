package dev.replayshield.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class IoUtils {

    private IoUtils() {
    }

    public static void deleteQuietly(Path target) {
        try {
            Files.deleteIfExists(target);
        } catch (IOException ignored) {
        }
    }
}
