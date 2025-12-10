package dev.replayshield.util;

import java.io.IOException;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * Centralized error reporter that prevents stack traces from hitting stdout/stderr
 * while still allowing contextual messages to be logged.
 */
public final class ErrorReporter {

    private static final Logger LOGGER = Logger.getLogger(ErrorReporter.class.getName());

    static {
        try {
            Handler handler = new FileHandler("%h/replayshield.log", true);
            handler.setFormatter(new SimpleFormatter());
            handler.setLevel(Level.ALL);
            LOGGER.addHandler(handler);
            LOGGER.setUseParentHandlers(false);
            LOGGER.setLevel(Level.ALL);
        } catch (IOException | SecurityException exception) {
            System.err.println("[LOGGER] Failed to initialize log file: " + exception.getMessage());
        }
    }

    private ErrorReporter() {
    }

    public static void logError(String context, Throwable throwable) {
        log(Level.WARNING, "[ERROR]", context, throwable);
    }

    public static void logError(String context, String detail) {
        log(Level.WARNING, "[ERROR]", context, detail);
    }

    public static void logFatal(String context, Throwable throwable) {
        log(Level.SEVERE, "[FATAL]", context, throwable);
    }

    public static void logFatal(String context, String detail) {
        log(Level.SEVERE, "[FATAL]", context, detail);
    }

    private static void log(Level level, String tag, String context, Throwable throwable) {
        String detail = null;
        if (throwable != null) {
            detail = throwable.getMessage();
            if (detail == null || detail.isBlank()) {
                detail = throwable.getClass().getSimpleName();
            }
        }
        log(level, tag, context, detail, throwable);
    }

    private static void log(Level level, String tag, String context, String detail) {
        log(level, tag, context, detail, null);
    }

    private static void log(Level level, String tag, String context, String detail, Throwable throwable) {
        StringBuilder message = new StringBuilder(tag).append(' ');
        if (context != null && !context.isBlank()) {
            message.append(context).append(':').append(' ');
        }
        if (detail == null || detail.isBlank()) {
            detail = "An error occurred";
        }
        message.append(detail);
        System.err.println(message);

        if (LOGGER.isLoggable(level)) {
            if (throwable != null) {
                LOGGER.log(level, message.toString(), throwable);
            } else {
                LOGGER.log(level, message.toString());
            }
        }
    }
}
