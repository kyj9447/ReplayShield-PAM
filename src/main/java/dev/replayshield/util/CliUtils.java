package dev.replayshield.util;

import java.io.Console;
import java.io.IOException;

public final class CliUtils {

    private static final Console CONSOLE = System.console();
    private static final String CLI_HEADER = "=== ReplayShield Manage CLI ===";

    private CliUtils() {
    }

    public static int readInt(String prompt) {
        Console console = requireInteractiveConsole();
        System.out.print(prompt);
        while (true) {
            String line = console.readLine().trim();
            try {
                return Integer.parseInt(line);
            } catch (NumberFormatException exception) {
                System.out.println("Invalid number. Please enter an integer.");
            }
        }
    }

    public static Console requireInteractiveConsole() {
        if (CONSOLE == null) {
            throw new ReplayShieldException(
                    ReplayShieldException.ErrorType.CONFIGURATION,
                    "Interactive console required (TTY not detected)");
        }
        return CONSOLE;
    }

    public static void consoleClear(String payload) {
        try {
            new ProcessBuilder("clear").inheritIO().start().waitFor();
        } catch (IOException | InterruptedException ignored) {
        }
        System.out.println(CLI_HEADER);
        if (payload != null) {
            System.out.println(payload);
        }
    }
}
