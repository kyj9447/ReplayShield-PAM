package dev.replayshield.util;

import java.io.Console;
import java.io.IOException;

public final class CliUtils {

    private static final Console CONSOLE = System.console();

    private CliUtils() {
    }

    public static int readInt(String prompt) {
        System.out.print(prompt);
        while (true) {
            String line = CONSOLE.readLine().trim();
            try {
                return Integer.parseInt(line);
            } catch (NumberFormatException exception) {
                System.out.println("Invalid number. Please enter an integer.");
            }
        }
    }

    public static void consoleClear() {
        try {
            new ProcessBuilder("clear").inheritIO().start().waitFor();
        } catch (IOException | InterruptedException ignored) {
        }
        System.out.println("=== ReplayShield Manage CLI ===");
    }

    public static void consoleClear(String payload) {
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
