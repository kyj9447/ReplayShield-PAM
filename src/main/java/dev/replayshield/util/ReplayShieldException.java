package dev.replayshield.util;

/**
 * Centralized unchecked exception for ReplayShield.
 * Use {@link #getType()} to determine the functional area of the failure.
 */
public class ReplayShieldException extends RuntimeException {

    // 타입
    private final ErrorType type;

    // 생성자 1
    public ReplayShieldException(ErrorType type, String message) {
        super(message);
        this.type = type;
    }

    // 생성자 2
    public ReplayShieldException(ErrorType type, String message, Throwable cause) {
        super(message, cause);
        this.type = type;
    }

    // 타입 Getter
    public ErrorType getType() {
        return type;
    }

    public enum ErrorType {
        SYSTEM_ENVIRONMENT,
        INITIALIZATION,
        ADMIN_AUTH,
        DATABASE_ACCESS,
        HTTP_SERVER,
        PAM_AUTH,
        CONFIGURATION,
        CRYPTO,
        CONSOLE_REQUIRED,
        UNKNOWN
    }
}
