package dev.replayshield.security;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public final class PasswordCodec {

    private PasswordCodec() {
    }

    public static String hashPassword(char[] password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] bytes = toUtf8Bytes(password);
        try {
            byte[] digest = md.digest(bytes);
            return Base64.getEncoder().encodeToString(digest);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    public static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] bytes = password.getBytes(StandardCharsets.UTF_8);
        try {
            byte[] digest = md.digest(bytes);
            return Base64.getEncoder().encodeToString(digest);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    public static String makeHint(char[] password) {
        char first = password[0];
        char last = password[password.length - 1];
        return first + "*****" + last;
    }

    private static byte[] toUtf8Bytes(char[] source) {
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(source));
        byte[] out = new byte[encoded.remaining()];
        encoded.get(out);
        if (encoded.hasArray()) {
            Arrays.fill(encoded.array(), (byte) 0);
        }
        return out;
    }
}
