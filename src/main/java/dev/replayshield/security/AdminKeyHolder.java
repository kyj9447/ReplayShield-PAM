package dev.replayshield.security;

import java.util.Arrays;

public class AdminKeyHolder {

    // volatile 사용
    private static volatile byte[] key;

    public static void setKey(byte[] k) {
        key = k;
    }

    public static byte[] getKey() {
        return key;
    }

    public static boolean hasKey() {
        return key != null;
    }

    public static void clear() {
        if (key != null) {
            Arrays.fill(key, (byte) 0); // 키 삭제
            key = null; // 참조 삭제
        }
    }
}
