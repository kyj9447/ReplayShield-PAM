package dev.replayshield.server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.sun.net.httpserver.HttpExchange;

import dev.replayshield.db.SecureDbSession;
import dev.replayshield.util.ReplayShieldException;
import dev.replayshield.util.ReplayShieldException.ErrorType;

public class PamAuthHandler {

    private final byte[] key;

    public PamAuthHandler(byte[] key) {
        this.key = key;
    }

    public String handleHttpPost(HttpExchange exchange) throws SQLException {
        String body = readRequestBody(exchange);

        Map<String, String> form = parseFormUrlEncoded(body);
        String username = form.get("username");
        String password = form.get("password");

        if (username == null || password == null) {
            return "FAIL";
        }

        return authenticate(username, password);
    }

    private String readRequestBody(HttpExchange exchange) {
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        } catch (IOException exception) {
            throw new ReplayShieldException(
                    ErrorType.HTTP_SERVER,
                    "Failed to read HTTP request body",
                    exception);
        }
    }

    private Map<String, String> parseFormUrlEncoded(String body) {
        Map<String, String> map = new HashMap<>();
        if (body == null || body.isEmpty())
            return map;
        String[] parts = body.split("&");
        for (String part : parts) {
            int idx = part.indexOf('=');
            if (idx <= 0)
                continue;
            String k = URLDecoder.decode(part.substring(0, idx), StandardCharsets.UTF_8);
            String v = URLDecoder.decode(part.substring(idx + 1), StandardCharsets.UTF_8);
            map.put(k, v);
        }
        return map;
    }

    // PASS/FAIL
    public String authenticate(String username, String password) throws SQLException {
        try (SecureDbSession.DbSession session = SecureDbSession.openWritable(key)) {
            return doAuth(session.connection(), username, password);
        }
    }

    private String doAuth(Connection conn, String username, String password) throws SQLException {
        String hash = hashPassword(password);

        // 1) user_config에서 block_count 조회
        int blockCount;
        try (PreparedStatement ps = conn.prepareStatement("""
                    SELECT block_count FROM user_config WHERE username=?
                """)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return "FAIL"; // 사용자 없음
                }
                blockCount = rs.getInt(1);
            }
        }

        refreshBlockedState(conn, username, blockCount);

        // 2) password_pool에서 해당 패스워드 존재 여부 확인
        int pwId;
        String pwHint;
        boolean blocked;

        try (PreparedStatement ps = conn.prepareStatement("""
                    SELECT id, pw_hint, blocked FROM password_pool
                    WHERE username=? AND pw_hash=?
                """)) {
            ps.setString(1, username);
            ps.setString(2, hash);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return "FAIL"; // 등록되지 않은 PW
                }
                pwId = rs.getInt("id");
                pwHint = rs.getString("pw_hint");
                blocked = rs.getInt("blocked") == 1;
            }
        }

        long now = System.currentTimeMillis();

        // 3-1) block된 경우 last_use 업데이트 하고 FAIL
        if (blocked) {
            try (PreparedStatement ps = conn.prepareStatement("""
                        UPDATE password_pool
                        SET last_use = ?
                        WHERE id=?
                    """)) {
                ps.setLong(1, now);
                ps.setInt(2, pwId);
                ps.executeUpdate();
            }
            refreshBlockedState(conn, username, blockCount);
            return "FAIL";
        }

        // 3-2) PASS: history에 추가
        try (PreparedStatement ps = conn.prepareStatement("""
                    INSERT INTO password_history(username, pw_hash, pw_hint, created_at)
                    VALUES(?, ?, ?, ?)
                """)) {
            ps.setString(1, username);
            ps.setString(2, hash);
            ps.setString(3, pwHint != null ? pwHint : "****");
            ps.setLong(4, now);
            ps.executeUpdate();
        }

        // hit_count/last_use 증가
        try (PreparedStatement ps = conn.prepareStatement("""
                    UPDATE password_pool
                    SET hit_count = hit_count + 1,
                        last_use = ?
                    WHERE id=?
                """)) {
            ps.setLong(1, now);
            ps.setInt(2, pwId);
            ps.executeUpdate();
        }

        refreshBlockedState(conn, username, blockCount);

        return "PASS";
    }

    private String hashPassword(String pw) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(pw.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new ReplayShieldException(
                    ErrorType.PAM_AUTH,
                    "SHA-256 digest not available",
                    exception);
        }
    }

    // last_use 기준으로 block 대상 패스워드계산
    public static void refreshBlockedState(Connection conn, String username, int blockCount) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("""
                UPDATE password_pool SET blocked=0 WHERE username=?
                """)) {
            ps.setString(1, username);
            ps.executeUpdate();
        }

        if (blockCount <= 0) {
            return;
        }

        try (PreparedStatement ps = conn.prepareStatement("""
                UPDATE password_pool
                SET blocked=1
                WHERE id IN (
                    SELECT id FROM password_pool
                    WHERE username=? AND last_use > 0
                    ORDER BY last_use DESC
                    LIMIT ?
                )
                """)) {
            ps.setString(1, username);
            ps.setInt(2, blockCount);
            ps.executeUpdate();
        }
    }
}
