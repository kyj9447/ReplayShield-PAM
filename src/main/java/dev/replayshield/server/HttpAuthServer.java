package dev.replayshield.server;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import dev.replayshield.util.ErrorReporter;

public class HttpAuthServer {

    public static final int DEFAULT_PORT = 4444;

    private final HttpServer server;
    private final PamAuthHandler authHandler;
    private final ExecutorService executor;

    public HttpAuthServer(int port, byte[] key) throws IOException {
        this.authHandler = new PamAuthHandler(key);

        InetSocketAddress addr = new InetSocketAddress("127.0.0.1", port);
        this.server = HttpServer.create(addr, 0);

        // '/auth'경로에 handleAuth()를 핸들러로 등록
        this.server.createContext("/auth", this::handleAuth);
        // Fixed-size pool to avoid unbounded thread growth.
        int threads = Math.max(2, Runtime.getRuntime().availableProcessors());
        this.executor = Executors.newFixedThreadPool(threads);
        this.server.setExecutor(executor);
    }

    private void handleAuth(HttpExchange exchange) throws IOException {
        try {
            // POST가 아니면 405
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            // 실제 인증로직 실행
            String result = authHandler.handleHttpPost(exchange);

            byte[] body = result.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        } catch (Exception exception) {
            ErrorReporter.logError("HTTP", exception);
            sendErrorQuietly(exchange);
        } finally {
            exchange.close();
        }
    }

    private void sendErrorQuietly(HttpExchange exchange) {
        try {
            exchange.sendResponseHeaders(500, 0);
            try (OutputStream os = exchange.getResponseBody()) {
                os.flush();
            }
        } catch (IOException ignored) {
        }
    }

    public void start() {
        this.server.start();
    }

    public void stop(int delaySeconds) {
        this.server.stop(delaySeconds);
        this.executor.shutdown();
    }
}
