package dev.replayshield.server;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import dev.replayshield.util.ReplayShieldException;

public class HttpAuthServer {

    private final HttpServer server;
    private final PamAuthHandler authHandler;

    public HttpAuthServer(int port, byte[] key) throws IOException {
        this.authHandler = new PamAuthHandler(key);

        InetSocketAddress addr = new InetSocketAddress("127.0.0.1", port);
        this.server = HttpServer.create(addr, 0);

        this.server.createContext("/auth", this::handleAuth);
        this.server.setExecutor(Executors.newCachedThreadPool());
    }

    private void handleAuth(HttpExchange exchange) throws IOException {
        try (exchange) {
            if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                byte[] body = "OK".getBytes();
                exchange.sendResponseHeaders(200, body.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(body);
                }
                return;
            }

            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                String result = authHandler.handleHttpPost(exchange);
                byte[] body = result.getBytes();
                exchange.sendResponseHeaders(200, body.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(body);
                }
                return;
            }

            exchange.sendResponseHeaders(405, -1);
        } catch (ReplayShieldException exception) {
            System.err.println("[HTTP] " + exception.getMessage());
            sendError(exchange);
        } catch (Exception exception) {
            System.err.println("[HTTP] Unexpected error: " + exception.getMessage());
            sendError(exchange);
        }
    }

    private void sendError(HttpExchange exchange) throws IOException {
        byte[] body = "FAIL".getBytes();
        exchange.sendResponseHeaders(500, body.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(body);
        }
    }

    public void start() {
        this.server.start();
    }

    public void stop(int delaySeconds) {
        this.server.stop(delaySeconds);
    }
}
