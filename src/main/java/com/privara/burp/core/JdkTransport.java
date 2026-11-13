package com.privara.burp.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Plain {@code java.net.http}, NOT Burp's HTTP stack: a call made through Burp would appear in
 * Burp's Logger with the Authorization header in it, and every other extension's HTTP handler
 * would see it. No proxy and no redirects: the token goes to the configured base URL and nowhere
 * else. The client's threads are this transport's own, and {@link #close()} stops them, so
 * unloading the extension leaves nothing running.
 */
public final class JdkTransport implements Transport {
    static final long MAX_BODY = 64L * 1024 * 1024;

    private final ExecutorService exec = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "privara-burp-http");
        t.setDaemon(true);
        return t;
    });
    private final HttpClient http = HttpClient.newBuilder()
            .proxy(HttpClient.Builder.NO_PROXY)
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(15))
            .executor(exec)
            .build();
    private final AtomicBoolean closed = new AtomicBoolean(false);

    @Override
    public String name() {
        return "direct";
    }

    @Override
    public Response send(String method, URI uri, List<String[]> headers, byte[] body, int timeoutSeconds)
            throws IOException, InterruptedException {
        if (closed.get()) {
            throw new IOException("the extension is unloading");
        }
        HttpRequest.Builder b = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(timeoutSeconds));
        for (String[] h : headers) {
            b.header(h[0], h[1]);
        }
        if ("POST".equals(method)) {
            b.POST(HttpRequest.BodyPublishers.ofByteArray(body == null ? new byte[0] : body));
        } else {
            b.GET();
        }
        HttpResponse<InputStream> r = http.send(b.build(), HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream in = r.body()) {
            return new Response(r.statusCode(), readCapped(in));
        }
    }

    static byte[] readCapped(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[65536];
        long total = 0;
        int n;
        while ((n = in.read(buf)) > 0) {
            total += n;
            if (total > MAX_BODY) {
                throw new IOException("answer larger than " + (MAX_BODY >> 20) + " MB");
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    /** True once {@link #close()} ran and the client's threads were told to stop. */
    public boolean isClosed() {
        return closed.get() && exec.isShutdown();
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        // Java 21+ (Burp ships a newer runtime) can shut the client down; on 17 the selector
        // thread ends by itself once the client is unreachable. Reflection keeps --release 17.
        try {
            Method m = HttpClient.class.getMethod("shutdownNow");
            m.invoke(http);
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // not available on this runtime
        }
        exec.shutdownNow();
        try {
            exec.awaitTermination(500, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
