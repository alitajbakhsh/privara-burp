package com.privara.burp.core;

import java.io.IOException;
import java.net.URI;
import java.util.List;

/**
 * How one Privara API call leaves the machine. {@link PrivaraClient} builds the call (base URL,
 * path, Authorization header, body) and checks the answer; a Transport only moves the bytes.
 *
 * Two exist:
 * <ul>
 *   <li>{@link JdkTransport}: Java's own HTTP client, no proxy, no redirects. The default. The
 *       token never enters a Burp tool, so it is never in Logger and no other extension's HTTP
 *       handler sees it.</li>
 *   <li>{@code BurpTransport} (the Montoya side): Burp's own networking ({@code Http.sendRequest}),
 *       chosen in Settings, so Burp's upstream proxy, SOCKS proxy and TLS settings apply. Redirects
 *       are never followed and the server certificate is verified there too.</li>
 * </ul>
 * Every transport must NOT follow redirects; {@link PrivaraClient} refuses a 3xx answer either way.
 */
public interface Transport {
    /** The answer: status code and the whole body (already size-capped by the transport). */
    final class Response {
        public final int status;
        public final byte[] body;

        public Response(int status, byte[] body) {
            this.status = status;
            this.body = body == null ? new byte[0] : body;
        }
    }

    /**
     * Send one request. {@code headers} are name/value pairs in order. A network failure is an
     * IOException; its message must not contain the request headers.
     */
    Response send(String method, URI uri, List<String[]> headers, byte[] body, int timeoutSeconds)
            throws IOException, InterruptedException;

    /** A short name for the Settings tab and the log ("direct" or "Burp networking"). */
    String name();

    /** Release threads and connections (the extension is being unloaded). Idempotent. */
    default void close() {
    }
}
