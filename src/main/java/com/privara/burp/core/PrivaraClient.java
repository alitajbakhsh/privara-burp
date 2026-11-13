package com.privara.burp.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * The Privara public API, as the customer's own token sees it. Nothing else.
 *
 * <ul>
 *   <li>The bytes move through a {@link Transport}: by default {@link JdkTransport} (Java's own
 *       client, no proxy, so the token never enters a Burp tool), or Burp's own networking when
 *       the tester ticks that in Settings (then Burp's upstream proxy and TLS settings apply).</li>
 *   <li>No redirects: the token goes to the configured base URL and nowhere else. A redirect is
 *       reported as an error instead of being followed, whatever the transport.</li>
 *   <li>Every error detail is scrubbed of the token before it is stored in an exception.</li>
 * </ul>
 */
public class PrivaraClient {
    public static final Set<String> RUN_OPS = Set.of("apimap", "cloudcheck", "deeplinks");
    private static final long MAX_BODY = JdkTransport.MAX_BODY;

    private final Supplier<PrivaraConfig> cfg;
    private final Supplier<Transport> transport;
    private final String userAgent;
    /** Called once on a 401: true when a NEW token is now available (this Kali's link rotated). */
    private volatile java.util.function.BooleanSupplier relink = () -> false;

    /** Java's own client (direct, no proxy): the core tests and Selfcheck use this. */
    public PrivaraClient(Supplier<PrivaraConfig> cfg) {
        this(cfg, constant(new JdkTransport()));
    }

    /** The extension passes a supplier that follows the "through Burp's networking" setting. */
    public PrivaraClient(Supplier<PrivaraConfig> cfg, Supplier<Transport> transport) {
        this.cfg = cfg;
        this.transport = transport;
        this.userAgent = "privara-burp/" + Version.VERSION;
    }

    private static Supplier<Transport> constant(Transport t) {
        return () -> t;
    }

    /** The transport the next call will use (for the Settings tab). */
    public String transportName() {
        return transport.get().name();
    }

    /** The configured platform host ("" when not configured): never a request-forging target. */
    public String baseHost() {
        try {
            PrivaraConfig c = cfg.get();
            String h = c == null ? null : URI.create(c.baseUrl()).getHost();
            return h == null ? "" : h;
        } catch (RuntimeException e) {
            return "";
        }
    }

    /** On a 401, ask once for a newer token (KaliLink.Source::reload) and retry the call with it. */
    public void onUnauthorized(java.util.function.BooleanSupplier relink) {
        this.relink = relink == null ? () -> false : relink;
    }

    // ------------------------------------------------------------------ calls

    public Map<String, Object> whoami() throws ApiException {
        return Json.obj(json(get(Endpoints.path(Endpoints.WHOAMI, 0), 30)));
    }

    /** The account's devices. {@link #isAnalysisDevice} picks the ones this extension can use. */
    public List<Map<String, Object>> devices() throws ApiException {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object o : Json.arr(json(get(Endpoints.path(Endpoints.DEVICES, 0), 30)))) {
            out.add(Json.obj(o));
        }
        return out;
    }

    /** A device that can run app-bundle analysis: the server says so in `capabilities`. */
    public static boolean isAnalysisDevice(Map<String, Object> d) {
        for (Object c : Json.arr(d.get("capabilities"))) {
            if ("ipa_analysis".equals(c)) {
                return true;
            }
        }
        return false;
    }

    public Map<String, Object> upload(long iid, Path file) throws ApiException {
        byte[] data;
        try {
            data = Files.readAllBytes(file);
        } catch (IOException e) {
            throw new ApiException(0, "cannot read " + file.getFileName() + ": " + e.getMessage());
        }
        String name = file.getFileName().toString().replaceAll("[^A-Za-z0-9._ -]", "_");
        String boundary = "privara-" + UUID.randomUUID();
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        String head = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\""
                + name + "\"\r\nContent-Type: application/octet-stream\r\n\r\n";
        b.writeBytes(head.getBytes(StandardCharsets.UTF_8));
        b.writeBytes(data);
        b.writeBytes(("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
        byte[] payload = b.toByteArray();
        return Json.obj(json(call(() -> request("POST", Endpoints.path(Endpoints.UPLOAD, iid), 900,
                "multipart/form-data; boundary=" + boundary, payload))));
    }

    /** Run one kit analysis on an uploaded file. Only the kit ops are offered from Burp. */
    public Map<String, Object> scan(long iid, String op, String guestPath) throws ApiException {
        if (!RUN_OPS.contains(op)) {
            throw new ApiException(0, "only " + RUN_OPS + " can be run from here");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("op", op);
        body.put("path", guestPath);
        return Json.obj(json(post(Endpoints.path(Endpoints.SCAN, iid), body, 1900)));
    }

    public List<Map<String, Object>> runs(long iid) throws ApiException {
        List<Map<String, Object>> out = new ArrayList<>();
        Object d = json(get(Endpoints.path(Endpoints.RUNS, iid) + "?limit=100", 60));
        for (Object o : Json.arr(Json.obj(d).get("runs"))) {
            out.add(Json.obj(o));
        }
        return out;
    }

    public byte[] bundle(long iid, long runId) throws ApiException {
        return get(Endpoints.path(Endpoints.BUNDLE, iid, runId), 300);
    }

    public Map<String, Object> report(long iid, long runId) throws ApiException {
        String q = "?run_id=" + runId + "&format=json";
        return Json.obj(json(get(Endpoints.path(Endpoints.REPORT, iid) + q, 300)));
    }

    /** The server's own dry run of one target against the device's engagement scope. */
    public Map<String, Object> scopeCheck(long iid, String host) throws ApiException {
        String q = "?target=" + URLEncoder.encode(host, StandardCharsets.UTF_8);
        return Json.obj(json(get(Endpoints.path(Endpoints.SCOPE_CHECK, iid) + q, 30)));
    }

    public Map<String, Object> forgeStatus(long iid) throws ApiException {
        return Json.obj(json(get(Endpoints.path(Endpoints.FORGE_STATUS, iid), 90)));
    }

    /** POST .../ipa/forge/sign. Returns the server's answer; a refusal is an ApiException. */
    public Map<String, Object> sign(long iid, long harnessId, Map<String, Object> request)
            throws ApiException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("harness_id", harnessId);
        body.put("request", request);
        return Json.obj(json(post(Endpoints.path(Endpoints.FORGE_SIGN, iid), body, 40)));
    }

    // ------------------------------------------------------------------ transport

    private PrivaraConfig conf() throws ApiException {
        PrivaraConfig c;
        try {
            c = cfg.get();
        } catch (IllegalArgumentException e) {
            throw new ApiException(0, e.getMessage());
        }
        if (c == null) {
            throw new ApiException(0, "set the Privara base URL and your API token first");
        }
        if (!c.hasToken()) {
            throw new ApiException(0, "set your Privara API token in the Privara tab first (on a Privara "
                    + "Kali with the link on, this Kali's link is used instead)");
        }
        return c;
    }

    /** One call, ready to send: built fresh for each try (a retry after a 401 gets the new token). */
    private static final class Call {
        final String method;
        final URI uri;
        final List<String[]> headers;
        final byte[] body;
        final int timeoutS;

        Call(String method, URI uri, List<String[]> headers, byte[] body, int timeoutS) {
            this.method = method;
            this.uri = uri;
            this.headers = headers;
            this.body = body;
            this.timeoutS = timeoutS;
        }
    }

    private Call request(String method, String path, int timeoutS, String contentType, byte[] body)
            throws ApiException {
        PrivaraConfig c = conf();
        if (!path.startsWith("/api/")) {
            throw new ApiException(0, "refusing a non-API path");
        }
        List<String[]> h = new ArrayList<>();
        h.add(new String[] {"Authorization", "Bearer " + c.token()});
        h.add(new String[] {"Accept", "application/json"});
        h.add(new String[] {"User-Agent", userAgent});
        if (contentType != null) {
            h.add(new String[] {"Content-Type", contentType});
        }
        return new Call(method, URI.create(c.baseUrl() + path), h, body, timeoutS);
    }

    private byte[] get(String path, int timeoutS) throws ApiException {
        return call(() -> request("GET", path, timeoutS, null, null));
    }

    private byte[] post(String path, Map<String, Object> body, int timeoutS) throws ApiException {
        byte[] json = Json.write(body).getBytes(StandardCharsets.UTF_8);
        return call(() -> request("POST", path, timeoutS, "application/json", json));
    }

    private interface Req {
        Call build() throws ApiException;
    }

    /** Send; on a 401, retry ONCE if a newer token became available (a rotated Kali link). */
    private byte[] call(Req r) throws ApiException {
        try {
            return send(r.build());
        } catch (ApiException e) {
            if (e.status() == 401 && relink.getAsBoolean()) {
                return send(r.build());
            }
            throw e;
        }
    }

    private byte[] send(Call c) throws ApiException {
        String tok = tokenOrEmpty();
        Transport.Response r;
        try {
            r = transport.get().send(c.method, c.uri, c.headers, c.body, c.timeoutS);
        } catch (IOException | RuntimeException e) {
            throw new ApiException(0, Redact.line("cannot reach Privara: " + e, tok, 300));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ApiException(0, "interrupted");
        }
        int st = r.status;
        byte[] body = r.body;
        if (body.length > MAX_BODY) {
            throw new ApiException(st, "answer larger than " + (MAX_BODY >> 20) + " MB");
        }
        if (st >= 300 && st < 400) {
            throw new ApiException(st, "the platform answered with a redirect; it was NOT followed "
                    + "(your token goes to the configured base URL only). Check the base URL.");
        }
        if (st != 200 && st != 201) {
            throw new ApiException(st, Redact.line(detailOf(body), tok, 600));
        }
        return body;
    }

    private String tokenOrEmpty() {
        try {
            PrivaraConfig c = cfg.get();
            return c == null ? "" : c.token();
        } catch (RuntimeException e) {
            return "";
        }
    }

    /** FastAPI's {"detail": "..."} (or a validation list), else the start of the body. */
    static String detailOf(byte[] body) {
        String s = new String(body, StandardCharsets.UTF_8);
        try {
            Object d = Json.obj(Json.parse(s)).get("detail");
            if (d instanceof String) {
                return (String) d;
            }
            if (d != null) {
                return Json.write(d);
            }
        } catch (RuntimeException ignored) {
            // not JSON
        }
        return s.length() > 300 ? s.substring(0, 300) : s;
    }

    private static Object json(byte[] body) throws ApiException {
        try {
            return Json.parse(new String(body, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            throw new ApiException(0, "the platform did not answer with JSON (" + e.getMessage() + ")");
        }
    }
}
