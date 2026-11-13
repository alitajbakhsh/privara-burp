package com.privara.burp.core;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

/**
 * Signs one outgoing request through {@code POST .../ipa/forge/sign}, if {@link ForgeGate} allows
 * it, and says what to change. Burp-free, so the tests drive it with plain values; the Montoya
 * HTTP handler only converts a Burp request in and applies the {@link Outcome} out.
 */
public final class Forger {
    private static final Pattern HEADER_NAME = Pattern.compile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$");

    /** The request as the sign API wants it. */
    public static final class Req {
        public final String method;
        public final String url;
        public final String host;
        public final String path;
        public final List<String[]> headers;
        public final byte[] body;

        public Req(String method, String url, String host, String path, List<String[]> headers, byte[] body) {
            this.method = method;
            this.url = url;
            this.host = host;
            this.path = path;
            this.headers = headers;
            this.body = body == null ? new byte[0] : body;
        }
    }

    public enum Kind { SIGNED, SKIPPED, FAILED }

    /** What to do with the request. For SKIPPED and FAILED nothing changes. */
    public static final class Outcome {
        public final Kind kind;
        public final String reason;
        public final Map<String, String> setHeaders;
        public final List<String> removeHeaders;
        public final byte[] body;

        Outcome(Kind kind, String reason, Map<String, String> set, List<String> remove, byte[] body) {
            this.kind = kind;
            this.reason = reason;
            this.setHeaders = set;
            this.removeHeaders = remove;
            this.body = body;
        }

        static Outcome skip(String why) {
            return new Outcome(Kind.SKIPPED, why, Map.of(), List.of(), null);
        }

        static Outcome fail(String why) {
            return new Outcome(Kind.FAILED, why, Map.of(), List.of(), null);
        }
    }

    /** One line of the status table. Path only, never a query string or a header value. */
    public static final class Event {
        public final long at;
        public final String method;
        public final String host;
        public final String path;
        public final Kind kind;
        public final String reason;

        Event(long at, String method, String host, String path, Kind kind, String reason) {
            this.at = at;
            this.method = method;
            this.host = host;
            this.path = path;
            this.kind = kind;
            this.reason = reason;
        }
    }

    private final PrivaraClient client;
    private final ForgeGate gate;
    private final SafeLog log;
    private volatile long deviceId;
    public final AtomicLong signed = new AtomicLong();
    public final AtomicLong failed = new AtomicLong();
    public final AtomicLong skipped = new AtomicLong();
    private final Deque<Event> events = new ArrayDeque<>();
    private volatile String lastError = "";

    public Forger(PrivaraClient client, ForgeGate gate, SafeLog log) {
        this.client = client;
        this.gate = gate;
        this.log = log;
    }

    public void setDevice(long iid) {
        deviceId = iid;
    }

    public long device() {
        return deviceId;
    }

    public ForgeGate gate() {
        return gate;
    }

    public SafeLog log() {
        return log;
    }

    public String lastError() {
        return lastError;
    }

    public synchronized List<Event> events() {
        return new ArrayList<>(events);
    }

    public Outcome forge(Req r) {
        ForgeGate.Decision d = gate.decide(r.host);
        if (!d.sign) {
            skipped.incrementAndGet();
            // Not recorded per request: most traffic is simply not a forging host, and a status
            // table full of "not a harness host" would hide the requests that matter.
            return Outcome.skip(d.reason);
        }
        // The platform's own host is never signed: with "through Burp's networking" on, the sign
        // call itself passes through this handler, and signing it would loop.
        String platform = client.baseHost();
        if (!platform.isEmpty() && platform.equalsIgnoreCase(r.host)) {
            skipped.incrementAndGet();
            return Outcome.skip("the Privara platform's own host is never signed");
        }
        long iid = deviceId;
        if (iid <= 0) {
            skipped.incrementAndGet();
            return Outcome.skip("no iOS Analysis device chosen");
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("method", r.method);
        payload.put("url", r.url);
        List<Object> hl = new ArrayList<>();
        for (String[] kv : r.headers) {
            List<Object> p = new ArrayList<>();
            p.add(kv[0]);
            p.add(kv[1]);
            hl.add(p);
        }
        payload.put("headers", hl);
        payload.put("body_b64", Base64.getEncoder().encodeToString(r.body));
        Map<String, Object> res;
        try {
            res = client.sign(iid, gate.harnessId(), payload);
        } catch (ApiException e) {
            String why = gate.onRefusal(r.host, e);
            return failed(r, why);
        }
        if (!Json.bool(res.get("ok"))) {
            return failed(r, "the signer failed: " + Json.str(res.get("error")));
        }
        Map<String, String> set = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : Json.obj(res.get("headers")).entrySet()) {
            String v = Json.str(e.getValue());
            if (!HEADER_NAME.matcher(e.getKey()).matches() || v.indexOf('\r') >= 0 || v.indexOf('\n') >= 0) {
                return failed(r, "the signer returned an unusable header; request left unsigned");
            }
            set.put(e.getKey(), v);
        }
        List<String> remove = new ArrayList<>();
        for (Object o : Json.arr(res.get("remove"))) {
            String n = Json.str(o);
            if (HEADER_NAME.matcher(n).matches()) {
                remove.add(n);
            }
        }
        byte[] body = null;
        if (res.get("body_b64") != null) {
            try {
                body = Base64.getDecoder().decode(Json.str(res.get("body_b64")));
            } catch (IllegalArgumentException e) {
                return failed(r, "the signer returned a body that is not base64; request left unsigned");
            }
        }
        signed.incrementAndGet();
        record(r, Kind.SIGNED, "signed by " + Json.str(res.get("harness")) + " (" + set.size() + " header(s))");
        log.info("signed " + r.method + " " + r.host + r.path);
        return new Outcome(Kind.SIGNED, "signed", set, remove, body);
    }

    private Outcome failed(Req r, String why) {
        failed.incrementAndGet();
        lastError = why;
        record(r, Kind.FAILED, why);
        log.warn("not signed: " + r.method + " " + r.host + r.path + " :: " + why);
        return Outcome.fail(why);
    }

    private synchronized void record(Req r, Kind k, String why) {
        events.addFirst(new Event(System.currentTimeMillis(), r.method, r.host, r.path, k, why));
        while (events.size() > 200) {
            events.removeLast();
        }
    }
}
