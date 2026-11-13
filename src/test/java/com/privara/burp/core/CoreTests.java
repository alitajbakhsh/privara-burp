package com.privara.burp.core;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Unit tests for the extension's core, against a LOOPBACK stub of the Privara API (nothing leaves
 * 127.0.0.1). No test framework: a check that fails prints FAIL and the run exits 1.
 *
 * What is proven: https-only config; the token goes only to the base URL, only as a bearer header,
 * never through a redirect and never into a log line (even when the server echoes it); the API map
 * puts in scope ONLY what burp-scope.json lists and drops hostile hosts and paths; request forging
 * asks the sign API only for an enabled, scope-checked host of a verified harness, honours the
 * server's refusals and rate limit, and refuses a bad signer answer; findings map to Burp severity
 * without ever claiming certainty, with escaped HTML.
 */
public final class CoreTests {
    static final String TOKEN = "pvt_test_SECRETtoken_0123456789abcdef";
    static int fails = 0;
    static int passes = 0;

    static void check(String name, boolean ok, Object got) {
        if (ok) {
            passes++;
            System.out.println("  PASS  " + name);
        } else {
            fails++;
            System.out.println("  FAIL  " + name + "   -> " + got);
        }
    }

    static void check(String name, boolean ok) {
        check(name, ok, "");
    }

    // ------------------------------------------------------------------ the stub API

    static final List<String> calls = Collections.synchronizedList(new ArrayList<>());
    static final List<String> signBodies = Collections.synchronizedList(new ArrayList<>());
    static final List<String> authSeen = Collections.synchronizedList(new ArrayList<>());
    static final List<String> evilAuth = Collections.synchronizedList(new ArrayList<>());
    static volatile boolean redirectWhoami = false;
    static volatile boolean rateLimit = false;
    static volatile boolean badHeader = false;
    static volatile boolean unauth = false;
    static volatile String altToken = null;   // a second token the stub accepts (Kali link tests)
    static volatile int evilPort = 0;
    static byte[] bundle;

    static void reply(HttpExchange x, int st, String ctype, byte[] body) throws IOException {
        x.getResponseHeaders().add("Content-Type", ctype);
        x.sendResponseHeaders(st, body.length);
        try (OutputStream o = x.getResponseBody()) {
            o.write(body);
        }
    }

    static void json(HttpExchange x, int st, Object v) throws IOException {
        reply(x, st, "application/json", Json.write(v).getBytes(StandardCharsets.UTF_8));
    }

    static Map<String, Object> m(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            out.put((String) kv[i], kv[i + 1]);
        }
        return out;
    }

    static List<Object> l(Object... v) {
        List<Object> out = new ArrayList<>();
        Collections.addAll(out, v);
        return out;
    }

    static String query(HttpExchange x, String k) {
        String q = x.getRequestURI().getRawQuery();
        if (q == null) {
            return null;
        }
        for (String p : q.split("&")) {
            int e = p.indexOf('=');
            if (e > 0 && p.substring(0, e).equals(k)) {
                return URLDecoder.decode(p.substring(e + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    static void handle(HttpExchange x) throws IOException {
        String path = x.getRequestURI().getPath();
        String auth = x.getRequestHeaders().getFirst("Authorization");
        calls.add(x.getRequestMethod() + " " + path);
        authSeen.add(String.valueOf(auth));
        byte[] in = x.getRequestBody().readAllBytes();
        String alt = altToken;
        if (unauth || (!("Bearer " + TOKEN).equals(auth) && !(alt != null && ("Bearer " + alt).equals(auth)))) {
            json(x, 401, m("detail", "invalid token"));
            return;
        }
        if (path.equals("/api/whoami")) {
            if (redirectWhoami) {
                x.getResponseHeaders().add("Location", "http://127.0.0.1:" + evilPort + "/api/whoami");
                reply(x, 302, "text/plain", new byte[0]);
                return;
            }
            json(x, 200, m("username", "demo"));
        } else if (path.equals("/api/instances")) {
            json(x, 200, l(m("id", 7L, "name", "ios-lab", "status", "running", "family", "ios",
                            "scope", "acme", "capabilities", l("ipa_analysis")),
                    m("id", 8L, "name", "kali-red", "status", "running", "family", "kali",
                            "capabilities", l("shell", "files"))));
        } else if (path.equals("/api/instances/7/ipa/runs/41/bundle")) {
            reply(x, 200, "application/zip", bundle);
        } else if (path.equals("/api/instances/7/ipa/forge")) {
            json(x, 200, forgeStatus(true));
        } else if (path.equals("/api/instances/9/ipa/forge")) {
            // a server that echoes the caller's token in an error (it must not reach a log)
            json(x, 400, m("detail", "bad request from Bearer " + TOKEN + " token=" + TOKEN));
        } else if (path.equals("/api/instances/7/scope")) {
            String t = query(x, "target");
            boolean ok = "api.acme.com".equals(t) || "x.svc.acme.com".equals(t);
            json(x, 200, m("scope", "acme", "target", t, "allowed", ok));
        } else if (path.equals("/api/instances/7/ipa/forge/sign")) {
            String body = new String(in, StandardCharsets.UTF_8);
            signBodies.add(body);
            Map<String, Object> req = Json.obj(Json.obj(Json.parse(body)).get("request"));
            String url = Json.str(req.get("url"));
            if (rateLimit) {
                json(x, 400, m("detail", "signing limit reached (120 per minute, burst 30) -- slow down"));
            } else if (url.contains("x.svc.acme.com")) {
                json(x, 400, m("detail", "x.svc.acme.com is outside this device's engagement scope 'acme'"));
            } else if (badHeader) {
                json(x, 200, m("ok", true, "headers", m("X-Sig", "abc\r\nInjected: 1"), "remove", l()));
            } else {
                json(x, 200, m("ok", true, "harness", "toybank", "harness_id", 3L,
                        "headers", m("X-Sig", "c2lnbmVk", "X-Ts", "1700000000"), "remove", l("X-Old"),
                        "body_b64", Base64.getEncoder().encodeToString("{\"signed\":true}".getBytes(StandardCharsets.UTF_8))));
            }
        } else if (path.equals("/api/instances/7/ipa/report")) {
            check("K7 the report is asked for as JSON for the chosen run",
                    "json".equals(query(x, "format")) && "41".equals(query(x, "run_id")), x.getRequestURI());
            json(x, 200, report());
        } else {
            json(x, 404, m("detail", "Not Found"));
        }
    }

    static Map<String, Object> forgeStatus(boolean verified) {
        return m("ok", true, "selected", 3L, "scope", "acme",
                "limits", m("per_minute", 120L, "burst", 3L),
                "harnesses", l(m("id", 3L, "name", "toybank", "verified", verified, "selected", true,
                                "meta", m("hosts", l("api.acme.com", "*.svc.acme.com", "other.acme.com",
                                        "bad host;rm"))),
                        m("id", 4L, "name", "draft", "verified", false, "selected", false,
                                "meta", m("hosts", l("api.acme.com")))));
    }

    static Map<String, Object> report() {
        return m("schema", "privara.ios.findings/1", "artifact", "AcmeShop.ipa",
                "app", m("name", "AcmeShop", "bundle_id", "com.acme.shop"),
                "findings", l(
                        m("id", "PRV-IOS-0000aaaa", "code", "CC-FIREBASE-RTDB-OPEN-READ", "title", "Open <script>alert(1)</script> DB",
                                "severity", "critical", "confidence", "probe", "masvs", "MASVS-STORAGE", "cwe", "CWE-284",
                                "description", "Readable by <img src=x onerror=alert(1)> anyone & everyone", "remediation", "Lock rules",
                                "evidence", l("GET /.json -> 200 <u>x</u>"), "limits", l("one read-only request")),
                        m("id", "PRV-IOS-0000bbbb", "code", "IOS-NET-NO-PINNING", "title", "No pinning",
                                "severity", "medium", "confidence", "static-absence", "description", "x"),
                        m("id", "PRV-IOS-0000cccc", "code", "IOS-X", "title", "Info", "severity", "info",
                                "confidence", "static-config", "description", "y")),
                "empty_reason", "");
    }

    static byte[] zip(Map<String, String> files) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(b)) {
            for (Map.Entry<String, String> e : files.entrySet()) {
                z.putNextEntry(new ZipEntry("AcmeShop-41/" + e.getKey()));
                z.write(e.getValue().getBytes(StandardCharsets.UTF_8));
                z.closeEntry();
            }
        }
        return b.toByteArray();
    }

    static String openapi() {
        Map<String, Object> users = m("get", m("operationId", "get_v1_users_id", "description", "Found in: main.jsbundle",
                "parameters", l(m("name", "id", "in", "path"), m("name", "expand", "in", "query"),
                        m("name", "bad name\r\n", "in", "query"))));
        Map<String, Object> orders = m("post", m("operationId", "post_v1_orders"),
                "servers", l(m("url", "https://api.acme.com")));
        Map<String, Object> debug = m("get", m("operationId", "get_debug"),
                "servers", l(m("url", "https://staging.acme-internal.net"), m("url", "https://evil.com;touch /tmp/pwn")));
        Map<String, Object> paths = new LinkedHashMap<>();
        paths.put("/v1/users/{id}", users);
        paths.put("/v1/orders", orders);
        paths.put("/debug", debug);
        paths.put("/a b\r\nX-Injected: 1", m("get", m("operationId", "bad")));
        return Json.write(m("openapi", "3.0.3", "info", m("title", "AcmeShop -- backend map (static)"),
                "servers", l(m("url", "https://api.acme.com"), m("url", "https://staging.acme-internal.net")),
                "paths", paths));
    }

    static String burpScope(String... hosts) {
        List<Object> inc = new ArrayList<>();
        for (String h : hosts) {
            inc.add(m("enabled", true, "protocol", "any", "host", "^" + h.replace(".", "\\.").replace("-", "\\-") + "$",
                    "file", "^/.*"));
        }
        return Json.write(m("target", m("scope", m("advanced_mode", true, "include", inc, "exclude", l()))));
    }

    // ------------------------------------------------------------------ tests

    public static void main(String[] args) throws Exception {
        HttpServer srv = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        srv.createContext("/", x -> {
            try {
                handle(x);
            } catch (Exception e) {
                json(x, 500, m("detail", String.valueOf(e)));
            }
        });
        srv.start();
        HttpServer evil = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        evil.createContext("/", x -> {
            evilAuth.add(String.valueOf(x.getRequestHeaders().getFirst("Authorization")));
            json(x, 200, m("username", "evil"));
        });
        evil.start();
        evilPort = evil.getAddress().getPort();
        String base = "http://127.0.0.1:" + srv.getAddress().getPort();
        try {
            Map<String, String> files = new LinkedHashMap<>();
            files.put("openapi.json", openapi());
            files.put("burp-scope.json", burpScope("api.acme.com"));
            files.put("README.txt", "x");
            bundle = zip(files);
            config(base);
            client(base);
            apimap();
            forging(base);
            findings();
            kaliLink(base);
            storeHardening(base);
        } finally {
            srv.stop(0);
            evil.stop(0);
        }
        System.out.println("\n" + passes + " passed, " + fails + " failed");
        System.exit(fails == 0 ? 0 : 1);
    }

    static boolean refused(String url, boolean local) {
        try {
            new PrivaraConfig(url, TOKEN, local);
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }

    static void config(String base) {
        System.out.println("\n=== C · configuration: https only, the token never printed ===");
        check("C1 https base URL accepted and normalised",
                new PrivaraConfig("https://App.Tajapps.com/", TOKEN, false).baseUrl().equals("https://app.tajapps.com"));
        check("C2 http to a real host refused even with the localhost toggle", refused("http://app.tajapps.com", true));
        check("C3 http://127.0.0.1 refused without the toggle", refused(base, false));
        check("C4 http://127.0.0.1 accepted with the toggle", !refused(base, true));
        check("C5 user info, a path, a query and a non-http scheme are refused",
                refused("https://u:p@app.tajapps.com", false) && refused("https://app.tajapps.com/api", false)
                        && refused("https://app.tajapps.com?x=1", false) && refused("ftp://app.tajapps.com", false)
                        && refused("http://localhost.evil.com", true));
        check("C6 the config's text form never contains the token",
                !new PrivaraConfig(base, TOKEN, true).toString().contains(TOKEN));
        check("C7 a token with a line break is refused (header injection)",
                refused2(base, "abc\r\nX-Evil: 1"));
    }

    static boolean refused2(String base, String tok) {
        try {
            new PrivaraConfig(base, tok, true);
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }

    static List<String> logLines = Collections.synchronizedList(new ArrayList<>());
    static SafeLog log = new SafeLog(logLines::add, () -> TOKEN);

    static void client(String base) throws Exception {
        System.out.println("\n=== K · the client: token to the base URL only, never logged ===");
        PrivaraClient c = new PrivaraClient(() -> new PrivaraConfig(base, TOKEN, true));
        calls.clear();
        authSeen.clear();
        check("K1 whoami sends the bearer token and reads the answer",
                "demo".equals(Json.str(c.whoami().get("username"))) && authSeen.get(0).equals("Bearer " + TOKEN), authSeen);
        List<Map<String, Object>> devs = c.devices();
        long n = devs.stream().filter(PrivaraClient::isAnalysisDevice).count();
        check("K2 only devices with the ipa_analysis capability count as iOS Analysis devices", n == 1, devs);
        String msg = "";
        try {
            c.forgeStatus(9);
        } catch (ApiException e) {
            msg = e.getMessage();
            log.warn("forge status failed: " + e.getMessage() + " / " + e.detail());
        }
        check("K3 a server error that echoes the token is scrubbed before it is stored",
                !msg.isEmpty() && !msg.contains(TOKEN) && msg.contains("<token>"), msg);
        redirectWhoami = true;
        evilAuth.clear();
        String red = "";
        try {
            c.whoami();
        } catch (ApiException e) {
            red = e.getMessage();
        }
        redirectWhoami = false;
        check("K4 a redirect is NOT followed: the other server is never contacted with the token",
                red.contains("redirect") && evilAuth.isEmpty(), red + " " + evilAuth);
        int before = calls.size();
        PrivaraClient noTok = new PrivaraClient(() -> new PrivaraConfig(base, "", true));
        boolean refusedNoToken = false;
        try {
            noTok.whoami();
        } catch (ApiException e) {
            refusedNoToken = e.getMessage().contains("token");
        }
        check("K5 with no token set, no request is made at all", refusedNoToken && calls.size() == before);
        boolean scanRefused = false;
        try {
            c.scan(7, "shell; id", "/x");
        } catch (ApiException e) {
            scanRefused = true;
        }
        check("K6 only the kit analyses can be run from Burp (no free-form op)", scanRefused);
 check("K8 the bundle is downloaded byte for byte", java.util.Arrays.equals(c.bundle(7, 41), bundle));
        check("K9 the findings report parses", Findings.parse(c.report(7, 41)).list().size() == 3);
        log.info("client section done for " + new PrivaraConfig(base, TOKEN, true));
    }

    static void apimap() throws Exception {
        System.out.println("\n=== M · API map: in scope is what burp-scope.json says, nothing else ===");
        ApiMap mp = ApiMap.fromBundle(bundle);
        check("M1 endpoints: one per (server, method, path); hostile server and path dropped",
                mp.endpoints().size() == 4, mp.endpoints().size());
        check("M2 in-scope hosts are exactly the burp-scope.json hosts", mp.inScopeHosts().equals(List.of("api.acme.com")),
                mp.inScopeHosts());
        boolean staging = false;
        boolean stagingIn = true;
        for (ApiMap.Endpoint e : mp.endpoints()) {
            if (e.host.equals("staging.acme-internal.net")) {
                staging = true;
                stagingIn = e.inScope;
            }
            check("M3 no endpoint carries a hostile host or path (" + e.host + e.path + ")",
                    Hosts.clean(e.host) != null && !e.path.contains(" ") && !e.path.contains("\n"), e.url());
        }
        check("M4 a first-party host outside the scope is listed but NOT in scope", staging && !stagingIn);
        boolean onlyIn = true;
        for (ApiMap.Endpoint e : mp.inScopeEndpoints()) {
            onlyIn &= e.host.equals("api.acme.com");
        }
        check("M5 the default (in-scope) view holds only in-scope hosts", onlyIn && mp.inScopeEndpoints().size() == 2);
        ApiMap.Endpoint users = null;
        for (ApiMap.Endpoint e : mp.endpoints()) {
            if (e.path.equals("/v1/users/{id}") && e.host.equals("api.acme.com")) {
                users = e;
            }
        }
        String raw = users == null ? "" : users.rawRequest();
        check("M6 the request stub: method, path, empty query params, Host header, CRLF framing",
                raw.startsWith("GET /v1/users/{id}?expand= HTTP/1.1\r\nHost: api.acme.com\r\n") && raw.endsWith("\r\n\r\n")
                        && !raw.contains("bad name"), raw);
        ApiMap none = ApiMap.fromFiles(openapi(), burpScope());
        check("M7 a scope file with no hosts (device has no scope) puts NOTHING in scope",
                none.inScopeHosts().isEmpty() && none.inScopeEndpoints().isEmpty() && !none.notes().isEmpty());
        ApiMap noFile = ApiMap.fromFiles(openapi(), null);
        check("M8 no scope file at all puts nothing in scope", noFile.inScopeHosts().isEmpty());
        check("M9 only an escaped literal host regex is read as a host",
                "api.acme.com".equals(Hosts.fromScopeRegex("^api\\.acme\\.com$"))
                        && Hosts.fromScopeRegex("^.*$") == null && Hosts.fromScopeRegex("^api.acme.com$") == null
                        && Hosts.fromScopeRegex("^(a|b)\\.com$") == null && Hosts.fromScopeRegex("api\\.acme\\.com") == null);
        String disabled = Json.write(m("target", m("scope", m("include", l(m("enabled", false, "host", "^x\\.com$")))))) ;
        check("M10 a disabled include entry is not in scope", ApiMap.scopeHosts(disabled).isEmpty());
        ApiMap post = ApiMap.fromFiles(openapi(), burpScope("api.acme.com"));
        String praw = "";
        for (ApiMap.Endpoint e : post.endpoints()) {
            if (e.method.equals("POST")) {
                praw = e.rawRequest();
            }
        }
        check("M11 a POST stub carries a JSON body with a correct Content-Length",
                praw.contains("Content-Length: 2\r\n\r\n{}"), praw);
    }

    static void forging(String base) throws Exception {
        System.out.println("\n=== F · request forging: only enabled, in-scope harness hosts are ever sent ===");
        AtomicLong clock = new AtomicLong(1_000_000);
        PrivaraClient c = new PrivaraClient(() -> new PrivaraConfig(base, TOKEN, true));
        ForgeGate gate = new ForgeGate(clock::get);
        Forger f = new Forger(c, gate, log);
        f.setDevice(7);
        List<String[]> hdrs = new ArrayList<>();
        hdrs.add(new String[] {"Host", "api.acme.com"});
        hdrs.add(new String[] {"Cookie", "session=SESSIONSECRET42"});
        hdrs.add(new String[] {"X-Old", "stale"});
        byte[] body = "{\"amount\":1}".getBytes(StandardCharsets.UTF_8);
        Forger.Req api = new Forger.Req("POST", "https://api.acme.com/v1/orders?x=1", "api.acme.com", "/v1/orders", hdrs, body);

        signBodies.clear();
        Forger.Outcome o = f.forge(api);
        check("F1 forging OFF: nothing is sent to the sign API", o.kind == Forger.Kind.SKIPPED && signBodies.isEmpty());
        gate.setOn(true);
        o = f.forge(api);
        check("F2 no harness loaded: nothing is sent", o.kind == Forger.Kind.SKIPPED && signBodies.isEmpty(), o.reason);

        gate.loadStatus(c.forgeStatus(7), 0);
        check("F3 the selected VERIFIED harness is loaded; a malformed HOSTS entry is dropped",
                gate.harnessId() == 3 && gate.patterns().equals(List.of("api.acme.com", "*.svc.acme.com", "other.acme.com")),
                gate.patterns());
        o = f.forge(api);
        check("F4 a harness host the tester did not enable: nothing is sent", o.kind == Forger.Kind.SKIPPED
                && signBodies.isEmpty(), o.reason);

        Forger.Req evil = new Forger.Req("GET", "https://evil.example/x", "evil.example", "/x", hdrs, new byte[0]);
        Forger.Req suffix = new Forger.Req("GET", "https://api.acme.com.evil.com/x", "api.acme.com.evil.com", "/x", hdrs, new byte[0]);
        check("F5 a host outside the harness HOSTS cannot even be enabled, and is never sent",
                gate.enable("evil.example", m("scope", "acme", "allowed", true)) != null
                        && gate.enable("api.acme.com.evil.com", m("scope", "acme", "allowed", true)) != null
                        && f.forge(evil).kind == Forger.Kind.SKIPPED && f.forge(suffix).kind == Forger.Kind.SKIPPED
                        && signBodies.isEmpty());
        check("F6 '*.svc.acme.com' covers a subdomain, never the bare domain",
                Hosts.allowed("x.svc.acme.com", gate.patterns()) && !Hosts.allowed("svc.acme.com", gate.patterns()));

        String why = gate.enable("api.acme.com", m("scope", null, "allowed", true, "why", "no scope on this device"));
        check("F7 a device with NO engagement scope: the host is not enabled (the server's dry run allows it, we do not)",
                why != null && !gate.candidate("api.acme.com"), why);
        why = gate.enable("other.acme.com", c.scopeCheck(7, "other.acme.com"));
        check("F8 a harness host outside the scope (server's dry run): not enabled", why != null
                && !gate.candidate("other.acme.com"), why);
        why = gate.enable("api.acme.com", c.scopeCheck(7, "api.acme.com"));
        check("F9 an in-scope harness host is enabled after the server's scope check", why == null
                && gate.candidate("api.acme.com"), why);

        o = f.forge(api);
        Map<String, Object> sent = signBodies.isEmpty() ? Map.of() : Json.obj(Json.parse(signBodies.get(0)));
        Map<String, Object> req = Json.obj(sent.get("request"));
        check("F10 the sign call carries the harness id, method, URL, headers and the body as base64",
                Json.num(sent.get("harness_id"), 0) == 3 && "POST".equals(req.get("method"))
                        && "https://api.acme.com/v1/orders?x=1".equals(req.get("url"))
                        && Json.arr(req.get("headers")).size() == 3
                        && "{\"amount\":1}".equals(new String(Base64.getDecoder().decode(Json.str(req.get("body_b64"))),
                        StandardCharsets.UTF_8)), sent);
        check("F11 the signed headers, removals and body come back to be applied",
                o.kind == Forger.Kind.SIGNED && "c2lnbmVk".equals(o.setHeaders.get("X-Sig"))
                        && o.removeHeaders.equals(List.of("X-Old"))
                        && "{\"signed\":true}".equals(new String(o.body, StandardCharsets.UTF_8)), o.reason);

        // client-side rate limit: burst 3 (from the status), one already used
        signBodies.clear();
        f.forge(api);
        f.forge(api);
        Forger.Outcome over = f.forge(api);
        check("F12 the client-side limit (the server's burst) stops the 4th immediate request before it is sent",
                signBodies.size() == 2 && over.kind == Forger.Kind.SKIPPED, signBodies.size() + " " + over.reason);
        clock.addAndGet(60_000);

        rateLimit = true;
        signBodies.clear();
        Forger.Outcome rl = f.forge(api);
        Forger.Outcome during = f.forge(api);
        rateLimit = false;
        check("F13 the server's rate-limit refusal starts a back-off: the next request is not sent",
                rl.kind == Forger.Kind.FAILED && during.kind == Forger.Kind.SKIPPED && signBodies.size() == 1,
                rl.reason + " / " + during.reason);
        clock.addAndGet(ForgeGate.BACKOFF_MS + 1000);
        signBodies.clear();
        check("F14 after the back-off, signing resumes", f.forge(api).kind == Forger.Kind.SIGNED && signBodies.size() == 1);

        check("F15 enabling the wildcard host after its scope check", gate.enable("x.svc.acme.com",
                c.scopeCheck(7, "x.svc.acme.com")) == null);
        Forger.Req svc = new Forger.Req("GET", "https://x.svc.acme.com/a", "x.svc.acme.com", "/a", hdrs, new byte[0]);
        signBodies.clear();
        Forger.Outcome ref = f.forge(svc);
        Forger.Outcome again = f.forge(svc);
        check("F16 the server refuses the host as out of scope: it is disabled and not tried again",
                ref.kind == Forger.Kind.FAILED && again.kind == Forger.Kind.SKIPPED && signBodies.size() == 1
                        && !gate.candidate("x.svc.acme.com"), ref.reason + " / " + again.reason);

        badHeader = true;
        Forger.Outcome bad = f.forge(api);
        badHeader = false;
        check("F17 a signer answer with a CR/LF in a header is refused; nothing is applied",
                bad.kind == Forger.Kind.FAILED && bad.setHeaders.isEmpty(), bad.reason);

        ForgeGate g2 = new ForgeGate(clock::get);
        g2.setOn(true);
        g2.loadStatus(forgeStatus(false), 0);
        check("F18 an UNVERIFIED harness is never used: no harness, enable refused, decide refuses",
                g2.harnessId() == 0 && g2.enable("api.acme.com", m("scope", "acme", "allowed", true)) != null
                        && !g2.decide("api.acme.com").sign && g2.harnessNote().contains("not verified"));
        g2.loadStatus(forgeStatus(true), 4);
        check("F19 asking for a specific harness that is not verified gives no harness", g2.harnessId() == 0);

        clock.addAndGet(5000);
        unauth = true;
        Forger.Outcome u = f.forge(api);
        unauth = false;
        check("F20 HTTP 401 from the sign API switches forging off", u.kind == Forger.Kind.FAILED && !gate.isOn(), u.reason);
        gate.setOn(true);
        gate.reset("device changed");
        check("F21 choosing another device resets the harness, the hosts and the switch",
                !gate.isOn() && gate.harnessId() == 0 && gate.hostStates().isEmpty());

        boolean leak = false;
        for (String line : logLines) {
            leak |= line.contains(TOKEN) || line.contains("SESSIONSECRET42") || line.contains("c2lnbmVk")
                    || line.contains("x=1");
        }
        check("F22 no log line holds the token, a request header value, a signature or a query string",
                !leak && !logLines.isEmpty(), logLines);
    }

    static String linkJson(String schema, String base, String token, long expiresAt) {
        return "{\"schema\":\"" + schema + "\",\"base\":\"" + base + "\",\"token\":\"" + token
                + "\",\"expires_at\":" + expiresAt + ",\"kali_id\":181,\"kali_name\":\"kali <b>red</b>\",\"note\":\"x\"}";
    }

    static void kaliLink(String base) throws Exception {
        System.out.println("\n=== L · this Kali's Privara link (/etc/privara/kali-link.json) ===");
        long now = 1_800_000_000L;
        String good = "privara_kl_LINKtoken_0123456789abcdef";
        KaliLink.Result r = KaliLink.parse(linkJson(KaliLink.SCHEMA, "https://app.tajapps.com/", good, now + 3600), now);
        check("L1 a valid link file parses: base (canonical), token, a cleaned Kali name; toString omits the token",
                r.ok() && r.link.base.equals("https://app.tajapps.com") && r.link.token.equals(good)
                        && r.link.kaliId == 181 && r.link.kaliName.equals("kali bredb")
                        && !r.link.toString().contains(good),
                r.ok() ? r.link.kaliName : r.problem);
        check("L2 an unknown schema is refused",
                !KaliLink.parse(linkJson("privara.kali-link/2", "https://app.tajapps.com", good, now + 60), now).ok());
        KaliLink.Result http = KaliLink.parse(linkJson(KaliLink.SCHEMA, "http://127.0.0.1:18090", good, now + 60), now);
        check("L3 an http base is refused, even loopback (the link never turns the localhost toggle on)",
                !http.ok() && http.present, http.problem);
        check("L4 a token that is not a Kali link token (an API token's shape) is refused",
                !KaliLink.parse(linkJson(KaliLink.SCHEMA, "https://app.tajapps.com", TOKEN, now + 60), now).ok()
                        && !KaliLink.parse(linkJson(KaliLink.SCHEMA, "https://app.tajapps.com", "privara_kl_a b", now + 60), now).ok());
        KaliLink.Result exp = KaliLink.parse(linkJson(KaliLink.SCHEMA, "https://app.tajapps.com", good, now - 1), now);
        check("L5 an expired link is refused, with the reason", !exp.ok() && exp.problem.contains("expired"), exp.problem);
        check("L5b a base URL with a path or user info is refused",
                !KaliLink.parse(linkJson(KaliLink.SCHEMA, "https://u:p@app.tajapps.com", good, now + 60), now).ok()
                        && !KaliLink.parse(linkJson(KaliLink.SCHEMA, "https://app.tajapps.com/api", good, now + 60), now).ok());
        java.nio.file.Path dir = java.nio.file.Files.createTempDirectory("pv-kl");
        java.nio.file.Path f = dir.resolve("kali-link.json");
        KaliLink.Result none = KaliLink.read(f, now);
        check("L6 no file at all: not present, no problem (not a Privara Kali, or the link is off)",
                !none.ok() && !none.present && none.problem.isEmpty(), none.problem);
        java.nio.file.Files.writeString(f, linkJson(KaliLink.SCHEMA, "https://app.tajapps.com", good, now + 3600));
        boolean root = "root".equals(System.getProperty("user.name"));
        if (!root) {
            java.nio.file.Files.setPosixFilePermissions(f, java.util.Set.of());
            KaliLink.Result denied = KaliLink.read(f, now);
            check("L7 an unreadable (root-only) file says so and does not crash",
                    !denied.ok() && denied.problem.equals(KaliLink.ROOT_ONLY), denied.problem);
            java.nio.file.Files.setPosixFilePermissions(f, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } else {
            check("L7 (skipped as root: a root process can read a 0000 file)", true);
        }
        KaliLink.Result ok = KaliLink.read(f, now);
        check("L8a a typed token ALWAYS wins over the link (with the settings' base URL)",
                KaliLink.choose(base, TOKEN, true, ok).token().equals(TOKEN)
                        && KaliLink.choose(base, TOKEN, true, ok).baseUrl().equals(base));
        check("L8b with no typed token the link is used, with ITS base URL",
                KaliLink.choose(base, "", true, ok).token().equals(good)
                        && KaliLink.choose(base, "  ", true, ok).baseUrl().equals("https://app.tajapps.com"));
        check("L8c no typed token and no usable link: no token (nothing is sent)",
                !KaliLink.choose(base, "", true, exp).hasToken() && !KaliLink.choose(base, "", true, none).hasToken());

        // The 401 path against the loopback stub: the link's base is https in real life, so the
        // client here is built on the loopback base with the link's TOKEN (choose() is proven above).
        long[] clock = {now};
        String stale = "privara_kl_STALEtoken_0123456789abcd";
        String fresh = "privara_kl_FRESHtoken_0123456789abcd";
        java.nio.file.Files.writeString(f, linkJson(KaliLink.SCHEMA, "https://app.tajapps.com", stale, now + 3600));
        KaliLink.Source src = new KaliLink.Source(f, () -> clock[0]);
        check("L9a the source reads the file", src.current().ok() && src.current().link.token.equals(stale));
        java.nio.file.Files.writeString(f, linkJson(KaliLink.SCHEMA, "https://app.tajapps.com", fresh, now + 7200) + " ");
        check("L9b ...and re-reads it when it changes (the platform rotates it daily)",
                src.current().ok() && src.current().link.token.equals(fresh));
        java.nio.file.Files.writeString(f, linkJson(KaliLink.SCHEMA, "https://app.tajapps.com", stale, now + 3600));
        src.current();
        altToken = fresh;
        PrivaraClient lc = new PrivaraClient(() -> new PrivaraConfig(base, src.current().ok() ? src.current().link.token : "", true));
        lc.onUnauthorized(() -> {
            try {
                java.nio.file.Files.writeString(f, linkJson(KaliLink.SCHEMA, "https://app.tajapps.com", fresh, now + 7200) + "  ");
            } catch (IOException e) {
                return false;
            }
            return src.reload();
        });
        authSeen.clear();
        String who = Json.str(lc.whoami().get("username"));
        check("L10 a 401 makes the client re-read the link ONCE and retry with the new token",
                who.equals("demo") && authSeen.size() == 2 && authSeen.get(0).equals("Bearer " + stale)
                        && authSeen.get(1).equals("Bearer " + fresh), authSeen);
        PrivaraClient lc2 = new PrivaraClient(() -> new PrivaraConfig(base, stale, true));
        lc2.onUnauthorized(() -> false);
        authSeen.clear();
        boolean refused = false;
        try {
            lc2.whoami();
        } catch (ApiException e) {
            refused = e.status() == 401;
        }
        check("L11 a 401 with no newer token is NOT retried (exactly one call)", refused && authSeen.size() == 1, authSeen);
        altToken = null;
        clock[0] = now + 100_000;
        check("L12 the cached link is dropped once it expires, without the file changing", !src.current().ok());
        java.nio.file.Files.delete(f);
        java.nio.file.Files.delete(dir);
    }

    /** A transport that records what it was asked to send and answers what the test says. */
    static final class FakeTransport implements Transport {
        final List<String> sent = Collections.synchronizedList(new ArrayList<>());
        volatile int status = 200;
        volatile byte[] body = "{\"username\":\"fake\"}".getBytes(StandardCharsets.UTF_8);
        volatile IOException fail = null;

        @Override
        public Response send(String method, java.net.URI uri, List<String[]> headers, byte[] b, int t)
                throws IOException {
            StringBuilder s = new StringBuilder(method + " " + uri);
            for (String[] h : headers) {
                s.append(" | ").append(h[0]).append(": ").append(h[1]);
            }
            sent.add(s.toString());
            if (fail != null) {
                throw fail;
            }
            return new Response(status, body);
        }

        @Override
        public String name() {
            return "fake";
        }
    }

    /** BApp Store hardening (PortSwigger's acceptance criteria): S1-S6. */
    static void storeHardening(String base) throws Exception {
        System.out.println("\n=== S · BApp Store hardening: plain text, error stream, transports, unload ===");
        String[] samples = {"<html><img src=http://evil.example/x>", "<HTML><b>x", "<html>", "<htm>x", " <html>x",
            "/v1/users/{id}", "", "<html ", "<b>bold</b>"};
        boolean same = true;
        boolean neutral = true;
        for (String x : samples) {
            same &= Plain.isHtml(x) == javax.swing.plaf.basic.BasicHTML.isHTMLString(x);
            neutral &= !javax.swing.plaf.basic.BasicHTML.isHTMLString(Plain.text(x));
        }
        check("S1 text from the app is never rendered as HTML by Swing: Plain.isHtml is Swing's own test, and "
                + "Plain.text output never passes it (plain text is left as it is)",
                same && neutral && Plain.text("/v1/users/{id}").equals("/v1/users/{id}")
                        && Plain.cell(7L).equals(7L), "");

        List<String> out = new ArrayList<>();
        List<String> err = new ArrayList<>();
        SafeLog sl = new SafeLog(out::add, err::add, () -> TOKEN);
        sl.info("hello");
        sl.error("worker failed", new IllegalStateException("boom with " + TOKEN));
        String e0 = err.isEmpty() ? "" : err.get(0);
        check("S2 an unexpected exception goes to the ERROR stream with its stack trace, scrubbed of the token; "
                + "info lines stay on Output", out.size() == 1 && err.size() == 1
                && e0.contains("IllegalStateException") && e0.contains("\tat com.privara.burp.core.CoreTests")
                && !e0.contains(TOKEN) && e0.contains("<token>"), err);

        FakeTransport ft = new FakeTransport();
        PrivaraClient fc = new PrivaraClient(() -> new PrivaraConfig("https://app.tajapps.com", TOKEN, false), () -> ft);
        String who = Json.str(fc.whoami().get("username"));
        check("S3 any transport gets the same call: the base URL's /api path, the bearer token, nothing else",
                who.equals("fake") && ft.sent.size() == 1
                        && ft.sent.get(0).startsWith("GET https://app.tajapps.com/api/whoami | Authorization: Bearer " + TOKEN)
                        && fc.transportName().equals("fake"), ft.sent);
        ft.status = 302;
        String red = "";
        try {
            fc.whoami();
        } catch (ApiException x) {
            red = x.getMessage();
        }
        ft.status = 200;
        ft.fail = new IOException("connect failed for Bearer " + TOKEN);
        String net = "";
        try {
            fc.whoami();
        } catch (ApiException x) {
            net = x.getMessage();
        }
        ft.fail = null;
        check("S4 whatever the transport, a 3xx is refused as a redirect and a network error is scrubbed",
                red.contains("redirect") && net.startsWith("cannot reach Privara") && !net.contains(TOKEN), red + " / " + net);

        JdkTransport jt = new JdkTransport();
        PrivaraClient jc = new PrivaraClient(() -> new PrivaraConfig(base, TOKEN, true), () -> jt);
        boolean worked = "demo".equals(Json.str(jc.whoami().get("username")));
        jt.close();
        jt.close();
        int before = calls.size();
        boolean refusedAfter = false;
        try {
            jc.whoami();
        } catch (ApiException x) {
            refusedAfter = x.getMessage().contains("unloading");
        }
        check("S5 unloading closes the direct HTTP client: its threads are stopped (twice is harmless) and no "
                + "call leaves afterwards", worked && jt.isClosed() && refusedAfter && calls.size() == before,
                "closed=" + jt.isClosed() + " refused=" + refusedAfter);

        FakeTransport st = new FakeTransport();
        PrivaraClient sc = new PrivaraClient(() -> new PrivaraConfig("https://api.acme.com", TOKEN, false), () -> st);
        ForgeGate g = new ForgeGate(System::currentTimeMillis);
        g.loadStatus(m("selected", 3L, "limits", m("per_minute", 120L, "burst", 30L),
                "harnesses", l(m("id", 3L, "name", "toybank", "verified", true, "meta", m("hosts", l("api.acme.com"))))), 0);
        g.enable("api.acme.com", m("scope", "acme", "allowed", true));
        g.setOn(true);
        Forger fg = new Forger(sc, g, sl);
        fg.setDevice(7);
        Forger.Outcome o = fg.forge(new Forger.Req("POST", "https://api.acme.com/v1/x", "api.acme.com", "/v1/x",
                new ArrayList<>(), new byte[0]));
        check("S6 the Privara platform's own host is never signed, even if a harness lists it (the sign call "
                + "through Burp's networking passes the handler too, and would loop)",
                o.kind == Forger.Kind.SKIPPED && st.sent.isEmpty(), o.kind + " " + st.sent);
    }

    static void findings() {
        System.out.println("\n=== R · findings: Burp severity, never 'certain', escaped HTML ===");
        Findings fs = Findings.parse(report());
        List<Findings.Finding> l = fs.list();
        check("R1 parsed", l.size() == 3 && fs.app().equals("AcmeShop"));
        check("R2 severity: critical->HIGH, medium->MEDIUM, info->INFORMATION",
                l.get(0).burpSeverity().equals("HIGH") && l.get(1).burpSeverity().equals("MEDIUM")
                        && l.get(2).burpSeverity().equals("INFORMATION"));
        check("R3 confidence: a probe is FIRM, static is TENTATIVE, nothing is CERTAIN",
                l.get(0).burpConfidence().equals("FIRM") && l.get(1).burpConfidence().equals("TENTATIVE")
                        && l.get(2).burpConfidence().equals("TENTATIVE"));
        String html = l.get(0).issueDetailHtml(fs.app());
        check("R4 the issue detail says 'static analysis, not runtime proof' first",
                html.startsWith("<p><b>" + Findings.esc(Findings.STATIC_NOTE)), html);
        check("R5 text from the report is HTML-escaped", !l.get(0).issueName().isEmpty()
                && !html.contains("<img") && !html.contains("<u>") && html.contains("&lt;img src=x")
                && html.contains("&amp; everyone"), html);
        boolean wrong = false;
        try {
            Findings.parse(m("schema", "something/else", "findings", l()));
        } catch (IllegalArgumentException e) {
            wrong = true;
        }
        check("R6 a document that is not a Privara findings report is refused", wrong);
    }
}
