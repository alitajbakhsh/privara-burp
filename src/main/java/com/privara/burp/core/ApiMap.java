package com.privara.burp.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * The app's backend map, read from the platform's kit bundle
 * ({@code GET /api/instances/{iid}/ipa/runs/{rid}/bundle}):
 *
 * <ul>
 *   <li>{@code openapi.json}: the first-party endpoints (servers, paths, methods, parameters).</li>
 *   <li>{@code burp-scope.json}: the first-party hosts that passed the iOS device's engagement-scope
 *       check ON THE SERVER. This is the only source of {@link #inScopeHosts()}: the client never
 *       decides on its own that a host is in scope. No scope on the device means no host here.</li>
 * </ul>
 *
 * The bundle describes an UNTRUSTED app, so every host, path, method and parameter name is
 * validated before it can reach a request line, a site-map URL or Burp's target scope.
 */
public final class ApiMap {
    public static final Set<String> METHODS = Set.of("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS");
    private static final Pattern PARAM = Pattern.compile("^[A-Za-z0-9_.\\-\\[\\]]{1,64}$");
    private static final Pattern PATH = Pattern.compile("^/[\\x21-\\x7e]{0,2000}$");
    private static final Pattern TEMPLATE = Pattern.compile("\\{([A-Za-z_][A-Za-z0-9_]*)\\}");
    private static final int MAX_ENTRIES = 64;
    private static final long MAX_ENTRY_BYTES = 16L * 1024 * 1024;
    private static final int MAX_ENDPOINTS = 20000;

    /** One request stub for one (host, method, path). */
    public static final class Endpoint {
        public final String scheme;
        public final String host;
        public final String method;
        public final String path;
        public final List<String> query;
        public final String note;
        public final boolean inScope;

        Endpoint(String scheme, String host, String method, String path, List<String> query,
                 String note, boolean inScope) {
            this.scheme = scheme;
            this.host = host;
            this.method = method;
            this.path = path;
            this.query = Collections.unmodifiableList(query);
            this.note = note;
            this.inScope = inScope;
        }

        public boolean secure() {
            return !"http".equals(scheme);
        }

        public int port() {
            return secure() ? 443 : 80;
        }

        public String url() {
            return scheme + "://" + host + target();
        }

        /** The request target: path plus empty query parameters for the tester to fill. */
        public String target() {
            if (query.isEmpty()) {
                return path;
            }
            StringBuilder b = new StringBuilder(path).append('?');
            for (int k = 0; k < query.size(); k++) {
                if (k > 0) {
                    b.append('&');
                }
                b.append(query.get(k)).append('=');
            }
            return b.toString();
        }

        /** A raw HTTP/1.1 request a tester can open in Repeater. Nothing here was seen on the wire. */
        public String rawRequest() {
            StringBuilder b = new StringBuilder();
            b.append(method).append(' ').append(target()).append(" HTTP/1.1\r\n");
            b.append("Host: ").append(host).append("\r\n");
            b.append("Accept: */*\r\n");
            b.append("User-Agent: privara-burp/").append(Version.VERSION).append(" (static map stub)\r\n");
            boolean body = method.equals("POST") || method.equals("PUT") || method.equals("PATCH");
            if (body) {
                b.append("Content-Type: application/json\r\n");
                b.append("Content-Length: 2\r\n\r\n{}");
            } else {
                b.append("\r\n");
            }
            return b.toString();
        }

        public List<String> pathParams() {
            List<String> out = new ArrayList<>();
            Matcher m = TEMPLATE.matcher(path);
            while (m.find()) {
                out.add(m.group(1));
            }
            return out;
        }
    }

    private final List<Endpoint> endpoints;
    private final List<String> hosts;
    private final List<String> inScopeHosts;
    private final boolean scopeFilePresent;
    private final List<String> notes;
    private final String title;

    private ApiMap(List<Endpoint> endpoints, List<String> hosts, List<String> inScopeHosts,
                   boolean scopeFilePresent, List<String> notes, String title) {
        this.endpoints = endpoints;
        this.hosts = hosts;
        this.inScopeHosts = inScopeHosts;
        this.scopeFilePresent = scopeFilePresent;
        this.notes = notes;
        this.title = title;
    }

    public List<Endpoint> endpoints() {
        return endpoints;
    }

    /** Only the endpoints on hosts the server says are in the engagement scope. */
    public List<Endpoint> inScopeEndpoints() {
        List<Endpoint> out = new ArrayList<>();
        for (Endpoint e : endpoints) {
            if (e.inScope) {
                out.add(e);
            }
        }
        return out;
    }

    public List<String> hosts() {
        return hosts;
    }

    public List<String> inScopeHosts() {
        return inScopeHosts;
    }

    public boolean scopeFilePresent() {
        return scopeFilePresent;
    }

    public List<String> notes() {
        return notes;
    }

    public String title() {
        return title;
    }

    // ------------------------------------------------------------------ reading the bundle

    public static Map<String, byte[]> unzip(byte[] zip) throws IOException {
        Map<String, byte[]> out = new LinkedHashMap<>();
        try (ZipInputStream z = new ZipInputStream(new ByteArrayInputStream(zip))) {
            ZipEntry e;
            int n = 0;
            while ((e = z.getNextEntry()) != null) {
                if (++n > MAX_ENTRIES) {
                    throw new IOException("the bundle has too many files");
                }
                if (e.isDirectory()) {
                    continue;
                }
                String name = e.getName();
                String base = name.substring(name.lastIndexOf('/') + 1);
                ByteArrayOutputStream b = new ByteArrayOutputStream();
                byte[] buf = new byte[65536];
                long total = 0;
                int r;
                while ((r = z.read(buf)) > 0) {
                    total += r;
                    if (total > MAX_ENTRY_BYTES) {
                        throw new IOException(base + " in the bundle is too large");
                    }
                    b.write(buf, 0, r);
                }
                out.put(base, b.toByteArray());
            }
        }
        return out;
    }

    public static ApiMap fromBundle(byte[] zip) throws IOException {
        Map<String, byte[]> files = unzip(zip);
        byte[] oa = files.get("openapi.json");
        byte[] sc = files.get("burp-scope.json");
        return fromFiles(oa == null ? null : new String(oa, StandardCharsets.UTF_8),
                sc == null ? null : new String(sc, StandardCharsets.UTF_8));
    }

    /** The in-scope hosts burp-scope.json lists (protocol "any", file "^/.*" only). */
    public static List<String> scopeHosts(String burpScopeJson) {
        Set<String> out = new TreeSet<>();
        if (burpScopeJson == null) {
            return new ArrayList<>(out);
        }
        Map<String, Object> scope = Json.obj(Json.obj(Json.obj(Json.parse(burpScopeJson)).get("target")).get("scope"));
        for (Object o : Json.arr(scope.get("include"))) {
            Map<String, Object> inc = Json.obj(o);
            if (!Json.bool(inc.get("enabled"))) {
                continue;
            }
            String h = Hosts.fromScopeRegex(Json.str(inc.get("host")));
            if (h != null) {
                out.add(h);
            }
        }
        return new ArrayList<>(out);
    }

    public static ApiMap fromFiles(String openapiJson, String burpScopeJson) {
        List<String> notes = new ArrayList<>();
        boolean scopePresent = burpScopeJson != null;
        List<String> inScope = scopeHosts(burpScopeJson);
        Set<String> inScopeSet = new LinkedHashSet<>(inScope);
        if (!scopePresent) {
            notes.add("the bundle has no burp-scope.json (no apimap run?), so no host is treated as in scope");
        } else if (inScope.isEmpty()) {
            notes.add("no host is in scope: the iOS device has no engagement scope, or none of the app's "
                    + "first-party hosts is in it. Assign a scope on the platform (privara scope set) and import again");
        }
        if (openapiJson == null) {
            notes.add("the bundle has no openapi.json: run apimap on the upload first");
            return new ApiMap(List.of(), List.of(), inScope, scopePresent, notes, "");
        }
        Map<String, Object> doc = Json.obj(Json.parse(openapiJson));
        String title = Json.str(Json.obj(doc.get("info")).get("title"));
        List<String[]> topServers = servers(doc.get("servers"));
        Set<String> hosts = new TreeSet<>();
        for (String[] s : topServers) {
            hosts.add(s[1]);
        }
        List<Endpoint> eps = new ArrayList<>();
        int dropped = 0;
        for (Map.Entry<String, Object> pe : Json.obj(doc.get("paths")).entrySet()) {
            String path = pe.getKey();
            if (!PATH.matcher(path).matches()) {
                dropped++;
                continue;
            }
            Map<String, Object> item = Json.obj(pe.getValue());
            List<String[]> srv = item.containsKey("servers") ? servers(item.get("servers")) : topServers;
            for (Map.Entry<String, Object> me : item.entrySet()) {
                String method = me.getKey().toUpperCase(Locale.ROOT);
                if (!METHODS.contains(method)) {
                    continue;                 // "servers", "parameters", vendor keys
                }
                Map<String, Object> op = Json.obj(me.getValue());
                List<String> query = new ArrayList<>();
                for (Object po : Json.arr(op.get("parameters"))) {
                    Map<String, Object> p = Json.obj(po);
                    String name = Json.str(p.get("name"));
                    if ("query".equals(Json.str(p.get("in"))) && PARAM.matcher(name).matches()
                            && !query.contains(name)) {
                        query.add(name);
                    }
                }
                String note = Json.str(op.get("description"));
                for (String[] s : srv) {
                    if (eps.size() >= MAX_ENDPOINTS) {
                        break;
                    }
                    eps.add(new Endpoint(s[0], s[1], method, path, query, note, inScopeSet.contains(s[1])));
                    hosts.add(s[1]);
                }
            }
        }
        if (dropped > 0) {
            notes.add(dropped + " path(s) with unusable characters were left out");
        }
        eps.sort((a, b) -> {
            int c = a.host.compareTo(b.host);
            if (c == 0) {
                c = a.path.compareTo(b.path);
            }
            return c == 0 ? a.method.compareTo(b.method) : c;
        });
        return new ApiMap(Collections.unmodifiableList(eps), new ArrayList<>(hosts), inScope,
                scopePresent, notes, title);
    }

    /** [scheme, host] pairs from an OpenAPI servers list; anything not a plain host is dropped. */
    private static List<String[]> servers(Object list) {
        List<String[]> out = new ArrayList<>();
        for (Object o : Json.arr(list)) {
            String url = Json.str(Json.obj(o).get("url"));
            String scheme;
            String rest;
            if (url.startsWith("https://")) {
                scheme = "https";
                rest = url.substring(8);
            } else if (url.startsWith("http://")) {
                scheme = "http";
                rest = url.substring(7);
            } else {
                continue;
            }
            if (rest.endsWith("/")) {
                rest = rest.substring(0, rest.length() - 1);
            }
            String h = Hosts.clean(rest);
            if (h != null && h.equals(rest.toLowerCase(Locale.ROOT))) {
                out.add(new String[] {scheme, h});
            }
        }
        return out;
    }
}
