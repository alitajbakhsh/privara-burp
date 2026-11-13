package com.privara.burp.core;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads a REAL platform bundle and findings report with the extension's own parsers and prints
 * what the extension would import, as JSON. No Burp needed:
 *
 * <pre>  java -cp privara-burp.jar com.privara.burp.core.Selfcheck kit.zip findings.json</pre>
 *
 * The platform's contract test runs it on a bundle built by the platform's own bundle builder, so the
 * two sides are checked against each other rather than each against its own fixture.
 */
public final class Selfcheck {
    private Selfcheck() {
    }

    public static void main(String[] args) throws Exception {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("version", Version.VERSION);
        if (args.length > 0) {
            ApiMap m = ApiMap.fromBundle(Files.readAllBytes(Path.of(args[0])));
            List<Object> eps = new ArrayList<>();
            for (ApiMap.Endpoint e : m.endpoints()) {
                Map<String, Object> x = new LinkedHashMap<>();
                x.put("host", e.host);
                x.put("method", e.method);
                x.put("path", e.path);
                x.put("url", e.url());
                x.put("in_scope", e.inScope);
                x.put("raw", e.rawRequest());
                eps.add(x);
            }
            out.put("endpoints", eps);
            out.put("hosts", new ArrayList<Object>(m.hosts()));
            out.put("in_scope_hosts", new ArrayList<Object>(m.inScopeHosts()));
            out.put("scope_file", m.scopeFilePresent());
            out.put("notes", new ArrayList<Object>(m.notes()));
        }
        if (args.length > 1) {
            Findings f = Findings.parse(Json.obj(Json.parse(
                    new String(Files.readAllBytes(Path.of(args[1])), StandardCharsets.UTF_8))));
            List<Object> fl = new ArrayList<>();
            for (Findings.Finding x : f.list()) {
                Map<String, Object> y = new LinkedHashMap<>();
                y.put("id", x.id);
                y.put("severity", x.severity);
                y.put("burp_severity", x.burpSeverity());
                y.put("burp_confidence", x.burpConfidence());
                y.put("detail_starts_static", x.issueDetailHtml(f.app()).contains(Findings.esc(Findings.STATIC_NOTE)));
                fl.add(y);
            }
            out.put("findings", fl);
            out.put("app", f.app());
        }
        System.out.println(Json.write(out));
    }
}
