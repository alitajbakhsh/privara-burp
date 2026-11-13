package com.privara.burp.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The findings report ({@code GET .../ipa/report?format=json}, schema privara.ios.findings/1) as
 * rows for the Findings tab, and as Burp audit issues for Burp Professional.
 *
 * Every finding is STATIC analysis of the app bundle. Raised as a Burp issue it says so in its
 * first line, and its confidence is never "certain": the report itself states that nothing in it
 * is runtime proof. Text from the report (which quotes an untrusted app) is HTML-escaped before it
 * becomes issue HTML.
 */
public final class Findings {
    public static final String SCHEMA = "privara.ios.findings/1";
    public static final String STATIC_NOTE = "Static analysis of the iOS app bundle by Privara, not runtime "
            + "proof: confirm it against the live backend before reporting it.";

    public static final class Finding {
        public final String id;
        public final String code;
        public final String title;
        public final String severity;
        public final String confidence;
        public final String masvs;
        public final String cwe;
        public final String description;
        public final String remediation;
        public final List<String> evidence;
        public final List<String> limits;

        Finding(Map<String, Object> m) {
            id = Json.str(m.get("id"));
            code = Json.str(m.get("code"));
            title = Json.str(m.get("title"));
            severity = Json.str(m.get("severity")).toLowerCase(Locale.ROOT);
            confidence = Json.str(m.get("confidence"));
            masvs = Json.str(m.get("masvs"));
            cwe = Json.str(m.get("cwe"));
            description = Json.str(m.get("description"));
            remediation = Json.str(m.get("remediation"));
            evidence = strings(m.get("evidence"));
            limits = strings(m.get("limits"));
        }

        /** Burp's AuditIssueSeverity name. */
        public String burpSeverity() {
            switch (severity) {
                case "critical":
                case "high":
                    return "HIGH";
                case "medium":
                    return "MEDIUM";
                case "low":
                    return "LOW";
                default:
                    return "INFORMATION";
            }
        }

        /** Burp's AuditIssueConfidence name. Static findings are never CERTAIN. */
        public String burpConfidence() {
            return "probe".equals(confidence) ? "FIRM" : "TENTATIVE";
        }

        public String issueName() {
            return "[Privara iOS static] " + title;
        }

        /** Issue detail HTML: the static note first, then the escaped report text. */
        public String issueDetailHtml(String app) {
            StringBuilder b = new StringBuilder();
            b.append("<p><b>").append(esc(STATIC_NOTE)).append("</b></p>");
            b.append("<p>").append(esc(description)).append("</p>");
            b.append("<p>Finding ").append(esc(id)).append(" &middot; code ").append(esc(code));
            if (!masvs.isEmpty()) {
                b.append(" &middot; ").append(esc(masvs));
            }
            if (!cwe.isEmpty()) {
                b.append(" &middot; ").append(esc(cwe));
            }
            b.append(" &middot; confidence ").append(esc(confidence));
            if (app != null && !app.isEmpty()) {
                b.append(" &middot; app ").append(esc(app));
            }
            b.append("</p>");
            if (!evidence.isEmpty()) {
                b.append("<p>Evidence:</p><ul>");
                for (String e : evidence) {
                    b.append("<li>").append(esc(e)).append("</li>");
                }
                b.append("</ul>");
            }
            if (!limits.isEmpty()) {
                b.append("<p>Limits:</p><ul>");
                for (String e : limits) {
                    b.append("<li>").append(esc(e)).append("</li>");
                }
                b.append("</ul>");
            }
            return b.toString();
        }

        public String remediationHtml() {
            return remediation.isEmpty() ? "" : "<p>" + esc(remediation) + "</p>";
        }
    }

    private final List<Finding> findings;
    private final String app;
    private final String artifact;
    private final String emptyReason;

    private Findings(List<Finding> f, String app, String artifact, String emptyReason) {
        this.findings = f;
        this.app = app;
        this.artifact = artifact;
        this.emptyReason = emptyReason;
    }

    public static Findings parse(Map<String, Object> model) {
        String schema = Json.str(model.get("schema"));
        if (!SCHEMA.equals(schema)) {
            throw new IllegalArgumentException("not a Privara findings report (schema '" + schema + "')");
        }
        List<Finding> out = new ArrayList<>();
        for (Object o : Json.arr(model.get("findings"))) {
            out.add(new Finding(Json.obj(o)));
        }
        Map<String, Object> app = Json.obj(model.get("app"));
        String name = Json.str(app.get("name"));
        if (name.isEmpty()) {
            name = Json.str(app.get("bundle_id"));
        }
        return new Findings(out, name, Json.str(model.get("artifact")), Json.str(model.get("empty_reason")));
    }

    public List<Finding> list() {
        return findings;
    }

    public String app() {
        return app;
    }

    public String artifact() {
        return artifact;
    }

    public String emptyReason() {
        return emptyReason;
    }

    private static List<String> strings(Object o) {
        List<String> out = new ArrayList<>();
        for (Object x : Json.arr(o)) {
            out.add(Json.str(x));
        }
        return out;
    }

    public static String esc(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            switch (c) {
                case '<': b.append("&lt;"); break;
                case '>': b.append("&gt;"); break;
                case '&': b.append("&amp;"); break;
                case '"': b.append("&quot;"); break;
                case '\'': b.append("&#39;"); break;
                default: b.append(c);
            }
        }
        return b.toString();
    }
}
