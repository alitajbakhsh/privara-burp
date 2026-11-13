package com.privara.burp.core;

/**
 * EVERY Privara API call this extension makes, in one place, in one parseable shape:
 *
 * <pre>  "METHOD /api/path/{iid}/... [?query,params] [{body,keys}] [&lt;multipart-field&gt;]"</pre>
 *
 * The platform's contract test reads these strings out of this file and checks each one
 * against the FastAPI route table (method, path, and that the route reads the query parameters and
 * body keys named here). So a renamed route or parameter fails the platform's QA, not a customer's
 * Burp. Nothing else in the extension may spell an API path.
 */
public final class Endpoints {
    public static final String WHOAMI = "GET /api/whoami";
    public static final String DEVICES = "GET /api/instances";
    public static final String UPLOAD = "POST /api/instances/{iid}/ipa/upload <file>";
    public static final String SCAN = "POST /api/instances/{iid}/ipa/scan {op,path}";
    public static final String RUNS = "GET /api/instances/{iid}/ipa/runs ?limit";
    public static final String BUNDLE = "GET /api/instances/{iid}/ipa/runs/{rid}/bundle";
    public static final String REPORT = "GET /api/instances/{iid}/ipa/report ?run_id,upload,format";
    public static final String SCOPE_CHECK = "GET /api/instances/{iid}/scope ?target";
    public static final String FORGE_STATUS = "GET /api/instances/{iid}/ipa/forge";
    public static final String FORGE_SIGN = "POST /api/instances/{iid}/ipa/forge/sign {harness_id,request}";

    public static final String[] ALL = {WHOAMI, DEVICES, UPLOAD, SCAN, RUNS, BUNDLE, REPORT,
        SCOPE_CHECK, FORGE_STATUS, FORGE_SIGN};

    private Endpoints() {
    }

    public static String method(String ep) {
        return ep.substring(0, ep.indexOf(' '));
    }

    /** The path with {iid} / {rid} filled in. Only integers go in, so nothing can be injected. */
    public static String path(String ep, long iid, long rid) {
        String rest = ep.substring(ep.indexOf(' ') + 1);
        int sp = rest.indexOf(' ');
        String p = sp < 0 ? rest : rest.substring(0, sp);
        return p.replace("{iid}", Long.toString(iid)).replace("{rid}", Long.toString(rid));
    }

    public static String path(String ep, long iid) {
        return path(ep, iid, 0);
    }
}
