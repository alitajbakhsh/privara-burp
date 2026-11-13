package com.privara.burp.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.LongSupplier;

/**
 * Decides, per outgoing request, whether the request-forging signer may be ASKED to sign it.
 *
 * The platform is the check (verified harness, engagement scope, rate limit, audit). This gate is
 * the client's half of the same rules, so the extension does not even try what the server would
 * refuse, and never sends an out-of-scope request's method, URL and headers to the sign API:
 *
 * <ol>
 *   <li>forging is switched on (off by default);</li>
 *   <li>a VERIFIED harness is loaded from {@code GET .../ipa/forge};</li>
 *   <li>the host matches the harness's {@code HOSTS} (exact, or {@code *.x} for subdomains);</li>
 *   <li>the tester enabled THIS host, and enabling it passed the server's own scope dry run
 *       ({@code GET .../scope?target=}) with a scope present: a device with no scope cannot
 *       sign, so nothing is enabled;</li>
 *   <li>the server has not refused the host since (out of scope, not a harness host);</li>
 *   <li>the client-side rate limit (the server's own numbers) and any back-off allow it.</li>
 * </ol>
 */
public final class ForgeGate {
    public static final long BACKOFF_MS = 60_000;

    /** What the gate says about one request. */
    public static final class Decision {
        public final boolean sign;
        public final String reason;

        Decision(boolean sign, String reason) {
            this.sign = sign;
            this.reason = reason;
        }
    }

    /** One host the tester may enable. */
    public static final class HostState {
        public final String host;
        public boolean enabled;
        public String scope = "";
        public String note = "";

        HostState(String host) {
            this.host = host;
        }
    }

    private final LongSupplier clockMs;
    private volatile boolean on;
    private long harnessId;
    private String harnessName = "";
    private List<String> patterns = List.of();
    private String harnessNote = "load the forge status first";
    private final Map<String, HostState> hosts = new TreeMap<>();
    private long backoffUntil;
    private double tokens;
    private double capacity = 30;
    private double perMs = 120.0 / 60_000.0;
    private long lastRefill;

    public ForgeGate(LongSupplier clockMs) {
        this.clockMs = clockMs;
        this.lastRefill = clockMs.getAsLong();
        this.tokens = capacity;
    }

    // ------------------------------------------------------------------ configuration

    public synchronized void setOn(boolean v) {
        on = v;
    }

    public boolean isOn() {
        return on;
    }

    public synchronized long harnessId() {
        return harnessId;
    }

    public synchronized String harnessName() {
        return harnessName;
    }

    public synchronized List<String> patterns() {
        return patterns;
    }

    public synchronized String harnessNote() {
        return harnessNote;
    }

    /**
     * Load {@code GET .../ipa/forge}. Picks {@code wantId} if given, else the device's selected
     * harness; only a VERIFIED one is usable. Host enablement is kept only for hosts the new
     * harness still lists.
     */
    public synchronized void loadStatus(Map<String, Object> status, long wantId) {
        Map<String, Object> pick = null;
        long sel = Json.num(status.get("selected"), 0);
        for (Object o : Json.arr(status.get("harnesses"))) {
            Map<String, Object> h = Json.obj(o);
            long id = Json.num(h.get("id"), 0);
            if ((wantId > 0 && id == wantId) || (wantId <= 0 && id == sel)) {
                pick = h;
            }
        }
        Map<String, Object> lim = Json.obj(status.get("limits"));
        long pm = Json.num(lim.get("per_minute"), 120);
        long burst = Json.num(lim.get("burst"), 30);
        capacity = Math.max(1, burst);
        perMs = Math.max(1, pm) / 60_000.0;
        tokens = Math.min(tokens, capacity);
        if (pick == null) {
            clearHarness(wantId > 0 ? "harness " + wantId + " is not on this device"
                    : "no harness is selected on this device (privara ipa forge use)");
            return;
        }
        if (!Json.bool(pick.get("verified"))) {
            clearHarness("harness " + Json.str(pick.get("name")) + " is not verified: only a verified "
                    + "harness signs (privara ipa forge verify)");
            return;
        }
        harnessId = Json.num(pick.get("id"), 0);
        harnessName = Json.str(pick.get("name"));
        List<String> pats = new ArrayList<>();
        for (Object p : Json.arr(Json.obj(pick.get("meta")).get("hosts"))) {
            String s = Json.str(p).trim().toLowerCase(java.util.Locale.ROOT);
            String core = s.startsWith("*.") ? s.substring(2) : s;
            if (Hosts.clean(core) != null && Hosts.clean(core).equals(core)) {
                pats.add(s);
            }
        }
        patterns = Collections.unmodifiableList(pats);
        harnessNote = "harness " + harnessName + " #" + harnessId + " (verified)";
        hosts.entrySet().removeIf(e -> !Hosts.allowed(e.getKey(), patterns));
        for (String p : patterns) {
            if (!p.startsWith("*.")) {
                hosts.computeIfAbsent(p, HostState::new);
            }
        }
    }

    /** A different device was chosen: forget the harness and every enabled host, switch off. */
    public synchronized void reset(String why) {
        on = false;
        clearHarness(why);
    }

    private void clearHarness(String why) {
        harnessId = 0;
        harnessName = "";
        patterns = List.of();
        harnessNote = why;
        hosts.clear();
    }

    /** The hosts listed for the tester (exact harness hosts plus any they added under a wildcard). */
    public synchronized List<HostState> hostStates() {
        return new ArrayList<>(hosts.values());
    }

    /**
     * Enable signing for one concrete host. {@code scopeCheck} is the server's answer to
     * {@code GET .../scope?target=<host>}. Returns null when enabled, else why not.
     */
    public synchronized String enable(String host, Map<String, Object> scopeCheck) {
        String h = Hosts.clean(host);
        if (h == null || !h.equals(host == null ? "" : host.trim().toLowerCase(java.util.Locale.ROOT))) {
            return "not a plain host name";
        }
        if (harnessId == 0) {
            return harnessNote;
        }
        if (!Hosts.allowed(h, patterns)) {
            return h + " is not one of the harness's HOSTS " + patterns;
        }
        HostState st = hosts.computeIfAbsent(h, HostState::new);
        Object scope = scopeCheck == null ? null : scopeCheck.get("scope");
        if (scope == null || Json.str(scope).isEmpty()) {
            st.enabled = false;
            st.note = "no engagement scope on the iOS device: signing is refused without one";
            return st.note;
        }
        if (!Json.bool(scopeCheck.get("allowed"))) {
            st.enabled = false;
            st.scope = Json.str(scope);
            st.note = "outside the engagement scope '" + st.scope + "'";
            return st.note;
        }
        st.enabled = true;
        st.scope = Json.str(scope);
        st.note = "in scope '" + st.scope + "'";
        return null;
    }

    public synchronized void disable(String host, String why) {
        HostState st = hosts.get(Hosts.clean(host));
        if (st != null) {
            st.enabled = false;
            st.note = why == null ? "disabled" : why;
        }
    }

    // ------------------------------------------------------------------ per request

    /**
     * A cheap pre-check the HTTP handler runs before it even copies a request: on, and an ENABLED
     * harness host. Consumes no rate-limit token; {@link #decide} is still the decision.
     */
    public synchronized boolean candidate(String host) {
        if (!on || harnessId == 0) {
            return false;
        }
        String h = Hosts.clean(host);
        HostState st = h == null ? null : hosts.get(h);
        return st != null && st.enabled && Hosts.allowed(h, patterns);
    }

    public synchronized Decision decide(String host) {
        if (!on) {
            return new Decision(false, "forging is off");
        }
        String h = Hosts.clean(host);
        if (h == null) {
            return new Decision(false, "not a plain host");
        }
        if (harnessId == 0) {
            return new Decision(false, harnessNote);
        }
        if (!Hosts.allowed(h, patterns)) {
            return new Decision(false, "not a harness host");
        }
        HostState st = hosts.get(h);
        if (st == null || !st.enabled) {
            return new Decision(false, "host not enabled for forging");
        }
        long now = clockMs.getAsLong();
        if (now < backoffUntil) {
            return new Decision(false, "the platform's signing limit was reached; backing off");
        }
        tokens = Math.min(capacity, tokens + (now - lastRefill) * perMs);
        lastRefill = now;
        if (tokens < 1) {
            return new Decision(false, "client-side rate limit (the platform's own numbers)");
        }
        tokens -= 1;
        return new Decision(true, "sign");
    }

    /** React to a refusal from the sign API so the same request is not tried again in vain. */
    public synchronized String onRefusal(String host, ApiException e) {
        String d = e.detail().toLowerCase(java.util.Locale.ROOT);
        if (e.status() == 401) {
            on = false;
            return "the token was refused (HTTP 401): forging switched off";
        }
        if (e.status() == 403) {
            on = false;
            return "iOS Analysis is not enabled for this account (HTTP 403): forging switched off";
        }
        if (d.contains("not verified")) {
            clearHarness("the platform says the harness is not verified any more: reload and verify");
            return harnessNote;
        }
        if (d.contains("switched off on this platform")) {
            on = false;
            return "request signing is switched off on the platform: forging switched off";
        }
        if (d.contains("signing limit reached")) {
            backoffUntil = clockMs.getAsLong() + BACKOFF_MS;
            return "the platform's signing limit was reached: backing off for 60 s";
        }
        if (d.contains("no engagement scope") || d.contains("outside this device's engagement scope")
                || d.contains("not one of this harness's hosts")) {
            disable(host, "refused by the platform: " + Redact.line(e.detail(), "", 160));
            return "refused for " + host + ": host disabled";
        }
        return "sign refused: " + Redact.line(e.detail(), "", 200);
    }
}
