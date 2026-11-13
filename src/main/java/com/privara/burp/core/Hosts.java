package com.privara.burp.core;

import java.util.Collection;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Host rules, kept identical to the platform's so the client and the server cannot disagree.
 *
 * <ul>
 *   <li>{@link #clean} is {@code ios_kit_kali._clean_host}: a plain hostname or IPv4 literal, lower
 *       case, no port. Hosts come from an analysis of an UNTRUSTED app, so anything else is dropped
 *       before it reaches Burp's scope, a site-map URL or a request line.</li>
 *   <li>{@link #allowed} is {@code ios_kit_forge.host_allowed}: an exact host, or {@code *.x} for a
 *       subdomain of x (never x itself), so {@code api.bank.example.evil.com} is not
 *       {@code api.bank.example}.</li>
 * </ul>
 */
public final class Hosts {
    private static final Pattern HOST_RE = Pattern.compile(
            "^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\\.[A-Za-z0-9-]{1,63})*$");

    private Hosts() {
    }

    /** A usable host, or null. */
    public static String clean(String h) {
        if (h == null) {
            return null;
        }
        String x = h.trim().toLowerCase(Locale.ROOT);
        while (x.endsWith(".")) {
            x = x.substring(0, x.length() - 1);
        }
        int colon = x.indexOf(':');
        if (colon >= 0 && colon == x.lastIndexOf(':')) {
            x = x.substring(0, colon);
        }
        if (x.isEmpty() || x.contains("..") || !HOST_RE.matcher(x).matches()) {
            return null;
        }
        return x;
    }

    /** Exact, or "*.x" for any subdomain of x (not x itself). */
    public static boolean allowed(String host, Collection<String> patterns) {
        String h = host == null ? "" : host.toLowerCase(Locale.ROOT);
        while (h.endsWith(".")) {
            h = h.substring(0, h.length() - 1);
        }
        if (h.isEmpty() || patterns == null) {
            return false;
        }
        for (String p0 : patterns) {
            if (p0 == null) {
                continue;
            }
            String p = p0.toLowerCase(Locale.ROOT);
            if (p.startsWith("*.")) {
                if (h.endsWith(p.substring(1)) && !h.equals(p.substring(2))) {
                    return true;
                }
            } else if (h.equals(p)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The host inside one burp-scope.json include regex. The platform writes
     * {@code "^" + re.escape(host) + "$"}; anything that is not exactly that shape is ignored rather
     * than guessed at, because a regex we did not write is not a host we were told is in scope.
     */
    public static String fromScopeRegex(String rx) {
        if (rx == null || !rx.startsWith("^") || !rx.endsWith("$") || rx.length() < 3) {
            return null;
        }
        String body = rx.substring(1, rx.length() - 1);
        StringBuilder b = new StringBuilder();
        for (int k = 0; k < body.length(); k++) {
            char c = body.charAt(k);
            if (c == '\\') {
                if (k + 1 >= body.length()) {
                    return null;
                }
                char n = body.charAt(++k);
                if (n != '.' && n != '-') {
                    return null;
                }
                b.append(n);
            } else if (c == '.' || c == '*' || c == '+' || c == '?' || c == '(' || c == ')'
                    || c == '[' || c == ']' || c == '|' || c == '{' || c == '}' || c == '^'
                    || c == '$') {
                return null;            // an unescaped metacharacter: not a literal host
            } else {
                b.append(c);
            }
        }
        String h = clean(b.toString());
        return (h != null && h.equals(b.toString().toLowerCase(Locale.ROOT))) ? h : null;
    }
}
