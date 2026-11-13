package com.privara.burp.core;

import java.net.URI;
import java.util.Locale;

/**
 * Where the extension talks to, and with what. The token is the customer's OWN Privara API token,
 * typed into the settings tab. It is sent only to {@link #baseUrl()}, only in the Authorization
 * header, and {@link #toString()} never includes it.
 *
 * HTTPS only. Plain http is accepted for a loopback address ONLY, and only when the explicit
 * "localhost development" toggle is on, so a typo cannot send the token over the network in clear.
 */
public final class PrivaraConfig {
    public static final String DEFAULT_BASE = "https://app.tajapps.com";

    private final String baseUrl;
    private final String token;
    private final boolean allowLocalhostHttp;

    public PrivaraConfig(String baseUrl, String token, boolean allowLocalhostHttp) {
        this.allowLocalhostHttp = allowLocalhostHttp;
        this.baseUrl = normalise(baseUrl, allowLocalhostHttp);
        this.token = token == null ? "" : token.trim();
        if (this.token.indexOf('\r') >= 0 || this.token.indexOf('\n') >= 0 || this.token.indexOf(' ') >= 0) {
            throw new IllegalArgumentException("the token contains spaces or line breaks -- paste it again");
        }
    }

    /** The base URL in canonical form (scheme://host[:port], no trailing slash), or an error. */
    public static String normalise(String raw, boolean allowLocalhostHttp) {
        String s = raw == null ? "" : raw.trim();
        while (s.endsWith("/")) {
            s = s.substring(0, s.length() - 1);
        }
        if (s.isEmpty()) {
            throw new IllegalArgumentException("set the Privara base URL (for example " + DEFAULT_BASE + ")");
        }
        URI u;
        try {
            u = new URI(s);
        } catch (Exception e) {
            throw new IllegalArgumentException("the base URL is not a URL");
        }
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
        String host = u.getHost() == null ? "" : u.getHost().toLowerCase(Locale.ROOT);
        if (host.isEmpty()) {
            throw new IllegalArgumentException("the base URL has no host");
        }
        if (u.getRawUserInfo() != null) {
            throw new IllegalArgumentException("the base URL must not carry a user name or password");
        }
        if (u.getRawQuery() != null || u.getRawFragment() != null) {
            throw new IllegalArgumentException("the base URL must not have a query or fragment");
        }
        String path = u.getRawPath() == null ? "" : u.getRawPath();
        if (!path.isEmpty() && !path.equals("/")) {
            throw new IllegalArgumentException("the base URL is just the site, e.g. " + DEFAULT_BASE
                    + " -- no path");
        }
        if (scheme.equals("http")) {
            if (!isLoopback(host)) {
                throw new IllegalArgumentException("https only: plain http would send your token in clear "
                        + "(http is allowed for localhost development only)");
            }
            if (!allowLocalhostHttp) {
                throw new IllegalArgumentException("http://" + host + " needs the 'localhost development' "
                        + "toggle; real platforms are https");
            }
        } else if (!scheme.equals("https")) {
            throw new IllegalArgumentException("the base URL must start with https://");
        }
        String h = host.contains(":") && !host.startsWith("[") ? "[" + host + "]" : host;
        return scheme + "://" + h + (u.getPort() > 0 ? ":" + u.getPort() : "");
    }

    public static boolean isLoopback(String host) {
        String h = host == null ? "" : host.toLowerCase(Locale.ROOT);
        return h.equals("localhost") || h.equals("127.0.0.1") || h.equals("[::1]") || h.equals("::1");
    }

    public String baseUrl() {
        return baseUrl;
    }

    public String token() {
        return token;
    }

    public boolean hasToken() {
        return !token.isEmpty();
    }

    public boolean allowLocalhostHttp() {
        return allowLocalhostHttp;
    }

    @Override
    public String toString() {
        return "PrivaraConfig{" + baseUrl + ", token " + (token.isEmpty() ? "not set" : "set") + "}";
    }
}
