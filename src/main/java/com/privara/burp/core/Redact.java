package com.privara.burp.core;

import java.util.regex.Pattern;

/**
 * The last line before text reaches Burp's Output tab or a label: the configured token is removed,
 * and so is anything that looks like a bearer credential, even when it came back from a server.
 * Nothing is ever printed "partially masked": the token is replaced whole.
 */
public final class Redact {
    private static final Pattern BEARER = Pattern.compile("(?i)(bearer\\s+)[A-Za-z0-9._~+/=\\-]{6,}");
    private static final Pattern AUTH_HDR = Pattern.compile("(?i)(authorization\\s*[:=]\\s*)\\S+");
    private static final Pattern CTRL = Pattern.compile("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]");

    private Redact() {
    }

    public static String scrub(String text, String token) {
        if (text == null) {
            return "";
        }
        String s = text;
        if (token != null && token.length() >= 4) {
            s = s.replace(token, "<token>");
        }
        s = BEARER.matcher(s).replaceAll("$1<token>");
        s = AUTH_HDR.matcher(s).replaceAll("$1<token>");
        return CTRL.matcher(s).replaceAll("");
    }

    /** One line, bounded, scrubbed: for status labels and log lines. */
    public static String line(String text, String token, int limit) {
        String s = scrub(text, token).replace('\r', ' ').replace('\n', ' ');
        return s.length() > limit ? s.substring(0, limit) + "..." : s;
    }
}
