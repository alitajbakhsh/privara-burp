package com.privara.burp;

import burp.api.montoya.persistence.Preferences;
import com.privara.burp.core.KaliLink;
import com.privara.burp.core.PrivaraConfig;

/**
 * Settings kept with Burp's own preferences API (Burp's user settings, on this machine only).
 *
 * The token is stored ONLY when "remember the token" is ticked; otherwise it lives in memory for
 * this Burp session. Either way it is never logged, never shown again in the UI (the field is a
 * password field), and sent only to the configured Privara base URL.
 *
 * On a Privara cloud Kali with the link on, {@link KaliLink} supplies a token from this Kali's link
 * file whenever NO token was typed by hand (a typed token always wins). The link token is never
 * stored in Burp's settings, whatever "remember" says.
 */
final class BurpSettings {
    private static final String K_BASE = "privara.base_url";
    private static final String K_TOKEN = "privara.token";
    private static final String K_REMEMBER = "privara.remember_token";
    private static final String K_LOCAL = "privara.allow_localhost_http";
    private static final String K_DEVICE = "privara.device_id";
    private static final String K_VIA_BURP = "privara.via_burp_networking";
    /**
     * Whether Privara API calls go through Burp's networking when the tester has not chosen.
     * false: Java's own client, so the token is never in Logger or another extension's handler.
     * Flip to true if PortSwigger's review requires Burp networking by default (one line; the
     * Settings checkbox and its warning stay either way). BApp criterion 7, "Uses Burp networking".
     */
    static final boolean DEFAULT_VIA_BURP = false;

    private final Preferences prefs;
    private final KaliLink.Source link;
    private volatile String sessionToken = "";

    BurpSettings(Preferences prefs, KaliLink.Source link) {
        this.prefs = prefs;
        this.link = link;
        String t = prefs.getString(K_TOKEN);
        if (t != null && remember()) {
            sessionToken = t;
        }
    }

    String baseUrl() {
        String b = prefs.getString(K_BASE);
        return b == null || b.isEmpty() ? PrivaraConfig.DEFAULT_BASE : b;
    }

    boolean allowLocalhost() {
        Boolean b = prefs.getBoolean(K_LOCAL);
        return b != null && b;
    }

    boolean remember() {
        Boolean b = prefs.getBoolean(K_REMEMBER);
        return b != null && b;
    }

    /** Send Privara API calls through Burp's networking (upstream proxy, TLS settings)? */
    boolean viaBurp() {
        Boolean b = prefs.getBoolean(K_VIA_BURP);
        return b == null ? DEFAULT_VIA_BURP : b;
    }

    void setViaBurp(boolean v) {
        prefs.setBoolean(K_VIA_BURP, v);
    }

    /** True when a token is in use: typed by hand, or this Kali's link. */
    boolean hasToken() {
        return !sessionToken.isEmpty() || usingLink();
    }

    /** A token typed by hand is set (it wins over the link). */
    boolean hasManualToken() {
        return !sessionToken.isEmpty();
    }

    KaliLink.Result linkResult() {
        return link == null ? null : link.current();
    }

    /** True when the link is what is in use (no token typed by hand, and the link file is valid). */
    boolean usingLink() {
        KaliLink.Result r = linkResult();
        return sessionToken.isEmpty() && r != null && r.ok();
    }

    /** Force a re-read of the link file (once, on a 401); true when a NEW token is now in use. */
    boolean relink() {
        return sessionToken.isEmpty() && link != null && link.reload();
    }

    /** Drop the token typed by hand and go back to this Kali's link. */
    KaliLink.Result useLink() {
        forgetToken();
        if (link == null) {
            return null;
        }
        link.reload();
        return link.current();
    }

    /** What the settings tab says about the token in use. Never the token itself. */
    String tokenState() {
        if (!sessionToken.isEmpty()) {
            return "token set by you";
        }
        KaliLink.Result r = linkResult();
        if (r != null && r.ok()) {
            return "Connected automatically through this Kali's Privara link (" + r.link.kaliName + ")";
        }
        if (r != null && r.present) {
            return "no token set (" + r.problem + ")";
        }
        return "no token set";
    }

    long deviceId() {
        Long l = prefs.getLong(K_DEVICE);
        return l == null ? 0 : l;
    }

    void setDeviceId(long id) {
        prefs.setLong(K_DEVICE, id);
    }

    /** Validate first (throws with a readable message), then store. Only a TYPED token is stored. */
    void save(String base, String newToken, boolean allowLocal, boolean rememberToken) {
        String tok = newToken == null || newToken.isEmpty() ? sessionToken : newToken.trim();
        PrivaraConfig c = new PrivaraConfig(base, tok, allowLocal);
        prefs.setString(K_BASE, c.baseUrl());
        prefs.setBoolean(K_LOCAL, allowLocal);
        prefs.setBoolean(K_REMEMBER, rememberToken);
        sessionToken = c.token();
        if (rememberToken && !sessionToken.isEmpty()) {
            prefs.setString(K_TOKEN, sessionToken);
        } else {
            prefs.deleteString(K_TOKEN);
        }
    }

    void forgetToken() {
        sessionToken = "";
        prefs.deleteString(K_TOKEN);
    }

    /** The token in use, for redaction only; never displayed. */
    String token() {
        if (!sessionToken.isEmpty()) {
            return sessionToken;
        }
        KaliLink.Result r = linkResult();
        return r != null && r.ok() ? r.link.token : "";
    }

    /** The live config, or an IllegalArgumentException that says what is wrong with it. */
    PrivaraConfig config() {
        return KaliLink.choose(baseUrl(), sessionToken, allowLocalhost(), linkResult());
    }
}
