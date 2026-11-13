package com.privara.burp.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Map;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

/**
 * This Kali's Privara link: on a Privara cloud Kali the platform keeps a short-lived,
 * route-limited token in {@code /etc/privara/kali-link.json} (root-only, rewritten atomically, rotated
 * daily, deleted when the customer turns the link off). When no token was typed by hand, the extension
 * uses that file, so nothing has to be pasted on a Privara Kali.
 *
 * <p>The file is accepted only when ALL hold: schema {@code privara.kali-link/1}, an https base URL
 * (no path, no user info), a token starting {@code privara_kl_} made of URL-safe characters, and an
 * {@code expires_at} still in the future. Anything else is ignored with a readable reason. The token
 * is never logged, never shown and never written to Burp's settings; {@link Link#toString()} omits it.
 *
 * <p>A token typed by hand ALWAYS wins ({@link #choose}).
 */
public final class KaliLink {
    public static final String DEFAULT_PATH = "/etc/privara/kali-link.json";
    public static final String SCHEMA = "privara.kali-link/1";
    public static final String PREFIX = "privara_kl_";
    static final int MAX_BYTES = 16 * 1024;
    private static final Pattern TOKEN_RE = Pattern.compile("^privara_kl_[A-Za-z0-9_-]{16,200}$");
    public static final String ROOT_ONLY = "this Kali's link file is root-only; run Burp as root or paste a token";

    private KaliLink() {
    }

    /** The path to read: $PRIVARA_KALI_LINK_FILE (tests only) or the platform's fixed path. */
    public static Path path() {
        String env = System.getenv("PRIVARA_KALI_LINK_FILE");
        return Path.of(env == null || env.isEmpty() ? DEFAULT_PATH : env);
    }

    /** A valid link. */
    public static final class Link {
        public final String base;
        public final String token;
        public final long expiresAt;
        public final long kaliId;
        public final String kaliName;

        Link(String base, String token, long expiresAt, long kaliId, String kaliName) {
            this.base = base;
            this.token = token;
            this.expiresAt = expiresAt;
            this.kaliId = kaliId;
            this.kaliName = kaliName;
        }

        @Override
        public String toString() {
            return "KaliLink{" + base + ", kali " + kaliName + " #" + kaliId + ", token set}";
        }
    }

    /**
     * What reading the file gave: a link, or nothing with a reason. {@code present} is false when
     * there is no file at all (not a Privara Kali, or the link is off) and then {@code problem} is "".
     */
    public static final class Result {
        public final Link link;
        public final boolean present;
        public final String problem;

        Result(Link link, boolean present, String problem) {
            this.link = link;
            this.present = present;
            this.problem = problem == null ? "" : problem;
        }

        public boolean ok() {
            return link != null;
        }

        static Result absent() {
            return new Result(null, false, "");
        }

        static Result bad(String why) {
            return new Result(null, true, why);
        }
    }

    /** Parse the file's text. {@code nowSeconds} is the current Unix time. */
    public static Result parse(String text, long nowSeconds) {
        Map<String, Object> o;
        try {
            o = Json.obj(Json.parse(text));
        } catch (RuntimeException e) {
            return Result.bad("this Kali's link file is not valid JSON");
        }
        if (!SCHEMA.equals(o.get("schema"))) {
            return Result.bad("this Kali's link file has an unknown schema");
        }
        String base;
        try {
            base = PrivaraConfig.normalise(Json.str(o.get("base")), false);
        } catch (IllegalArgumentException e) {
            return Result.bad("this Kali's link file has a bad base URL: " + e.getMessage());
        }
        if (!base.startsWith("https://")) {
            return Result.bad("this Kali's link file must name an https base URL");
        }
        String token = Json.str(o.get("token"));
        if (!TOKEN_RE.matcher(token).matches()) {
            return Result.bad("this Kali's link file does not hold a Kali link token");
        }
        Object exp = o.get("expires_at");
        if (!(exp instanceof Number)) {
            return Result.bad("this Kali's link file has no expiry");
        }
        long expiresAt = ((Number) exp).longValue();
        if (expiresAt <= nowSeconds) {
            return Result.bad("this Kali's link token has expired; the platform renews it while the Kali "
                    + "runs and the link is on");
        }
        long kaliId = o.get("kali_id") instanceof Number ? ((Number) o.get("kali_id")).longValue() : 0;
        String name = Json.str(o.get("kali_name")).replaceAll("[^A-Za-z0-9 ._()#-]", "");
        if (name.length() > 80) {
            name = name.substring(0, 80);
        }
        return new Result(new Link(base, token, expiresAt, kaliId, name.isEmpty() ? "this Kali" : name),
                true, "");
    }

    /** Read and parse the file at {@code p}. Never throws. */
    public static Result read(Path p, long nowSeconds) {
        try {
            if (!Files.exists(p)) {
                return Result.absent();
            }
            if (Files.size(p) > MAX_BYTES) {
                return Result.bad("this Kali's link file is too large");
            }
            return parse(new String(Files.readAllBytes(p), StandardCharsets.UTF_8), nowSeconds);
        } catch (NoSuchFileException e) {
            return Result.absent();
        } catch (AccessDeniedException e) {
            return Result.bad(ROOT_ONLY);
        } catch (IOException | SecurityException e) {
            // a directory with mode 0700 owned by root also lands here on some JDKs
            return Files.isReadable(p) ? Result.bad("this Kali's link file could not be read") : Result.bad(ROOT_ONLY);
        }
    }

    /**
     * The config to use: a token typed by hand ALWAYS wins (with the base URL from the settings);
     * otherwise a valid link (with ITS base URL, https only); otherwise the settings with no token.
     */
    public static PrivaraConfig choose(String settingsBase, String manualToken, boolean allowLocal, Result link) {
        if (manualToken != null && !manualToken.trim().isEmpty()) {
            return new PrivaraConfig(settingsBase, manualToken, allowLocal);
        }
        if (link != null && link.ok()) {
            return new PrivaraConfig(link.link.base, link.link.token, false);
        }
        return new PrivaraConfig(settingsBase, "", allowLocal);
    }

    /**
     * The file, re-read only when it changed (modification time or size) or the cached link has
     * expired. {@link #reload()} forces a read (used once on a 401) and says whether the token changed.
     */
    public static final class Source {
        private final Path path;
        private final LongSupplier nowSeconds;
        private long mtime = Long.MIN_VALUE;
        private long size = -1;
        private Result cached = Result.absent();
        private boolean loaded = false;

        public Source(Path path, LongSupplier nowSeconds) {
            this.path = path;
            this.nowSeconds = nowSeconds;
        }

        public synchronized Result current() {
            long m = Long.MIN_VALUE;
            long s = -1;
            try {
                m = Files.getLastModifiedTime(path).toMillis();
                s = Files.size(path);
            } catch (IOException | SecurityException e) {
                // absent or unreadable: read() says which
            }
            boolean expired = cached.ok() && cached.link.expiresAt <= nowSeconds.getAsLong();
            if (!loaded || m != mtime || s != size || expired) {
                cached = read(path, nowSeconds.getAsLong());
                mtime = m;
                size = s;
                loaded = true;
            }
            return cached;
        }

        /** Force a re-read; true when it now gives a DIFFERENT valid token than before. */
        public synchronized boolean reload() {
            String before = cached.ok() ? cached.link.token : "";
            loaded = false;
            Result r = current();
            return r.ok() && !r.link.token.equals(before);
        }
    }
}
