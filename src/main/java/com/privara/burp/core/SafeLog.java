package com.privara.burp.core;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Every log line the extension writes goes through here, and is scrubbed of the current token
 * first. The sinks are Burp's output and error streams in the extension and lists in the tests,
 * which is how the tests prove a token never reaches a log even when a server echoes it back.
 *
 * {@link #error} writes an unexpected exception with its stack trace to the ERROR stream (Burp
 * does not report exceptions thrown on an extension's own threads, so without this they vanish).
 * Each stack-trace line is scrubbed like any other line.
 */
public final class SafeLog {
    private static final int MAX_TRACE_LINES = 40;

    private final Consumer<String> sink;
    private final Consumer<String> errSink;
    private final Supplier<String> token;

    public SafeLog(Consumer<String> sink, Supplier<String> token) {
        this(sink, sink, token);
    }

    public SafeLog(Consumer<String> sink, Consumer<String> errSink, Supplier<String> token) {
        this.sink = sink;
        this.errSink = errSink;
        this.token = token;
    }

    public void info(String msg) {
        emit(sink, "", msg);
    }

    public void warn(String msg) {
        emit(sink, "WARN ", msg);
    }

    /** An unexpected failure: the message and the scrubbed stack trace, on the error stream. */
    public void error(String msg, Throwable t) {
        StringBuilder b = new StringBuilder(msg == null ? "" : msg);
        if (t != null) {
            StringWriter w = new StringWriter();
            t.printStackTrace(new PrintWriter(w));
            String tok = tokenOrEmpty();
            String[] lines = w.toString().split("\r?\n");
            for (int i = 0; i < lines.length && i < MAX_TRACE_LINES; i++) {
                b.append('\n').append(Redact.line(lines[i], tok, 400));
            }
            if (lines.length > MAX_TRACE_LINES) {
                b.append("\n\t... ").append(lines.length - MAX_TRACE_LINES).append(" more");
            }
        }
        try {
            errSink.accept("[privara] ERROR " + Redact.scrub(b.toString(), tokenOrEmpty()));
        } catch (RuntimeException ignored) {
            // a log sink that fails must never break a request
        }
    }

    private String tokenOrEmpty() {
        try {
            String t = token.get();
            return t == null ? "" : t;
        } catch (RuntimeException e) {
            return "";
        }
    }

    private void emit(Consumer<String> to, String level, String msg) {
        try {
            to.accept("[privara] " + level + Redact.line(msg, tokenOrEmpty(), 2000));
        } catch (RuntimeException ignored) {
            // a log sink that fails must never break a request
        }
    }
}
