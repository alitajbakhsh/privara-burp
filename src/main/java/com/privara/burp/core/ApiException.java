package com.privara.burp.core;

/** A refusal or failure from the Privara API: the HTTP status and the server's own `detail`. */
public final class ApiException extends Exception {
    private final int status;
    private final String detail;

    public ApiException(int status, String detail) {
        super(status > 0 ? "HTTP " + status + ": " + detail : detail);
        this.status = status;
        this.detail = detail == null ? "" : detail;
    }

    public int status() {
        return status;
    }

    public String detail() {
        return detail;
    }
}
