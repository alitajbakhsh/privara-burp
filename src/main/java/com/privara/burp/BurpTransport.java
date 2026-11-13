package com.privara.burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.privara.burp.core.Transport;

import java.io.IOException;
import java.net.URI;
import java.util.List;

/**
 * Privara API calls through Burp's own networking ({@code Http.sendRequest}), so Burp's upstream
 * proxy, SOCKS proxy and TLS settings apply (BApp criterion "Uses Burp networking"). Chosen in the
 * Settings tab; off by default, because then Burp's Logger records these calls WITH the
 * Authorization header, and every other extension's HTTP handler sees them.
 *
 * Redirects are never followed (RedirectionMode.NEVER) and the server certificate is verified
 * ({@code withUpstreamTLSVerification}), so the token still goes only to the configured base URL.
 */
final class BurpTransport implements Transport {
    private final Http http;

    BurpTransport(Http http) {
        this.http = http;
    }

    @Override
    public String name() {
        return "Burp networking";
    }

    @Override
    public Response send(String method, URI uri, List<String[]> headers, byte[] body, int timeoutSeconds)
            throws IOException {
        HttpRequest req = HttpRequest.httpRequestFromUrl(uri.toString()).withMethod(method);
        for (String[] h : headers) {
            req = req.withHeader(h[0], h[1]);
        }
        if (body != null) {
            req = req.withBody(ByteArray.byteArray(body));
        }
        RequestOptions opts = RequestOptions.requestOptions()
                .withRedirectionMode(RedirectionMode.NEVER)
                .withUpstreamTLSVerification()
                .withResponseTimeout(timeoutSeconds * 1000L);
        HttpRequestResponse rr = http.sendRequest(req, opts);
        HttpResponse resp = rr == null ? null : rr.response();
        if (resp == null) {
            // Burp gives no reason here; never echo the request (it holds the Authorization header).
            throw new IOException("no answer through Burp's networking (check Burp's upstream proxy and "
                    + "TLS settings, or untick 'through Burp's networking')");
        }
        ByteArray b = resp.body();
        return new Response(resp.statusCode(), b == null ? new byte[0] : b.getBytes());
    }
}
