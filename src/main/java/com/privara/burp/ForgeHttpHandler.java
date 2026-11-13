package com.privara.burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.privara.burp.core.Forger;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Request forging inside Burp: every request Burp is about to send (Proxy, Repeater, Intruder,
 * Scanner, other extensions) is offered to {@link Forger}. Only a request to a host that the
 * harness lists, that the tester enabled, and that passed the platform's scope check is sent to
 * the sign API; every other request leaves Burp exactly as it was and the API never hears of it.
 *
 * A request that cannot be signed goes out UNSIGNED (Montoya's HTTP handler cannot drop a
 * request); the Forging tab and Burp's Output say why.
 *
 * Speed (BApp criterion "no slow work in an HttpHandler"): a request to any host that is not an
 * enabled forging host returns after two field reads (forging on? host enabled?), with no copy and
 * no network. Only a request the tester opted in to signing waits for the sign API, because the
 * signature must be on the request before Burp sends it; Burp runs this handler on its own network
 * thread, never the Swing thread, and the call is rate-limited and time-bounded.
 */
final class ForgeHttpHandler implements HttpHandler {
    private final Forger forger;

    ForgeHttpHandler(Forger forger) {
        this.forger = forger;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        try {
            if (!forger.gate().isOn() || !forger.gate().candidate(req.httpService().host())) {
                return RequestToBeSentAction.continueWith(req);
            }
            List<String[]> headers = new ArrayList<>();
            for (HttpHeader h : req.headers()) {
                headers.add(new String[] {h.name(), h.value()});
            }
            Forger.Req r = new Forger.Req(req.method(), req.url(), req.httpService().host(),
                    req.pathWithoutQuery(), headers, req.body().getBytes());
            Forger.Outcome o = forger.forge(r);
            if (o.kind != Forger.Kind.SIGNED) {
                return RequestToBeSentAction.continueWith(req);
            }
            HttpRequest out = req;
            for (String name : o.removeHeaders) {
                out = out.withRemovedHeader(name);
            }
            for (Map.Entry<String, String> e : o.setHeaders.entrySet()) {
                out = out.withHeader(e.getKey(), e.getValue());
            }
            if (o.body != null) {
                out = out.withBody(ByteArray.byteArray(o.body));
            }
            Annotations a = req.annotations();
            String notes = a.notes() == null || a.notes().isEmpty() ? "" : a.notes() + " | ";
            return RequestToBeSentAction.continueWith(out, a.withNotes(notes + "signed by Privara request forging"));
        } catch (RuntimeException e) {
            // Never break the tester's traffic because of the extension; Burp does not report an
            // exception thrown here, so write it (scrubbed) to the extension's error stream.
            forger.log().error("request forging failed on a request; it was sent unsigned", e);
            return RequestToBeSentAction.continueWith(req);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        return ResponseReceivedAction.continueWith(resp);
    }
}
