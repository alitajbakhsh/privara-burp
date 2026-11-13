# Privara iOS kit for Burp Suite

A Burp Suite extension (Montoya API) that brings **Privara iOS Analysis** into Burp: the backend
API map of an iOS app, scoped to your engagement, as site-map stubs, target scope and Repeater
tabs; the app's findings as Burp issues; and analyst-assisted request signing for apps that sign
their API requests.

It needs a **Privara account with iOS Analysis** (a paid service from TAJ APPS LLC,
[tajapps.com](https://tajapps.com)) and your own Privara API token. Without one, the extension
loads but has nothing to talk to.

## What it does

**Device & API map**
- Lists your iOS Analysis devices, uploads an `.ipa`, runs `apimap`, `cloudcheck` or `deeplinks`
  on the platform and lists the runs.
- **Import API map** reads the run's map (`openapi.json`) and the hosts the platform checked
  against your device's **engagement scope** (`burp-scope.json`). A host is in scope only if the
  platform says so; a device with no scope puts nothing in scope.
- **Add to site map** adds request stubs (highlighted, noted "static map, not observed"). Nothing
  is sent. **Add in-scope hosts to target scope** adds only the in-scope hosts. **Send selected to
  Repeater** opens tabs for in-scope entries only; you send them.

**Request forging** (off until you switch it on)
- For an app whose requests carry a signature, Privara can run the app's own signing code for you
  (a "harness", verified on your device). Tick the hosts to sign; each one is first checked against
  your engagement scope by the platform. Then requests to those hosts, from any Burp tool, are
  signed before Burp sends them. Requests to any other host are never sent to Privara.

**Findings**
- The platform's findings report for the run. In Burp Professional, **Raise as Burp issues** adds
  them under the first in-scope host, marked Tentative ("static analysis, not runtime proof").

## What leaves Burp, and where it goes

Everything goes to **one place: the Privara base URL you set** (default `https://app.tajapps.com`),
and only when you click a button (or, with forging on, when Burp sends a request to a host you
ticked). Nothing is sent when the extension loads, and there is no telemetry and no update check.

| You click | Sent to the base URL |
|---|---|
| Test connection, Refresh devices / runs | your API token (Authorization header) |
| Upload app | the `.ipa` file you choose |
| Run analysis | the analysis name and the uploaded file's path |
| Import API map, Load findings | the run id |
| Tick a forging host | the host name (scope check) |
| Forging on: a request to a ticked host | that request's method, URL, headers and body, to be signed; the signed headers and body come back |

- Your token is sent only to the base URL and only in the Authorization header. Redirects are
  never followed. It is removed from every message and log line, and stored in Burp's settings on
  this machine only if you tick "remember the token".
- `https://` only. Plain `http://` is accepted for `localhost` alone, with an explicit
  development box ticked.
- By default the calls use Java's own HTTP client, not Burp's, so the token never appears in
  Burp's Logger and no other extension's HTTP handler sees it. If you need Burp's **upstream
  proxy** or TLS settings, tick **Send Privara API calls through Burp's networking** in Settings;
  then Logger records these calls, token included.
- Text from the analysed app (paths, hosts, finding titles) is treated as untrusted: it is never
  rendered as HTML in the tab, and it is HTML-escaped in Burp issues.

## Install

1. Burp **Extensions > BApp Store > Privara iOS kit > Install** (or **Extensions > Installed >
   Add**, type Java, the jar built below).
2. Open the **Privara** tab > **Settings**: base URL `https://app.tajapps.com` (or your own
   platform), your API token (Privara: **API** page > **Generate token**), **Save**, **Test
   connection**.
3. **Device & API map**: refresh devices, pick yours, import a run's map.

On a Privara cloud Kali the token is not needed: the extension uses that Kali's own short-lived,
root-only link file (`/etc/privara/kali-link.json`) when no token was typed. A typed token always
wins.

## Build

Any JDK 17 or later.

```
./gradlew jar          # build/libs/privara-burp.jar
./gradlew check        # compile with -Werror, run the unit tests and the Montoya smoke test
./build.sh             # the same sources with javac + jar only (no Gradle): dist/privara-burp.jar
```

The Montoya API (`net.portswigger.burp.extensions:montoya-api`) is a compile-only dependency:
Burp provides it at run time. The extension has no other dependency.

## Licence

See [LICENSE](LICENSE).
