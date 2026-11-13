package com.privara.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import com.privara.burp.core.ApiException;
import com.privara.burp.core.ApiMap;
import com.privara.burp.core.Findings;
import com.privara.burp.core.ForgeGate;
import com.privara.burp.core.Forger;
import com.privara.burp.core.Json;
import com.privara.burp.core.PrivaraClient;
import com.privara.burp.core.PrivaraConfig;
import com.privara.burp.core.SafeLog;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The Burp side of the extension, driven through the REAL Montoya interfaces with a recording fake
 * of Burp (java.lang.reflect.Proxy, plus the factory Burp installs at load time). Not a substitute
 * for loading the jar into Burp, but it runs every Montoya call the extension makes:
 * initialize(), the site map, the target scope, Repeater, audit issues, and the HTTP handler
 * applying a signature. Run headless.
 */
public final class MontoyaSmoke {
    static int fails = 0;
    static int passes = 0;
    static final List<String> rec = Collections.synchronizedList(new ArrayList<>());

    static void check(String name, boolean ok, Object got) {
        if (ok) {
            passes++;
            System.out.println("  PASS  " + name);
        } else {
            fails++;
            System.out.println("  FAIL  " + name + "   -> " + got);
        }
    }

    /** A value object: answers toString with what it was made from, records with* calls. */
    static Object value(Class<?> iface, String desc, Map<String, Object> props) {
        return Proxy.newProxyInstance(MontoyaSmoke.class.getClassLoader(), new Class<?>[] {iface}, (p, m, a) -> {
            String n = m.getName();
            if (n.equals("toString")) {
                return desc;
            }
            if (n.equals("hashCode")) {
                return System.identityHashCode(p);
            }
            if (n.equals("equals")) {
                return p == a[0];
            }
            if (props.containsKey(n)) {
                return props.get(n);
            }
            if (n.startsWith("with")) {
                rec.add("req." + n + " " + java.util.Arrays.toString(a));
                return p;
            }
            return dflt(m);
        });
    }

    static Object dflt(Method m) {
        Class<?> r = m.getReturnType();
        if (r == void.class) {
            return null;
        }
        if (r == boolean.class) {
            return false;
        }
        if (r == int.class || r == long.class || r == short.class || r == byte.class) {
            return 0;
        }
        if (r == String.class) {
            return "";
        }
        if (r == List.class) {
            return new ArrayList<>();
        }
        if (r == Optional.class) {
            return Optional.empty();
        }
        if (r.isInterface()) {
            return value(r, m.getName(), new HashMap<>());
        }
        return null;
    }

    static Object api(Class<?> iface, InvocationHandler h) {
        return Proxy.newProxyInstance(MontoyaSmoke.class.getClassLoader(), new Class<?>[] {iface}, h);
    }

    public static void main(String[] args) throws Exception {
        // the factory Burp installs when it loads an extension
        ObjectFactoryLocator.FACTORY = (MontoyaObjectFactory) api(MontoyaObjectFactory.class, (p, m, a) -> {
            String n = m.getName();
            if (n.equals("httpRequest") && a != null && a.length == 2) {
                rec.add("factory.httpRequest " + a[0] + " :: " + a[1]);
                return value(m.getReturnType(), String.valueOf(a[1]), new HashMap<>());
            }
            if (n.equals("httpRequestFromUrl")) {
                rec.add("factory.httpRequestFromUrl " + a[0]);
                return value(m.getReturnType(), "fromUrl " + a[0], new HashMap<>());
            }
            if (n.equals("httpService")) {
                return value(m.getReturnType(), a[0] + ":" + a[1] + ":" + a[2], new HashMap<>());
            }
            if (n.equals("auditIssue")) {
                rec.add("factory.auditIssue " + a[0] + " | " + a[3] + " | " + a[4] + " | " + a[5]
                        + " | static-first=" + String.valueOf(a[1]).startsWith("<p><b>Static analysis"));
                return value(m.getReturnType(), "issue", new HashMap<>());
            }
            if (n.equals("annotations")) {
                return value(m.getReturnType(), "annotations " + java.util.Arrays.toString(a), new HashMap<>());
            }
            if (n.equals("requestResult")) {
                rec.add("factory.requestResult " + a[0]);
                return value(m.getReturnType(), "result", new HashMap<>());
            }
            if (n.equals("byteArray")) {
                byte[] b = a[0] instanceof byte[] ? (byte[]) a[0] : new byte[0];
                return value(m.getReturnType(), new String(b, StandardCharsets.UTF_8), new HashMap<>());
            }
            return dflt(m);
        });

        Map<String, Object> prefs = new HashMap<>();
        Object preferences = api(burp.api.montoya.persistence.Preferences.class, (p, m, a) -> {
            String n = m.getName();
            if (n.startsWith("get")) {
                return prefs.get(n.substring(3) + ":" + a[0]);
            }
            if (n.startsWith("set")) {
                prefs.put(n.substring(3) + ":" + a[0], a[1]);
                return null;
            }
            if (n.startsWith("delete")) {
                prefs.remove(n.substring(6) + ":" + a[0]);
                return null;
            }
            return dflt(m);
        });
        List<String> out = new ArrayList<>();
        List<String> err = Collections.synchronizedList(new ArrayList<>());
        List<String> regRec = Collections.synchronizedList(new ArrayList<>());
        Object[] tab = new Object[1];
        HttpHandler[] handler = new HttpHandler[1];
        Runnable[] unload = new Runnable[1];
        Object[] burpAnswer = new Object[1];
        MontoyaApi montoya = (MontoyaApi) api(MontoyaApi.class, (p, m, a) -> {
            switch (m.getName()) {
                case "persistence":
                    return api(m.getReturnType(), (p2, m2, a2) -> m2.getName().equals("preferences") ? preferences : dflt(m2));
                case "logging":
                    return api(m.getReturnType(), (p2, m2, a2) -> {
                        if (m2.getName().equals("logToError")) {
                            err.add(String.valueOf(a2[0]));
                        } else if (m2.getName().startsWith("logTo")) {
                            out.add(String.valueOf(a2[0]));
                        }
                        return dflt(m2);
                    });
                case "extension":
                    return api(m.getReturnType(), (p2, m2, a2) -> {
                        if (m2.getName().equals("registerUnloadingHandler")) {
                            burp.api.montoya.extension.ExtensionUnloadingHandler u =
                                    (burp.api.montoya.extension.ExtensionUnloadingHandler) a2[0];
                            unload[0] = u::extensionUnloaded;
                            return registration("unloading", regRec);
                        }
                        return dflt(m2);
                    });
                case "http":
                    return api(m.getReturnType(), (p2, m2, a2) -> {
                        if (m2.getName().equals("registerHttpHandler")) {
                            handler[0] = (HttpHandler) a2[0];
                            return registration("http", regRec);
                        }
                        if (m2.getName().equals("sendRequest")) {
                            rec.add("http.sendRequest " + a2[0] + (a2.length > 1 ? " opts=" + a2[1] : ""));
                            return burpAnswer[0];
                        }
                        return dflt(m2);
                    });
                case "userInterface":
                    return api(m.getReturnType(), (p2, m2, a2) -> {
                        if (m2.getName().equals("registerSuiteTab")) {
                            rec.add("suiteTab " + a2[0]);
                            tab[0] = a2[1];
                            return registration("tab", regRec);
                        }
                        return dflt(m2);
                    });
                case "siteMap":
                    return api(m.getReturnType(), (p2, m2, a2) -> {
                        rec.add("siteMap." + m2.getName() + " " + a2[0]);
                        return null;
                    });
                case "scope":
                    return api(m.getReturnType(), (p2, m2, a2) -> {
                        rec.add("scope." + m2.getName() + " " + a2[0]);
                        return false;
                    });
                case "repeater":
                    return api(m.getReturnType(), (p2, m2, a2) -> {
                        rec.add("repeater " + a2[a2.length - 1]);
                        return null;
                    });
                case "burpSuite":
                    Map<String, Object> v = new HashMap<>();
                    v.put("edition", BurpSuiteEdition.PROFESSIONAL);
                    Map<String, Object> bs = new HashMap<>();
                    bs.put("version", value(burp.api.montoya.core.Version.class, "version", v));
                    return value(m.getReturnType(), "burpSuite", bs);
                default:
                    return dflt(m);
            }
        });

        System.out.println("\n=== B · the extension inside a recording fake of Burp ===");
        new PrivaraExtension().initialize(montoya);
        check("B1 initialize registers the Privara tab and an HTTP handler",
                rec.contains("suiteTab Privara") && handler[0] != null && tab[0] != null, rec);
        check("B2 the load message says forging is OFF", out.stream().anyMatch(s -> s.contains("forging is OFF")), out);

        // Drive the tab's own Montoya calls with a real imported map.
        BurpSettings bset = new BurpSettings(montoya.persistence().preferences(),
                new com.privara.burp.core.KaliLink.Source(java.nio.file.Path.of("/nonexistent/privara-kali-link.json"),
                        () -> System.currentTimeMillis() / 1000));
        PrivaraClient pc = new PrivaraClient(bset::config);
        SafeLog sl = new SafeLog(out::add, err::add, bset::token);
        PrivaraTab t = new PrivaraTab(montoya, bset, pc, new Forger(pc, new ForgeGate(System::currentTimeMillis), sl), sl);
        String openapi = Json.write(Map.of("openapi", "3.0.3", "info", Map.of("title", "x"),
                "servers", List.of(Map.of("url", "https://api.acme.com"), Map.of("url", "https://staging.acme-internal.net")),
                "paths", Map.of("/v1/users/{id}", Map.of("get", Map.of("operationId", "u")))));
        String scope = "{\"target\":{\"scope\":{\"include\":[{\"enabled\":true,\"protocol\":\"any\","
                + "\"host\":\"^api\\\\.acme\\\\.com$\",\"file\":\"^/.*\"}]}}}";
        set(t, "map", ApiMap.fromFiles(openapi, scope));
        rec.clear();
        call(t, "addToSiteMap");
        long added = rec.stream().filter(s -> s.startsWith("siteMap.add")).count();
        check("B3 'Add to site map' adds only the IN-SCOPE stubs by default", added == 1
                && rec.stream().anyMatch(s -> s.contains("factory.httpRequest api.acme.com:443:true :: GET /v1/users/{id} HTTP/1.1")),
                rec);
        rec.clear();
        call(t, "addToScope");
        check("B4 'Add in-scope hosts to target scope' includes exactly the burp-scope.json host",
                rec.equals(List.of("scope.includeInScope https://api.acme.com/")), rec);
        rec.clear();
        javax.swing.JCheckBox outside = (javax.swing.JCheckBox) get(t, "showOutside");
        outside.setSelected(true);
        Object em = get(t, "endpointModel");
        Method reload = em.getClass().getDeclaredMethod("reload");
        reload.setAccessible(true);
        reload.invoke(em);
        javax.swing.JTable table = (javax.swing.JTable) get(t, "endpointTable");
        table.selectAll();
        call(t, "sendToRepeater");
        check("B5 Repeater gets the in-scope entry and REFUSES the out-of-scope one",
                rec.size() == 2 && rec.get(1).equals("repeater Privara GET /v1/users/{id}"), rec);

        Map<String, Object> rep = new LinkedHashMap<>();
        rep.put("schema", Findings.SCHEMA);
        rep.put("app", Map.of("name", "AcmeShop"));
        rep.put("findings", List.of(Map.of("id", "PRV-IOS-1", "code", "C", "title", "T", "severity", "high",
                "confidence", "static-config", "description", "d")));
        set(t, "findings", Findings.parse(rep));
        rec.clear();
        call(t, "raiseIssues");
        call(t, "raiseIssues");
        check("B6 Burp Pro: a finding becomes ONE audit issue on the in-scope host, HIGH / TENTATIVE, static note first",
                rec.size() == 2 && rec.get(0).equals("factory.auditIssue [Privara iOS static] T | https://api.acme.com/ | HIGH | TENTATIVE | static-first=true"),
                rec);

        // B10-B12: device list refresh, device change, and the worker pool (bugs found 2026-11-12 while
        // checking the tab against the flows driven live in Caido).
        Forger tf = (Forger) get(t, "forger");
        tf.setDevice(9);
        tf.gate().loadStatus(Map.of("selected", 3L, "limits", Map.of("per_minute", 120L, "burst", 30L),
                "harnesses", List.of(Map.of("id", 3L, "name", "toybank", "verified", true,
                        "meta", Map.of("hosts", List.of("api.acme.com"))))), 0);
        tf.gate().enable("api.acme.com", Map.of("scope", "acme", "allowed", true));
        tf.gate().setOn(true);
        List<Map<String, Object>> devList = List.of(
                Map.of("id", 7L, "name", "ios-a", "status", "running", "scope", "acme", "capabilities", List.of("ipa_analysis")),
                Map.of("id", 9L, "name", "ios-b", "status", "running", "scope", "acme", "capabilities", List.of("ipa_analysis")),
                Map.of("id", 8L, "name", "kali", "status", "running", "capabilities", List.of("shell")));
        javax.swing.JComboBox<?> devCombo = (javax.swing.JComboBox<?>) get(t, "devices");
        Method fill = t.getClass().getDeclaredMethod("fillDevices", List.class);
        fill.setAccessible(true);
        fill.invoke(t, devList);
        check("B10 'Refresh devices' keeps the chosen device (not the first) and does NOT reset forging",
                devCombo.getItemCount() == 2 && String.valueOf(devCombo.getSelectedItem()).contains("#9")
                        && tf.device() == 9 && tf.gate().isOn() && tf.gate().harnessId() == 3 && bset.deviceId() != 7,
                devCombo.getSelectedItem() + " device=" + tf.device() + " on=" + tf.gate().isOn() + " saved=" + bset.deviceId());
        javax.swing.JComboBox<Object> runCombo = cast(get(t, "runs"));
        Class<?> itemCls = Class.forName("com.privara.burp.PrivaraTab$Item");
        java.lang.reflect.Constructor<?> mk = itemCls.getDeclaredConstructor(long.class, String.class, Map.class);
        mk.setAccessible(true);
        runCombo.addItem(mk.newInstance(41L, "#1 apimap", Map.of()));
        devCombo.setSelectedIndex(0);
        check("B11 choosing another device clears its runs, the imported map (in-scope hosts) and the findings, and forging",
                tf.device() == 7 && runCombo.getItemCount() == 0 && get(t, "map") == null && get(t, "findings") == null
                        && !tf.gate().isOn() && bset.deviceId() == 7,
                "runs=" + runCombo.getItemCount() + " map=" + get(t, "map") + " on=" + tf.gate().isOn());
        Method bgm = t.getClass().getDeclaredMethod("bg", javax.swing.JLabel.class, String.class,
                java.util.concurrent.Callable.class, java.util.function.Consumer.class);
        bgm.setAccessible(true);
        java.util.concurrent.CountDownLatch hold = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch second = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.Callable<Object> slow = () -> {
            hold.await(10, java.util.concurrent.TimeUnit.SECONDS);
            return "slow";
        };
        java.util.concurrent.Callable<Object> quick = () -> {
            second.countDown();
            return "quick";
        };
        java.util.function.Consumer<Object> none = x -> { };
        bgm.invoke(t, new javax.swing.JLabel(), "a long scan", slow, none);
        bgm.invoke(t, new javax.swing.JLabel(), "load devices", quick, none);
        boolean ran = second.await(3, java.util.concurrent.TimeUnit.SECONDS);
        hold.countDown();
        check("B12 a long-running call (scan, upload) does not block the other buttons' calls", ran, "second call waited");

        // The HTTP handler applying a signature, with a client whose sign() is a stub.
        ForgeGate gate = new ForgeGate(System::currentTimeMillis);
        List<String> signed = new ArrayList<>();
        PrivaraClient fake = new PrivaraClient(() -> new PrivaraConfig("https://app.tajapps.com", "tok", false)) {
            @Override
            public Map<String, Object> sign(long iid, long hid, Map<String, Object> request) throws ApiException {
                signed.add(Json.str(request.get("url")));
                return Map.of("ok", true, "harness", "toybank", "headers", Map.of("X-Sig", "abc"),
                        "remove", List.of("X-Old"), "body_b64", Base64.getEncoder().encodeToString("B".getBytes()));
            }
        };
        Forger f = new Forger(fake, gate, new SafeLog(s -> { }, () -> "tok"));
        f.setDevice(7);
        gate.loadStatus(Map.of("selected", 3L, "limits", Map.of("per_minute", 120L, "burst", 30L),
                "harnesses", List.of(Map.of("id", 3L, "name", "toybank", "verified", true,
                        "meta", Map.of("hosts", List.of("api.acme.com"))))), 0);
        gate.enable("api.acme.com", Map.of("scope", "acme", "allowed", true));
        ForgeHttpHandler h = new ForgeHttpHandler(f);
        rec.clear();
        h.handleHttpRequestToBeSent(request("api.acme.com"));
        check("B7 forging OFF: the handler passes the request through untouched", signed.isEmpty()
                && rec.stream().noneMatch(s -> s.startsWith("req.with")), rec);
        gate.setOn(true);
        rec.clear();
        h.handleHttpRequestToBeSent(request("other.example"));
        check("B8 a host that is not enabled is never sent to the sign API", signed.isEmpty()
                && rec.stream().noneMatch(s -> s.startsWith("req.with")), rec);
        rec.clear();
        h.handleHttpRequestToBeSent(request("api.acme.com"));
        check("B9 an enabled host is signed: header removed, signed header set, body replaced, request continued",
                signed.size() == 1 && rec.contains("req.withRemovedHeader [X-Old]") && rec.contains("req.withHeader [X-Sig, abc]")
                        && rec.stream().anyMatch(s -> s.startsWith("req.withBody")) && rec.stream().anyMatch(s -> s.startsWith("factory.requestResult")),
                rec);

        // This Kali's Privara link, through the extension's own settings object (Burp prefs fake).
        java.nio.file.Path dir = java.nio.file.Files.createTempDirectory("pv-kl");
        java.nio.file.Path lf = dir.resolve("kali-link.json");
        String linkTok = "privara_kl_SMOKEtoken0123456789abcdef";
        java.nio.file.Files.writeString(lf, "{\"schema\":\"privara.kali-link/1\",\"base\":\"https://app.tajapps.com\","
                + "\"token\":\"" + linkTok + "\",\"expires_at\":" + (System.currentTimeMillis() / 1000 + 86400)
                + ",\"kali_id\":181,\"kali_name\":\"kali\"}");
        prefs.clear();
        BurpSettings ls = new BurpSettings(montoya.persistence().preferences(),
                new com.privara.burp.core.KaliLink.Source(lf, () -> System.currentTimeMillis() / 1000));
        PrivaraConfig lc = ls.config();
        check("B13 with no typed token, the settings use this Kali's link (its base, its token)",
                ls.usingLink() && lc.token().equals(linkTok) && lc.baseUrl().equals("https://app.tajapps.com")
                        && ls.tokenState().startsWith("Connected automatically through this Kali's Privara link (kali)"),
                ls.tokenState());
        ls.save("https://app.tajapps.com", "", false, true);
        check("B14 the link token is NEVER written to Burp's settings, even with 'remember' ticked",
                !prefs.toString().contains(linkTok), prefs);
        ls.save("https://app.tajapps.com", "pvt_typed_by_hand_0123456789", false, false);
        check("B15 a token typed by hand wins over the link", !ls.usingLink()
                && ls.config().token().equals("pvt_typed_by_hand_0123456789") && ls.tokenState().equals("token set by you"),
                ls.tokenState());
        com.privara.burp.core.KaliLink.Result back = ls.useLink();
        check("B16 'Use this Kali's link' drops the typed token and goes back to the link",
                back != null && back.ok() && ls.usingLink() && ls.config().token().equals(linkTok), ls.tokenState());
        java.nio.file.Files.delete(lf);
        java.nio.file.Files.delete(dir);

        // B17-B20: PortSwigger's BApp Store acceptance criteria.
        System.out.println("\n=== S · BApp Store criteria, on the Montoya side ===");
        Map<String, Object> hostile = new LinkedHashMap<>();
        hostile.put("schema", Findings.SCHEMA);
        hostile.put("app", Map.of("name", "AcmeShop"));
        hostile.put("findings", List.of(Map.of("id", "PRV-IOS-2", "code", "C", "title",
                "<html><img src=https://evil.example/x.png>", "severity", "low", "confidence", "static-config",
                "description", "d")));
        set(t, "findings", Findings.parse(hostile));
        javax.swing.JTable ft = (javax.swing.JTable) get(t, "findingTable");
        Object cell = ft.getModel().getValueAt(0, 1);
        java.awt.Component rc = ft.getCellRenderer(0, 1).getTableCellRendererComponent(ft, cell, false, false, 0, 1);
        List<javax.swing.JComponent> comps = allComponents(t.component(), new ArrayList<>());
        long noFlag = comps.stream().filter(c -> !Boolean.TRUE.equals(c.getClientProperty("html.disable"))).count();
        check("B17 an app-supplied '<html>' title is never rendered as HTML: the cell text is not Swing HTML, the "
                + "renderer and every component of the tab (" + comps.size() + ") have html.disable",
                !javax.swing.plaf.basic.BasicHTML.isHTMLString(String.valueOf(cell)) && noFlag == 0
                        && rc instanceof javax.swing.JComponent
                        && Boolean.TRUE.equals(((javax.swing.JComponent) rc).getClientProperty("html.disable"))
                        && comps.size() > 40,
                "cell=" + cell + " without flag=" + noFlag);

        err.clear();
        java.util.concurrent.Callable<Object> boom = () -> {
            throw new IllegalStateException("worker exploded");
        };
        java.util.concurrent.Callable<Object> refused = () -> {
            throw new ApiException(403, "forbidden by the platform");
        };
        bgm.invoke(t, new javax.swing.JLabel(), "a refused call", refused, none);
        bgm.invoke(t, new javax.swing.JLabel(), "a broken call", boom, none);
        for (int i = 0; i < 60 && err.isEmpty(); i++) {
            Thread.sleep(50);
        }
        Thread.sleep(100);
        check("B18 an unexpected exception on a worker thread reaches Burp's ERROR stream with its stack trace; "
                + "an API refusal does not (it is shown in the tab and Output)",
                err.size() == 1 && err.get(0).contains("IllegalStateException: worker exploded")
                        && err.get(0).contains("\tat ") && !err.get(0).contains("forbidden"), err);

        prefs.clear();
        BurpSettings nb = new BurpSettings(montoya.persistence().preferences(), null);
        nb.save("https://app.tajapps.com", "pvt_typed_by_hand_0123456789", false, false);
        com.privara.burp.core.JdkTransport direct = new com.privara.burp.core.JdkTransport();
        BurpTransport viaBurp = new BurpTransport(montoya.http());
        PrivaraClient nc = new PrivaraClient(nb::config, () -> nb.viaBurp() ? viaBurp : direct);
        String defaultName = nc.transportName();
        nb.setViaBurp(true);
        burpAnswer[0] = burpAnswer(200, "{\"username\":\"via-burp\"}");
        rec.clear();
        String who = Json.str(nc.whoami().get("username"));
        check("B19 'through Burp's networking' (off by default) sends with Burp's Http.sendRequest: the base URL, "
                + "the bearer token, redirects NEVER followed, upstream TLS verified, a response timeout",
                defaultName.equals("direct") && who.equals("via-burp")
                        && rec.contains("factory.httpRequestFromUrl https://app.tajapps.com/api/whoami")
                        && rec.contains("req.withHeader [Authorization, Bearer pvt_typed_by_hand_0123456789]")
                        && rec.contains("req.withRedirectionMode [NEVER]") && rec.contains("req.withUpstreamTLSVerification null")
                        && rec.contains("req.withResponseTimeout [30000]")
                        && rec.stream().anyMatch(s -> s.startsWith("http.sendRequest ")),
                defaultName + " " + who + " " + rec);
        burpAnswer[0] = burpAnswer(302, "");
        String red = "";
        try {
            nc.whoami();
        } catch (ApiException e) {
            red = e.getMessage();
        }
        burpAnswer[0] = null;
        String none2 = "";
        try {
            nc.whoami();
        } catch (ApiException e) {
            none2 = e.getMessage();
        }
        check("B19b through Burp too, a redirect is refused, and no answer is an error that holds no request header",
                red.contains("redirect") && none2.contains("no answer through Burp's networking")
                        && !none2.contains("pvt_typed"), red + " / " + none2);
        direct.close();

        int errBefore = err.size();
        unload[0].run();
        t.stop();
        check("B20 unloading deregisters the HTTP handler and the tab, without an error; the tab's timer and "
                + "workers are stopped",
                regRec.contains("deregister http") && regRec.contains("deregister tab") && err.size() == errBefore
                        && t.stopped(), regRec + " " + err);

        System.out.println("\n" + passes + " passed, " + fails + " failed");
        System.exit(fails == 0 ? 0 : 1);
    }

    /** A Montoya Registration that records deregister() calls. */
    static Object registration(String what, List<String> log) {
        boolean[] live = {true};
        return api(burp.api.montoya.core.Registration.class, (p, m, a) -> {
            switch (m.getName()) {
                case "isRegistered":
                    return live[0];
                case "deregister":
                    live[0] = false;
                    log.add("deregister " + what);
                    return null;
                case "hashCode":
                    return System.identityHashCode(p);
                case "equals":
                    return p == a[0];
                default:
                    return "registration " + what;
            }
        });
    }

    /** What Burp's Http.sendRequest answers: a response with this status and body. */
    static Object burpAnswer(int status, String body) {
        Map<String, Object> rp = new HashMap<>();
        rp.put("statusCode", (short) status);
        rp.put("body", value(burp.api.montoya.core.ByteArray.class, body,
                Map.of("getBytes", body.getBytes(StandardCharsets.UTF_8))));
        Object resp = value(burp.api.montoya.http.message.responses.HttpResponse.class, "resp " + status, rp);
        Map<String, Object> rr = new HashMap<>();
        rr.put("response", resp);
        return value(burp.api.montoya.http.message.HttpRequestResponse.class, "rr " + status, rr);
    }

    static List<javax.swing.JComponent> allComponents(java.awt.Component c, List<javax.swing.JComponent> acc) {
        if (c instanceof javax.swing.JComponent) {
            acc.add((javax.swing.JComponent) c);
        }
        if (c instanceof java.awt.Container) {
            for (java.awt.Component k : ((java.awt.Container) c).getComponents()) {
                allComponents(k, acc);
            }
        }
        return acc;
    }

    static HttpRequestToBeSent request(String host) {
        Map<String, Object> svc = new HashMap<>();
        svc.put("host", host);
        Map<String, Object> props = new HashMap<>();
        props.put("httpService", value(burp.api.montoya.http.HttpService.class, host, svc));
        props.put("method", "POST");
        props.put("url", "https://" + host + "/v1/orders");
        props.put("pathWithoutQuery", "/v1/orders");
        props.put("headers", List.of());
        props.put("body", value(burp.api.montoya.core.ByteArray.class, "", Map.of("getBytes", new byte[0])));
        Map<String, Object> ann = new HashMap<>();
        ann.put("notes", "");
        props.put("annotations", value(burp.api.montoya.core.Annotations.class, "ann", ann));
        return (HttpRequestToBeSent) value(HttpRequestToBeSent.class, "req " + host, props);
    }

    @SuppressWarnings("unchecked")
    static <T> T cast(Object o) {
        return (T) o;
    }

    static Object get(Object o, String field) throws Exception {
        Field f = o.getClass().getDeclaredField(field);
        f.setAccessible(true);
        return f.get(o);
    }

    static void set(Object o, String field, Object v) throws Exception {
        Field f = o.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(o, v);
    }

    static void call(Object o, String method) throws Exception {
        Method m = o.getClass().getDeclaredMethod(method);
        m.setAccessible(true);
        m.invoke(o);
    }
}
