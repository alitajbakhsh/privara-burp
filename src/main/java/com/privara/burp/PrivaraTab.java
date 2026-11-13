package com.privara.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.privara.burp.core.ApiMap;
import com.privara.burp.core.Findings;
import com.privara.burp.core.ForgeGate;
import com.privara.burp.core.Forger;
import com.privara.burp.core.Hosts;
import com.privara.burp.core.ApiException;
import com.privara.burp.core.Json;
import com.privara.burp.core.KaliLink;
import com.privara.burp.core.Plain;
import com.privara.burp.core.PrivaraClient;
import com.privara.burp.core.Redact;
import com.privara.burp.core.SafeLog;
import com.privara.burp.core.Version;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Container;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * The "Privara" suite tab. Four sub-tabs: Settings, Device &amp; API map, Request forging, Findings.
 * Every network call runs off the Swing thread; every message shown is scrubbed of the token.
 */
final class PrivaraTab {
    private final MontoyaApi api;
    private final BurpSettings settings;
    private final PrivaraClient client;
    private final Forger forger;
    private final SafeLog log;
    // Several workers: a scan (up to ~30 min) or an upload must not queue every other button behind it.
    static final int WORKERS = 4;
    private final ExecutorService pool = Executors.newFixedThreadPool(WORKERS, r -> {
        Thread t = new Thread(r, "privara-burp");
        t.setDaemon(true);
        return t;
    });
    private final JTabbedPane root = new JTabbedPane();
    private final Timer refresh;

    // device + runs
    private final JComboBox<Item> devices = new JComboBox<>();
    private final JComboBox<Item> runs = new JComboBox<>();
    private final JTextField uploadPath = new JTextField(36);
    private final JComboBox<String> op = new JComboBox<>(new String[] {"apimap", "cloudcheck", "deeplinks"});
    private final JLabel deviceStatus = new JLabel(" ");
    /** True while loadDevices refills the list: JComboBox fires an action per addItem then. */
    private boolean fillingDevices;

    // API map
    private ApiMap map;
    private final EndpointModel endpointModel = new EndpointModel();
    private final JTable endpointTable = new JTable(endpointModel);
    private final JCheckBox showOutside = new JCheckBox("Show first-party hosts OUTSIDE the engagement scope");
    private final JLabel mapStatus = new JLabel(" ");

    // forging
    private final JCheckBox forgeOn = new JCheckBox("Sign requests (request forging ON)");
    private final JTextField harnessId = new JTextField(5);
    private final JLabel harnessLabel = new JLabel("load the forge status");
    private final HostModel hostModel = new HostModel();
    private final JTable hostTable = new JTable(hostModel);
    private final EventModel eventModel = new EventModel();
    private final JLabel forgeCounters = new JLabel(" ");
    private final JTextField wildcardHost = new JTextField(24);
    private final JLabel forgeStatus = new JLabel(" ");

    // findings
    private Findings findings;
    private final FindingModel findingModel = new FindingModel();
    private final JTable findingTable = new JTable(findingModel);
    private final JTextArea findingDetail = new JTextArea(10, 60);
    private final JLabel findingStatus = new JLabel(" ");
    private final Set<String> raised = new HashSet<>();

    PrivaraTab(MontoyaApi api, BurpSettings settings, PrivaraClient client, Forger forger, SafeLog log) {
        this.api = api;
        this.settings = settings;
        this.client = client;
        this.forger = forger;
        this.log = log;
        root.addTab("Settings", settingsPanel());
        root.addTab("Device & API map", devicePanel());
        root.addTab("Request forging", forgePanel());
        root.addTab("Findings", findingsPanel());
        refresh = new Timer(2000, e -> refreshForge());
        refresh.start();
        noHtml(root);
        for (JTable t : new JTable[] {endpointTable, hostTable, findingTable}) {
            noHtmlRenderers(t);
        }
    }

    /**
     * Swing renders text starting with "<html>" as HTML (it can load remote images). Paths, hosts,
     * titles and file names come from the analysed app, so HTML is switched off on every component
     * of the tab; table models and list items also pass their text through {@link Plain#text}.
     */
    static void noHtml(Component c) {
        if (c instanceof JComponent) {
            ((JComponent) c).putClientProperty("html.disable", Boolean.TRUE);
        }
        if (c instanceof JComboBox) {
            Object r = ((JComboBox<?>) c).getRenderer();
            if (r instanceof JComponent) {
                ((JComponent) r).putClientProperty("html.disable", Boolean.TRUE);
            }
        }
        if (c instanceof JTable) {
            noHtmlRenderers((JTable) c);
        }
        if (c instanceof Container) {
            for (Component k : ((Container) c).getComponents()) {
                noHtml(k);
            }
        }
    }

    static void noHtmlRenderers(JTable t) {
        for (Class<?> k : new Class<?>[] {Object.class, String.class, Number.class, Boolean.class}) {
            Object r = t.getDefaultRenderer(k);
            if (r instanceof JComponent) {
                ((JComponent) r).putClientProperty("html.disable", Boolean.TRUE);
            }
        }
        if (t.getTableHeader() != null && t.getTableHeader().getDefaultRenderer() instanceof JComponent) {
            ((JComponent) t.getTableHeader().getDefaultRenderer()).putClientProperty("html.disable", Boolean.TRUE);
        }
    }

    JComponent component() {
        return root;
    }

    /** Unload: stop the timer and every worker (a running scan or upload is interrupted). */
    void stop() {
        refresh.stop();
        pool.shutdownNow();
        try {
            pool.awaitTermination(1, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    boolean stopped() {
        return !refresh.isRunning() && pool.isShutdown();
    }

    // ================================================================== helpers

    private static final class Item {
        final long id;
        final String label;
        final Map<String, Object> raw;

        Item(long id, String label, Map<String, Object> raw) {
            this.id = id;
            this.label = label;
            this.raw = raw;
        }

        @Override
        public String toString() {
            return Plain.text(label);
        }
    }

    private String msg(Throwable e) {
        return Redact.line(e.getMessage() == null ? e.toString() : e.getMessage(), settings.token(), 300);
    }

    /** Run off the Swing thread; report the outcome in {@code status}. */
    private <T> void bg(JLabel status, String what, Callable<T> work, Consumer<T> done) {
        status.setText(what + "...");
        pool.submit(() -> {
            try {
                T v = work.call();
                SwingUtilities.invokeLater(() -> {
                    status.setText(what + ": done");
                    done.accept(v);
                });
            } catch (Throwable e) {
                // Burp does not report exceptions on an extension's own threads: an expected API
                // refusal goes to Output, anything else also to the error stream with its trace.
                String m = msg(e);
                log.warn(what + " failed: " + m);
                if (!(e instanceof ApiException)) {
                    log.error(what + " failed unexpectedly", e);
                }
                SwingUtilities.invokeLater(() -> status.setText(what + " failed: " + m));
            }
        });
    }

    private long deviceId() {
        Item it = (Item) devices.getSelectedItem();
        return it == null ? 0 : it.id;
    }

    private long runId() {
        Item it = (Item) runs.getSelectedItem();
        return it == null ? 0 : it.id;
    }

    private static JPanel row(JComponent... cs) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
        for (JComponent c : cs) {
            p.add(c);
        }
        return p;
    }

    private static JButton button(String text, Runnable r) {
        JButton b = new JButton(text);
        b.addActionListener(e -> r.run());
        return b;
    }

    // ================================================================== Settings

    private JComponent settingsPanel() {
        JTextField base = new JTextField(settings.baseUrl(), 36);
        JPasswordField token = new JPasswordField(36);
        JCheckBox remember = new JCheckBox("Remember the token in Burp's settings on this machine", settings.remember());
        JCheckBox local = new JCheckBox("Allow http://localhost (development only; real platforms are https)",
                settings.allowLocalhost());
        JCheckBox viaBurp = new JCheckBox("Send Privara API calls through Burp's networking (upstream proxy, "
                + "SOCKS and TLS settings apply)", settings.viaBurp());
        JLabel viaBurpNote = new JLabel("  When ticked, Burp's Logger records these calls, including your token "
                + "in the Authorization header, and other extensions' HTTP handlers see them.");
        JLabel tokenState = new JLabel(settings.tokenState());
        JLabel status = new JLabel(" ");
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(4, 6, 4, 6);
        g.anchor = GridBagConstraints.WEST;
        g.gridx = 0;
        g.gridy = 0;
        p.add(new JLabel("Privara base URL"), g);
        g.gridx = 1;
        p.add(base, g);
        g.gridx = 0;
        g.gridy++;
        p.add(new JLabel("Your API token"), g);
        g.gridx = 1;
        p.add(token, g);
        g.gridx = 2;
        p.add(tokenState, g);
        g.gridx = 1;
        g.gridy++;
        p.add(remember, g);
        g.gridy++;
        p.add(local, g);
        g.gridy++;
        p.add(viaBurp, g);
        g.gridy++;
        p.add(viaBurpNote, g);
        g.gridy++;
        p.add(row(
                button("Save", () -> {
                    try {
                        settings.save(base.getText(), new String(token.getPassword()), local.isSelected(),
                                remember.isSelected());
                        settings.setViaBurp(viaBurp.isSelected());
                        token.setText("");
                        base.setText(settings.baseUrl());
                        tokenState.setText(settings.tokenState());
                        status.setText("saved");
                    } catch (IllegalArgumentException e) {
                        status.setText(msg(e));
                    }
                }),
                button("Test connection", () -> bg(status, "Test connection", client::whoami,
                        w -> status.setText("signed in as " + Json.str(w.get("username"))))),
                button("Forget token", () -> {
                    settings.forgetToken();
                    forger.gate().setOn(false);
                    tokenState.setText(settings.tokenState());
                    status.setText("token forgotten; forging switched off");
                }),
                button("Use this Kali's link", () -> {
                    KaliLink.Result r = settings.useLink();
                    forger.gate().setOn(false);
                    tokenState.setText(settings.tokenState());
                    if (r != null && r.ok()) {
                        status.setText("using this Kali's Privara link; forging switched off");
                    } else if (r != null && r.present) {
                        status.setText("typed token dropped, but the link is not usable: " + r.problem);
                    } else {
                        status.setText("typed token dropped; there is no Privara link on this machine "
                                + "(it exists only on a Privara cloud Kali with the link on)");
                    }
                })), g);
        g.gridy++;
        p.add(status, g);
        g.gridy++;
        JTextArea help = new JTextArea(
                "On a Privara cloud Kali you need no token: the extension uses this Kali's Privara link.\n"
                + "Elsewhere, create a token on the platform: API page (sidebar) -> Generate token.\n"
                + "A token typed here always wins over the link; 'Use this Kali's link' goes back to it.\n"
                + "The token is sent ONLY to the base URL above, only in the Authorization header, and\n"
                + "redirects are never followed. By default it goes with Java's own HTTP client, never through\n"
                + "Burp, so it is never in Proxy history or Logger; tick 'through Burp's networking' if you\n"
                + "need Burp's upstream proxy (then Logger shows the calls). Nothing is sent until you click.\n"
                + "It is never written to Burp's output. Unticking 'Remember' keeps it for this Burp session only.\n"
                + "Version " + Version.VERSION + ".");
        help.setEditable(false);
        help.setOpaque(false);
        p.add(help, g);
        JPanel outer = new JPanel(new BorderLayout());
        outer.add(p, BorderLayout.NORTH);
        return outer;
    }

    // ================================================================== Device & API map

    private JComponent devicePanel() {
        devices.addActionListener(e -> {
            if (!fillingDevices) {
                deviceChosen(deviceId());
            }
        });
        endpointTable.setAutoCreateRowSorter(true);
        showOutside.addActionListener(e -> endpointModel.reload());
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.add(row(new JLabel("iOS Analysis device"), devices, button("Refresh devices", this::loadDevices)));
        top.add(row(button("Upload an app (.ipa)...", this::uploadApp), new JLabel("uploaded file on the device"), uploadPath));
        top.add(row(new JLabel("Analysis"), op, button("Run on that file", this::runOp)));
        top.add(row(new JLabel("Run"), runs, button("Refresh runs", this::loadRuns),
                button("Import API map", this::importMap)));
        top.add(row(deviceStatus));
        top.add(row(showOutside));
        top.add(row(button("Add to site map", this::addToSiteMap),
                button("Add in-scope hosts to target scope", this::addToScope),
                button("Send selected to Repeater", this::sendToRepeater)));
        top.add(row(mapStatus));
        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(new JScrollPane(endpointTable), BorderLayout.CENTER);
        return p;
    }

    private void loadDevices() {
        bg(deviceStatus, "Loading devices", client::devices, this::fillDevices);
    }

    /**
     * Refill the device list. The listener is held off while refilling: otherwise the first addItem
     * selects the first device, which resets the forge gate (forging OFF, hosts cleared) and
     * overwrites the saved device, even when the same device ends up selected again.
     */
    void fillDevices(List<Map<String, Object>> list) {
        long want = forger.device() > 0 ? forger.device() : settings.deviceId();
        int n = 0;
        fillingDevices = true;
        try {
            devices.removeAllItems();
            for (Map<String, Object> d : list) {
                if (!PrivaraClient.isAnalysisDevice(d)) {
                    continue;
                }
                long id = Json.num(d.get("id"), 0);
                String scope = Json.str(d.get("scope"));
                Item it = new Item(id, Json.str(d.get("name")) + " (#" + id + ", " + Json.str(d.get("status"))
                        + ", scope " + (scope.isEmpty() ? "none" : scope) + ")", d);
                devices.addItem(it);
                if (id == want) {
                    devices.setSelectedItem(it);
                }
                n++;
            }
        } finally {
            fillingDevices = false;
        }
        deviceChosen(deviceId());
        deviceStatus.setText(n == 0 ? "no iOS Analysis device on this account (or iOS Analysis is not enabled)"
                : n + " iOS Analysis device(s)");
    }

    /** A different device: forge state, runs, the imported map and findings were the old device's. */
    private void deviceChosen(long id) {
        if (id <= 0 || id == forger.device()) {
            return;
        }
        forger.setDevice(id);
        forger.gate().reset("a different device was chosen: load its forge status");
        settings.setDeviceId(id);
        forgeOn.setSelected(false);
        hostModel.reload();
        runs.removeAllItems();
        map = null;
        endpointModel.reload();
        findings = null;
        findingModel.fireTableDataChanged();
        findingDetail.setText("");
        findingStatus.setText(" ");
        mapStatus.setText("device changed: refresh its runs, then import");
    }

    private void uploadApp() {
        long iid = deviceId();
        if (iid <= 0) {
            deviceStatus.setText("choose a device first");
            return;
        }
        JFileChooser fc = new JFileChooser();
        // BApp criterion: dialogs are children of Burp's main frame (right monitor, right z-order)
        if (fc.showOpenDialog(api.userInterface().swingUtils().suiteFrame()) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File f = fc.getSelectedFile();
        bg(deviceStatus, "Uploading " + f.getName(), () -> client.upload(iid, f.toPath()),
                r -> {
                    uploadPath.setText(Json.str(r.get("path")));
                    deviceStatus.setText("uploaded " + Json.str(r.get("filename")) + " (" + Json.str(r.get("size_mb"))
                            + " MB); now run apimap on it");
                });
    }

    private void runOp() {
        long iid = deviceId();
        String path = uploadPath.getText().trim();
        String o = (String) op.getSelectedItem();
        if (iid <= 0 || path.isEmpty()) {
            deviceStatus.setText("choose a device and an uploaded file first");
            return;
        }
        bg(deviceStatus, "Running " + o, () -> client.scan(iid, o, path), r -> {
            deviceStatus.setText(o + (Json.bool(r.get("ok")) ? " finished" : " failed: " + Json.str(r.get("error")))
                    + "; refreshing runs");
            loadRuns();
        });
    }

    private void loadRuns() {
        long iid = deviceId();
        if (iid <= 0) {
            deviceStatus.setText("choose a device first");
            return;
        }
        bg(deviceStatus, "Loading runs", () -> client.runs(iid), list -> {
            runs.removeAllItems();
            for (Map<String, Object> r : list) {
                if (!Json.bool(r.get("ok"))) {
                    continue;
                }
                runs.addItem(new Item(Json.num(r.get("id"), 0), "#" + Json.str(r.get("seq")) + " "
                        + Json.str(r.get("op")) + " " + Json.str(r.get("artifact")), r));
            }
            deviceStatus.setText(runs.getItemCount() + " successful run(s); pick one and import");
        });
    }

    private void importMap() {
        long iid = deviceId();
        long rid = runId();
        if (iid <= 0 || rid <= 0) {
            mapStatus.setText("choose a device and a run first");
            return;
        }
        bg(mapStatus, "Importing the API map", () -> ApiMap.fromBundle(client.bundle(iid, rid)), m -> {
            map = m;
            endpointModel.reload();
            mapStatus.setText(m.endpoints().size() + " endpoint(s) on " + m.hosts().size() + " first-party host(s); "
                    + m.inScopeHosts().size() + " host(s) in the engagement scope "
                    + m.inScopeHosts() + (m.notes().isEmpty() ? "" : " -- " + String.join("; ", m.notes())));
        });
    }

    private List<ApiMap.Endpoint> visible() {
        List<ApiMap.Endpoint> out = new ArrayList<>();
        if (map != null) {
            out.addAll(showOutside.isSelected() ? map.endpoints() : map.inScopeEndpoints());
        }
        return out;
    }

    private List<ApiMap.Endpoint> selectedOrAll() {
        List<ApiMap.Endpoint> v = visible();
        int[] rows = endpointTable.getSelectedRows();
        if (rows.length == 0) {
            return v;
        }
        List<ApiMap.Endpoint> out = new ArrayList<>();
        for (int r : rows) {
            out.add(v.get(endpointTable.convertRowIndexToModel(r)));
        }
        return out;
    }

    private HttpRequest stub(ApiMap.Endpoint e) {
        HttpService svc = HttpService.httpService(e.host, e.port(), e.secure());
        return HttpRequest.httpRequest(svc, e.rawRequest());
    }

    private void addToSiteMap() {
        List<ApiMap.Endpoint> eps = selectedOrAll();
        int n = 0;
        for (ApiMap.Endpoint e : eps) {
            String note = "Privara static map (not observed on the wire)"
                    + (e.inScope ? "" : " -- OUTSIDE the engagement scope");
            Annotations a = Annotations.annotations(note, e.inScope ? HighlightColor.CYAN : HighlightColor.GRAY);
            HttpRequestResponse rr;
            try {
                rr = HttpRequestResponse.httpRequestResponse(stub(e), null, a);
                api.siteMap().add(rr);
            } catch (RuntimeException ex) {
                // Some Burp builds want a response object; an empty one marks it as never requested.
                rr = HttpRequestResponse.httpRequestResponse(stub(e), HttpResponse.httpResponse(), a);
                api.siteMap().add(rr);
            }
            n++;
        }
        mapStatus.setText(n + " request stub(s) added to Target > Site map");
    }

    private void addToScope() {
        if (map == null) {
            mapStatus.setText("import the API map first");
            return;
        }
        if (map.inScopeHosts().isEmpty()) {
            mapStatus.setText("nothing added: no host is in the device's engagement scope (assign a scope on the "
                    + "platform, re-run apimap or re-import)");
            return;
        }
        Set<String> added = new HashSet<>();
        for (String h : map.inScopeHosts()) {
            String clean = Hosts.clean(h);
            if (clean == null) {
                continue;
            }
            boolean http = false;
            for (ApiMap.Endpoint e : map.endpoints()) {
                if (e.host.equals(clean) && !e.secure()) {
                    http = true;
                }
            }
            api.scope().includeInScope("https://" + clean + "/");
            if (http) {
                api.scope().includeInScope("http://" + clean + "/");
            }
            added.add(clean);
        }
        mapStatus.setText("added to Target > Scope: " + added + " (only hosts the platform found in the engagement scope)");
    }

    private void sendToRepeater() {
        int[] rows = endpointTable.getSelectedRows();
        if (rows.length == 0) {
            mapStatus.setText("select one or more rows first");
            return;
        }
        List<ApiMap.Endpoint> v = visible();
        int sent = 0;
        int refused = 0;
        for (int r : rows) {
            ApiMap.Endpoint e = v.get(endpointTable.convertRowIndexToModel(r));
            if (!e.inScope) {
                refused++;
                continue;
            }
            api.repeater().sendToRepeater(stub(e), "Privara " + e.method + " " + e.path);
            sent++;
        }
        mapStatus.setText(sent + " sent to Repeater" + (refused > 0 ? "; " + refused
                + " refused: outside the device's engagement scope" : ""));
    }

    private final class EndpointModel extends AbstractTableModel {
        private final String[] cols = {"In scope", "Method", "Host", "Path", "Query parameters", "Found in"};
        private List<ApiMap.Endpoint> rows = new ArrayList<>();

        void reload() {
            rows = visible();
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return cols.length;
        }

        @Override
        public String getColumnName(int c) {
            return cols[c];
        }

        @Override
        public Object getValueAt(int r, int c) {
            return Plain.cell(raw(r, c));
        }

        private Object raw(int r, int c) {
            ApiMap.Endpoint e = rows.get(r);
            switch (c) {
                case 0: return e.inScope ? "yes" : "NO";
                case 1: return e.method;
                case 2: return e.host;
                case 3: return e.path;
                case 4: return String.join(", ", e.query);
                default: return e.note;
            }
        }
    }

    // ================================================================== Request forging

    private JComponent forgePanel() {
        forgeOn.addActionListener(e -> {
            forger.gate().setOn(forgeOn.isSelected());
            log.info("request forging " + (forgeOn.isSelected() ? "ON" : "OFF"));
        });
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        JTextArea note = new JTextArea(
                "Analyst-assisted: a harness for the app is set up on the platform with Privara's help and VERIFIED there.\n"
                + "Only requests to a host you enable below are sent to the platform's sign API; all other traffic is untouched\n"
                + "and never leaves Burp. Enabling a host asks the platform whether it is in the iOS device's engagement scope;\n"
                + "the platform checks again on every sign, rate-limits and audits it. A request that cannot be signed goes out unsigned.");
        note.setEditable(false);
        note.setOpaque(false);
        top.add(row(note));
        top.add(row(new JLabel("Harness id (empty = the device's selected one)"), harnessId,
                button("Load forge status", this::loadForge)));
        top.add(row(harnessLabel));
        top.add(row(forgeOn));
        top.add(row(new JLabel("Add a host under a wildcard HOSTS entry"), wildcardHost,
                button("Add and check scope", () -> enableHost(wildcardHost.getText().trim()))));
        top.add(row(forgeCounters));
        top.add(row(forgeStatus));
        JTable events = new JTable(eventModel);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(hostTable), new JScrollPane(events));
        split.setResizeWeight(0.4);
        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(split, BorderLayout.CENTER);
        return p;
    }

    private void loadForge() {
        long iid = deviceId();
        if (iid <= 0) {
            forgeStatus.setText("choose a device in 'Device & API map' first");
            return;
        }
        long want = 0;
        String t = harnessId.getText().trim();
        if (!t.isEmpty()) {
            try {
                want = Long.parseLong(t);
            } catch (NumberFormatException e) {
                forgeStatus.setText("the harness id is a number");
                return;
            }
        }
        long w = want;
        bg(forgeStatus, "Loading forge status", () -> client.forgeStatus(iid), st -> {
            forger.setDevice(iid);
            forger.gate().loadStatus(st, w);
            Map<String, Object> lim = Json.obj(st.get("limits"));
            harnessLabel.setText(forger.gate().harnessNote() + "; HOSTS " + forger.gate().patterns()
                    + "; device scope '" + Json.str(st.get("scope")) + "'; limit " + Json.str(lim.get("per_minute"))
                    + "/min, burst " + Json.str(lim.get("burst")));
            hostModel.reload();
        });
    }

    private void enableHost(String host) {
        long iid = deviceId();
        String h = Hosts.clean(host);
        if (iid <= 0 || h == null) {
            forgeStatus.setText("choose a device and give a plain host name");
            return;
        }
        if (!Hosts.allowed(h, forger.gate().patterns())) {
            // Not even asked: a host outside the harness's HOSTS is never sent to the platform.
            forgeStatus.setText(h + " is not one of the harness's HOSTS " + forger.gate().patterns());
            return;
        }
        bg(forgeStatus, "Checking " + h + " against the engagement scope", () -> client.scopeCheck(iid, h), res -> {
            String why = forger.gate().enable(h, res);
            forgeStatus.setText(why == null ? h + " enabled for signing" : h + " NOT enabled: " + why);
            hostModel.reload();
        });
    }

    private void refreshForge() {
        forgeCounters.setText("signed " + forger.signed.get() + " | failed " + forger.failed.get()
                + " | passed through " + forger.skipped.get()
                + (forger.lastError().isEmpty() ? "" : " | last problem: " + Redact.line(forger.lastError(), settings.token(), 200)));
        if (forgeOn.isSelected() != forger.gate().isOn()) {
            forgeOn.setSelected(forger.gate().isOn());   // the gate switched itself off (401, kill switch)
        }
        eventModel.reload();
        hostModel.fireTableDataChanged();
    }

    private final class HostModel extends AbstractTableModel {
        private final String[] cols = {"Sign", "Host", "Scope", "Note"};
        private List<ForgeGate.HostState> rows = new ArrayList<>();

        void reload() {
            rows = forger.gate().hostStates();
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return cols.length;
        }

        @Override
        public String getColumnName(int c) {
            return cols[c];
        }

        @Override
        public Class<?> getColumnClass(int c) {
            return c == 0 ? Boolean.class : String.class;
        }

        @Override
        public boolean isCellEditable(int r, int c) {
            return c == 0;
        }

        @Override
        public Object getValueAt(int r, int c) {
            return Plain.cell(raw(r, c));
        }

        private Object raw(int r, int c) {
            ForgeGate.HostState s = rows.get(r);
            switch (c) {
                case 0: return s.enabled;
                case 1: return s.host;
                case 2: return s.scope;
                default: return s.note;
            }
        }

        @Override
        public void setValueAt(Object v, int r, int c) {
            ForgeGate.HostState s = rows.get(r);
            if (Boolean.TRUE.equals(v)) {
                enableHost(s.host);
            } else {
                forger.gate().disable(s.host, "disabled by you");
                reload();
            }
        }
    }

    private final class EventModel extends AbstractTableModel {
        private final String[] cols = {"Time", "Method", "Host", "Path", "Result", "Detail"};
        private final SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss");
        private List<Forger.Event> rows = new ArrayList<>();

        void reload() {
            rows = forger.events();
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return cols.length;
        }

        @Override
        public String getColumnName(int c) {
            return cols[c];
        }

        @Override
        public Object getValueAt(int r, int c) {
            return Plain.cell(raw(r, c));
        }

        private Object raw(int r, int c) {
            Forger.Event e = rows.get(r);
            switch (c) {
                case 0: return fmt.format(new Date(e.at));
                case 1: return e.method;
                case 2: return e.host;
                case 3: return e.path;
                case 4: return e.kind.name().toLowerCase();
                default: return Redact.line(e.reason, settings.token(), 300);
            }
        }
    }

    // ================================================================== Findings

    private JComponent findingsPanel() {
        findingDetail.setEditable(false);
        findingDetail.setLineWrap(true);
        findingDetail.setWrapStyleWord(true);
        findingTable.setAutoCreateRowSorter(true);
        findingTable.getSelectionModel().addListSelectionListener(e -> showFinding());
        boolean pro = api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL;
        JButton raise = button("Raise as Burp issues", this::raiseIssues);
        raise.setEnabled(pro);
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.add(row(button("Load findings for the chosen run", this::loadFindings), raise,
                new JLabel(pro ? "(selected rows, or all; attached to the first in-scope host of the imported map)"
                        : "Raising Burp issues needs Burp Professional; the findings are listed here.")));
        top.add(row(new JLabel(Findings.STATIC_NOTE)));
        top.add(row(findingStatus));
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(findingTable),
                new JScrollPane(findingDetail));
        split.setResizeWeight(0.6);
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
        p.add(top, BorderLayout.NORTH);
        p.add(split, BorderLayout.CENTER);
        return p;
    }

    private void loadFindings() {
        long iid = deviceId();
        long rid = runId();
        if (iid <= 0 || rid <= 0) {
            findingStatus.setText("choose a device and a run in 'Device & API map' first");
            return;
        }
        bg(findingStatus, "Loading findings", () -> Findings.parse(client.report(iid, rid)), f -> {
            findings = f;
            findingModel.fireTableDataChanged();
            findingStatus.setText(f.list().size() + " finding(s) for " + f.app() + " (" + f.artifact() + ")"
                    + (f.emptyReason().isEmpty() ? "" : " -- " + f.emptyReason()));
        });
    }

    private void showFinding() {
        int r = findingTable.getSelectedRow();
        if (findings == null || r < 0) {
            return;
        }
        Findings.Finding f = findings.list().get(findingTable.convertRowIndexToModel(r));
        StringBuilder b = new StringBuilder();
        b.append(f.title).append("\n\n").append(Findings.STATIC_NOTE).append("\n\n").append(f.description)
                .append("\n\nRemediation: ").append(f.remediation)
                .append("\n\n").append(f.id).append("  ").append(f.code).append("  ").append(f.masvs).append("  ")
                .append(f.cwe).append("  confidence ").append(f.confidence);
        for (String e : f.evidence) {
            b.append("\nevidence: ").append(e);
        }
        for (String l : f.limits) {
            b.append("\nlimit: ").append(l);
        }
        findingDetail.setText(b.toString());
        findingDetail.setCaretPosition(0);
    }

    private void raiseIssues() {
        if (findings == null) {
            findingStatus.setText("load the findings first");
            return;
        }
        if (map == null || map.inScopeHosts().isEmpty()) {
            findingStatus.setText("import the API map first: issues are attached to a host in the engagement scope");
            return;
        }
        String base = "https://" + map.inScopeHosts().get(0) + "/";
        List<Findings.Finding> pick = new ArrayList<>();
        int[] rows = findingTable.getSelectedRows();
        if (rows.length == 0) {
            pick.addAll(findings.list());
        } else {
            for (int r : rows) {
                pick.add(findings.list().get(findingTable.convertRowIndexToModel(r)));
            }
        }
        int n = 0;
        for (Findings.Finding f : pick) {
            if (!raised.add(f.id)) {
                continue;                      // once per Burp session per finding
            }
            AuditIssue issue = AuditIssue.auditIssue(f.issueName(), f.issueDetailHtml(findings.app()),
                    f.remediationHtml(), base, AuditIssueSeverity.valueOf(f.burpSeverity()),
                    AuditIssueConfidence.valueOf(f.burpConfidence()),
                    Findings.esc("Reported by Privara iOS Analysis from a static analysis of the app bundle."),
                    "", AuditIssueSeverity.valueOf(f.burpSeverity()));
            api.siteMap().add(issue);
            n++;
        }
        findingStatus.setText(n + " issue(s) raised on " + base + " (static analysis, tentative)");
    }

    private final class FindingModel extends AbstractTableModel {
        private final String[] cols = {"Severity", "Title", "Code", "Confidence", "ID"};

        @Override
        public int getRowCount() {
            return findings == null ? 0 : findings.list().size();
        }

        @Override
        public int getColumnCount() {
            return cols.length;
        }

        @Override
        public String getColumnName(int c) {
            return cols[c];
        }

        @Override
        public Object getValueAt(int r, int c) {
            return Plain.cell(raw(r, c));
        }

        private Object raw(int r, int c) {
            Findings.Finding f = findings.list().get(r);
            switch (c) {
                case 0: return f.severity;
                case 1: return f.title;
                case 2: return f.code;
                case 3: return f.confidence;
                default: return f.id;
            }
        }
    }
}
