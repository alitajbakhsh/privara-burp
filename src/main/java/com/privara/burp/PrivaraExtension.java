package com.privara.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import com.privara.burp.core.ForgeGate;
import com.privara.burp.core.Forger;
import com.privara.burp.core.JdkTransport;
import com.privara.burp.core.KaliLink;
import com.privara.burp.core.PrivaraClient;
import com.privara.burp.core.SafeLog;
import com.privara.burp.core.Transport;
import com.privara.burp.core.Version;

import java.util.ArrayList;
import java.util.List;

/**
 * Privara iOS kit for Burp Suite (Montoya API).
 *
 * Talks ONLY to the Privara public API, with the customer's own API token (or, on a Privara cloud
 * Kali with the link on, this Kali's link token: see KaliLink), over HTTPS:
 * <ul>
 *   <li>pick an iOS Analysis device, upload an app, run apimap / cloudcheck / deeplinks;</li>
 *   <li>import the API map: request stubs into the site map, the first-party hosts the platform
 *       found IN the device's engagement scope into Burp's target scope, any in-scope entry to
 *       Repeater;</li>
 *   <li>request forging: requests to an enabled host of a verified harness are signed through
 *       the platform's sign API before Burp sends them (off until switched on);</li>
 *   <li>findings: the platform's findings report in a tab, and, in Burp Professional, as audit
 *       issues marked as static analysis.</li>
 * </ul>
 *
 * Nothing is sent at load time: the first network call is the tester's own click. Unloading
 * switches forging off, stops the tab's timer and workers, closes the HTTP client and deregisters
 * the handler and the tab.
 */
public final class PrivaraExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Privara iOS kit");
        KaliLink.Source link = new KaliLink.Source(KaliLink.path(), () -> System.currentTimeMillis() / 1000);
        BurpSettings settings = new BurpSettings(api.persistence().preferences(), link);
        SafeLog log = new SafeLog(api.logging()::logToOutput, api.logging()::logToError, settings::token);
        JdkTransport direct = new JdkTransport();
        Transport viaBurp = new BurpTransport(api.http());
        PrivaraClient client = new PrivaraClient(settings::config, () -> settings.viaBurp() ? viaBurp : direct);
        client.onUnauthorized(settings::relink);
        ForgeGate gate = new ForgeGate(System::currentTimeMillis);
        Forger forger = new Forger(client, gate, log);
        forger.setDevice(settings.deviceId());
        List<Registration> regs = new ArrayList<>();
        regs.add(api.http().registerHttpHandler(new ForgeHttpHandler(forger)));
        PrivaraTab tab = new PrivaraTab(api, settings, client, forger, log);
        regs.add(api.userInterface().registerSuiteTab("Privara", tab.component()));
        api.extension().registerUnloadingHandler(() -> {
            gate.setOn(false);
            tab.stop();
            direct.close();
            viaBurp.close();
            for (Registration r : regs) {
                try {
                    if (r != null && r.isRegistered()) {
                        r.deregister();
                    }
                } catch (RuntimeException e) {
                    log.error("deregistering on unload failed", e);
                }
            }
        });
        log.info("Privara iOS kit " + Version.VERSION + " loaded; request forging is OFF until you "
                + "switch it on in the Privara tab");
        if (settings.usingLink()) {
            log.info("connected through this Kali's Privara link; a token typed in the Privara tab overrides it");
        }
    }
}
