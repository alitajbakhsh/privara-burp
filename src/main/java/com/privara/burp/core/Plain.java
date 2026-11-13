package com.privara.burp.core;

/**
 * Text for a Swing label, table cell or list entry, never HTML.
 *
 * Swing renders any text that starts with {@code <html>} as HTML, in JLabel, JButton, the default
 * table cell renderer and the combo box renderer. Endpoint paths, host names, finding titles and
 * file names come from the analysed app (untrusted), so an app could ship a path such as
 * {@code <html><img src=http://attacker/>} and make Burp fetch a URL just by showing the table.
 * The tab sets {@code html.disable} on every component too; this is the second guard, for any
 * renderer that does not honour that property.
 */
public final class Plain {
    private Plain() {
    }

    /** The same test Swing uses (javax.swing.plaf.basic.BasicHTML.isHTMLString). */
    public static boolean isHtml(String s) {
        return s != null && s.length() >= 6 && s.charAt(0) == '<' && s.charAt(5) == '>'
                && s.substring(1, 5).equalsIgnoreCase("html");
    }

    /** The text unchanged, unless Swing would render it as HTML: then a leading space stops that. */
    public static String text(String s) {
        if (s == null) {
            return "";
        }
        return isHtml(s) ? " " + s : s;
    }

    /** For table models: strings go through {@link #text}, anything else is returned as it is. */
    public static Object cell(Object v) {
        return v instanceof String ? text((String) v) : v;
    }
}
