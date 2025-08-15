import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;
import java.util.logging.Level;
import java.util.logging.Logger;

class HookSettings {
    private static final Logger LOG = Logger.getLogger(HookSettings.class.getName());
    static final String PREF_KEY_HOOK_JS = "aes_decryptor.hook_js";
    static final String PREF_KEY_HOOK_PATH = "aes_decryptor.hook_path";
    static final String DEFAULT_HOOK_PATH = "/static/js/app.js";

    static String defaultHook() {
        return HookPayload.HOOK_JS;
    }

    static String getHook(Preferences prefs) {
        if (prefs == null) return defaultHook();
        String v = null;
        try { v = prefs.getString(PREF_KEY_HOOK_JS); } catch (Throwable t) { LOG.log(Level.FINE, "Failed to read hook JS from preferences: {0}", t.toString()); }
        if (v == null || v.trim().isEmpty()) return defaultHook();
        return v;
    }

    static void setHook(Preferences prefs, String js) {
        if (prefs == null) return;
        try { prefs.setString(PREF_KEY_HOOK_JS, js != null ? js : ""); } catch (Throwable t) { LOG.log(Level.FINE, "Failed to write hook JS to preferences: {0}", t.toString()); }
    }

    static String getHookPath(Preferences prefs) {
        if (prefs == null) return DEFAULT_HOOK_PATH;
        String v = null;
        try { v = prefs.getString(PREF_KEY_HOOK_PATH); } catch (Throwable t) { LOG.log(Level.FINE, "Failed to read hook path from preferences: {0}", t.toString()); }
        if (v == null || v.trim().isEmpty()) return DEFAULT_HOOK_PATH;
        return v.trim();
    }

    static void setHookPath(Preferences prefs, String path) {
        if (prefs == null) return;
        try { prefs.setString(PREF_KEY_HOOK_PATH, path != null ? path.trim() : ""); } catch (Throwable t) { LOG.log(Level.FINE, "Failed to write hook path to preferences: {0}", t.toString()); }
    }
}
