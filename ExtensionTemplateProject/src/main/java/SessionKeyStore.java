import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Stores latest sessionkey per host observed from server responses.
 */
class SessionKeyStore {
    private static final Map<String, String> HOST_TO_TOKEN = new ConcurrentHashMap<>();

    static void put(String host, String token) {
        if (host == null || host.isEmpty() || token == null || token.isEmpty()) return;
        HOST_TO_TOKEN.put(host.toLowerCase(), token);
    }

    static String get(String host) {
        if (host == null || host.isEmpty()) return null;
        return HOST_TO_TOKEN.get(host.toLowerCase());
    }
}
