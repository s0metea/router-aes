import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Stores latest Session cookie per host observed from server responses.
 */
class SessionCookieStore {
    private static final Map<String, String> HOST_TO_COOKIE = new ConcurrentHashMap<>();

    static void put(String host, String cookieValue) {
        if (host == null || host.isEmpty() || cookieValue == null || cookieValue.isEmpty()) return;
        HOST_TO_COOKIE.put(host.toLowerCase(), cookieValue);
    }

    static String get(String host) {
        if (host == null || host.isEmpty()) return null;
        return HOST_TO_COOKIE.get(host.toLowerCase());
    }
}
