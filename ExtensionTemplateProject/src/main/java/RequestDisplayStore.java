import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Store to keep decrypted/pretty-printed versions of requests by messageId
 * until the corresponding response arrives.
 */
class RequestDisplayStore {
    private static final Map<Integer, HttpRequest> MAP = new ConcurrentHashMap<>();

    static void put(int messageId, HttpRequest displayedRequest) {
        if (displayedRequest == null) return;
        MAP.put(messageId, displayedRequest);
    }

    static HttpRequest take(int messageId) {
        return MAP.remove(messageId);
    }
}
