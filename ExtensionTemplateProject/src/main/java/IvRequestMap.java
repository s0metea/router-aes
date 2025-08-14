import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

class IvRequestMap {
    private static final Map<String, Integer> IV_TO_MSG = new ConcurrentHashMap<>();
    private static final Map<Integer, HttpRequest> MSG_TO_REQ = new ConcurrentHashMap<>();

    static void remember(String ivB64, int messageId, HttpRequest req) {
        if (ivB64 == null || ivB64.isEmpty() || req == null) return;
        IV_TO_MSG.put(ivB64, messageId);
        MSG_TO_REQ.put(messageId, req);
    }

    static Integer messageIdForIv(String ivB64) {
        if (ivB64 == null) return null;
        return IV_TO_MSG.get(ivB64);
    }

    static HttpRequest requestForMessageId(int messageId) {
        return MSG_TO_REQ.get(messageId);
    }

    static void clearForIv(String ivB64) {
        Integer msg = IV_TO_MSG.remove(ivB64);
        if (msg != null) MSG_TO_REQ.remove(msg);
    }
}