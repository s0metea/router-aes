import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

class CaptureProxyHandler implements ProxyRequestHandler {
    private final MontoyaApi api;
    private final DecryptTabPanel panel;

    CaptureProxyHandler(MontoyaApi api, DecryptTabPanel panel) {
        this.api = api;
        this.panel = panel;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        // We are not changing initial intercept behavior; just follow user rules
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        try {
            String path = safe(() -> interceptedRequest.pathWithoutQuery());
            if (path == null || !path.startsWith("/__capture__")) {
                return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
            }

            String body = safe(() -> interceptedRequest.bodyToString());
            String payloadJson = null;
            if (body != null && !body.isEmpty()) {
                payloadJson = body;
            } else {
                String query = safe(() -> interceptedRequest.query());
                Map<String, String> q = parseQuery(query);
                String d = q.get("d");
                if (d != null) {
                    try {
                        String decoded = new String(Base64.getDecoder().decode(d), StandardCharsets.ISO_8859_1);
                        byte[] bytes = decoded.getBytes(StandardCharsets.ISO_8859_1);
                        payloadJson = new String(bytes, StandardCharsets.UTF_8);
                    } catch (Exception ex) {
                        payloadJson = "{}";
                    }
                }
            }
            if (payloadJson == null) payloadJson = "{}";

            // Parse JSON payload, correlate by IV, and update displayed request body with plaintext
            try {
                String iv = extractJsonString(payloadJson, "ivB64");
                if (iv == null) iv = extractJsonString(payloadJson, "iv");
                if (iv == null) iv = extractJsonStringNested(payloadJson, "ivB64");
                if (iv == null) iv = extractJsonStringNested(payloadJson, "iv");
                try { if (iv != null) panel.setIv(iv); } catch (Throwable ignored) {}

                // plaintext may be sent as 'plaintext' (full string) or fallback to preview fields if not present
                String plaintext = extractJsonString(payloadJson, "plaintext");
                if (plaintext == null) plaintext = extractJsonStringNested(payloadJson, "plaintext");
                if (plaintext == null) plaintext = extractJsonString(payloadJson, "plaintextPreview");
                if (plaintext == null) plaintext = extractJsonStringNested(payloadJson, "plaintextPreview");

                if (iv != null && plaintext != null) {
                    Integer msgId = IvRequestMap.messageIdForIv(iv);
                    if (msgId != null) {
                        var origReq = IvRequestMap.requestForMessageId(msgId);
                        if (origReq != null) {
                            var displayedReq = origReq.withBody(plaintext).withRemovedHeader("Content-Length");
                            RequestDisplayStore.put(msgId, displayedReq);
                        }
                        IvRequestMap.clearForIv(iv);
                    } else {
                        // No mapping yet: store plaintext to apply once the request mapping is remembered
                        IvRequestMap.putPendingPlaintext(iv, plaintext);
                    }
                }
            } catch (Throwable ignored) {}

            // Drop request so it doesn't hit the backend and don't log it to the table
            return ProxyRequestToBeSentAction.drop();
        } catch (Throwable t) {
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        }
    }

    private static Map<String, String> parseQuery(String query) {
        Map<String, String> map = new HashMap<>();
        if (query == null) return map;
        for (String part : query.split("&")) {
            if (part.isEmpty()) continue;
            int eq = part.indexOf('=');
            if (eq < 0) {
                map.put(urlDecode(part), "");
            } else {
                map.put(urlDecode(part.substring(0, eq)), urlDecode(part.substring(eq + 1)));
            }
        }
        return map;
    }

    private static String urlDecode(String s) {
        try { return URLDecoder.decode(s, StandardCharsets.UTF_8); } catch (Exception e) { return s; }
    }

    private static <T> T safe(SupplierWithEx<T> f) {
        try { return f.get(); } catch (Throwable t) { return null; }
    }
    interface SupplierWithEx<T> { T get(); }

    private static String extractJsonString(String json, String key) {
        if (json == null || key == null) return null;
        String needle = "\"" + key + "\"";
        int len = json.length();
        int idx = 0;
        while (idx < len) {
            int k = json.indexOf(needle, idx);
            if (k < 0) return null;
            int i = k + needle.length();
            // skip whitespace
            while (i < len && Character.isWhitespace(json.charAt(i))) i++;
            if (i >= len || json.charAt(i) != ':') { idx = k + 1; continue; }
            i++;
            while (i < len && Character.isWhitespace(json.charAt(i))) i++;
            if (i >= len || json.charAt(i) != '"') { idx = k + 1; continue; }
            i++; // start of string value
            StringBuilder sb = new StringBuilder();
            while (i < len) {
                char c = json.charAt(i++);
                if (c == '\\') {
                    if (i >= len) break;
                    char e = json.charAt(i++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            if (i + 3 < len) {
                                String hex = json.substring(i, i + 4);
                                try {
                                    int code = Integer.parseInt(hex, 16);
                                    sb.append((char) code);
                                } catch (Exception ex) { /* ignore bad hex */ }
                                i += 4;
                            }
                            break;
                        default:
                            sb.append(e);
                    }
                } else if (c == '"') {
                    return sb.toString();
                } else {
                    sb.append(c);
                }
            }
            // malformed, continue searching further occurrences
            idx = k + 1;
        }
        return null;
    }

    private static String extractJsonStringNested(String json, String key) {
        // For simplicity, fallback to generic search anywhere in JSON
        return extractJsonString(json, key);
    }
}
