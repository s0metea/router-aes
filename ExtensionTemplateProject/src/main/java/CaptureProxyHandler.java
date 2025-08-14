import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.http.message.responses.HttpResponse;

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

            // Create a synthetic response to show in the UI with the payload
            HttpResponse displayed = HttpResponse.httpResponse(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + payloadJson
            );
            HttpResponse original = HttpResponse.httpResponse(
                    "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
            );

            panel.addEntry(new DecryptEntry(System.currentTimeMillis(), interceptedRequest, original, displayed, true, "capture"));

            // Drop request so it doesn't hit the backend
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
}
