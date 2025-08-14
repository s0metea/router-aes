import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

class DecryptingHttpHandler implements HttpHandler {
    private final MontoyaApi api;
    private final DecryptTabPanel panel;

    private static final Pattern CONTENT_PATTERN = Pattern.compile("\\\"content\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");
    private static final Pattern IV_PATTERN = Pattern.compile("\\\"iv\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");

    DecryptingHttpHandler(MontoyaApi api, DecryptTabPanel panel) {
        this.api = api;
        this.panel = panel;
    }

    @Override
    public burp.api.montoya.http.handler.RequestToBeSentAction handleHttpRequestToBeSent(burp.api.montoya.http.handler.HttpRequestToBeSent requestToBeSent) {
        // We don't modify requests for this extension
        return burp.api.montoya.http.handler.RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        HttpResponse originalResp = responseReceived;
        var req = responseReceived.initiatingRequest();

        boolean shouldProcess = panel.isFeatureEnabled() && originMatches(panel.getOrigin(), safe(() -> req.url()));
        if (!shouldProcess) {
            // Only record entries when enabled and origin matches, otherwise just continue
            return ResponseReceivedAction.continueWith(originalResp);
        }

        String body = safe(() -> responseReceived.bodyToString());
        boolean decrypted = false;
        String note = "";
        HttpResponse resultResp = originalResp;

        if (body != null && body.length() > 0 && maybeJson(body)) {
            try {
                String content = extract(CONTENT_PATTERN, body);
                String iv = extract(IV_PATTERN, body);
                if (content != null && iv != null) {
                    byte[] key = AESCbcDecryptor.parseKey(panel.getAesKey());
                    byte[] ivBytes = AESCbcDecryptor.parseIv(iv);
                    if (key != null && ivBytes != null) {
                        String plain = AESCbcDecryptor.decryptBase64Content(content, key, ivBytes);
                        // The decrypted content is itself JSON; replace body with it and set content-type json
                        resultResp = resultResp.withBody(plain)
                                .withRemovedHeader("Content-Encoding")
                                .withRemovedHeader("Content-Length")
                                .withAddedHeader("Content-Type", "application/json");
                        decrypted = true;
                        note = "decrypted";
                    } else {
                        note = "missing key/iv";
                    }
                } else {
                    note = "no content/iv";
                }
            } catch (Exception ex) {
                note = "decrypt error: " + ex.getMessage();
            }
        } else {
            note = "not json";
        }

        panel.addEntry(new DecryptEntry(System.currentTimeMillis(), req, originalResp, resultResp, decrypted, note));
        return ResponseReceivedAction.continueWith(resultResp);
    }

    private boolean originMatches(String origin, String url) {
        if (origin == null || origin.isEmpty() || url == null) return false;
        // simple contains match to allow host or scheme://host prefix
        return url.contains(origin);
    }

    private static String extract(Pattern p, String text) {
        Matcher m = p.matcher(text);
        if (m.find()) return m.group(1);
        return null;
    }

    private static boolean maybeJson(String s) {
        String t = s.trim();
        return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"));
    }

    private static <T> T safe(SupplierWithEx<T> s) {
        try { return s.get(); } catch (Throwable t) { return null; }
    }

    interface SupplierWithEx<T> { T get(); }
}
