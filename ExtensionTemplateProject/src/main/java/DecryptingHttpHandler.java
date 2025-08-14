import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class DecryptingHttpHandler implements HttpHandler {
    private final MontoyaApi api;
    private final DecryptTabPanel panel;

    private static final Pattern CONTENT_PATTERN = Pattern.compile("\\\"content\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");
    private static final Pattern IV_PATTERN = Pattern.compile("\\\"iv\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");
    private static final Pattern RSAPUB_PATTERN = Pattern.compile("\\\"RSAPublicKey\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");

    DecryptingHttpHandler(MontoyaApi api, DecryptTabPanel panel) {
        this.api = api;
        this.panel = panel;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        try {
            String pathNoQ = safe(requestToBeSent::pathWithoutQuery);
            if (pathNoQ != null && pathNoQ.startsWith("/__capture__")) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }
            // If the body looks like encrypted JSON, extract IV and remember mapping for later correlation
            String bodyOrig = safe(requestToBeSent::bodyToString);
            if (bodyOrig != null && bodyOrig.contains("\"content\"") && bodyOrig.contains("\"iv\"")) {
                String iv = normalizeEscapes(extract(IV_PATTERN, bodyOrig));
                if (iv != null && !iv.isEmpty()) {
                    IvRequestMap.remember(iv, requestToBeSent.messageId(), requestToBeSent);
                }
            }
        } catch (Throwable ignored) {}

        // Repeater encryption logic
        try {
            if (panel.isEncryptRepeaterEnabled() && requestToBeSent.toolSource() != null && requestToBeSent.toolSource().isFromTool(ToolType.REPEATER)) {
                String method = safe(requestToBeSent::method);
                if (method != null) method = method.toUpperCase();
                if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
                    String body = safe(requestToBeSent::bodyToString);
                    // Keep a plaintext view for the table
                    if (body != null) {
                        try {
                            var displayedReq = requestToBeSent.withBody(body).withRemovedHeader("Content-Length");
                            RequestDisplayStore.put(requestToBeSent.messageId(), displayedReq);
                        } catch (Throwable ignored) {}
                    }
                    // If already in encrypted envelope, avoid double-wrapping
                    if (body != null && body.contains("\"content\"") && body.contains("\"iv\"")) {
                        return RequestToBeSentAction.continueWith(requestToBeSent);
                    }
                    byte[] keyBytes = AESCbcDecryptor.parseKey(panel.getAesKey());
                    byte[] ivBytes = AESCbcDecryptor.parseIv(panel.getIv());
                    if (body != null && keyBytes != null && ivBytes != null) {
                        String contentB64 = AESCbcEncryptor.encryptToBase64(body, keyBytes, ivBytes);
                        String ivOut = Base64.getEncoder().encodeToString(ivBytes);
                        boolean isUserLogin = false;
                        String path = safe(requestToBeSent::pathWithoutQuery);
                        if (path != null) {
                            String p = path;
                            isUserLogin = p.equals("/UserLogin") || p.endsWith("/UserLogin");
                        }
                        boolean alwaysSetKey = "always set".equalsIgnoreCase(panel.getKeyParamMode());
                        String keyField = "";
                        if (alwaysSetKey || isUserLogin) {
                            byte[] usedKey = normalizeKey(keyBytes);
                            try {
                                keyField = RsaUtil.encryptKeyToBase64(usedKey, panel.getRsaPublicKey());
                            } catch (Exception e) {
                                keyField = "";
                            }
                        }
                        String json = "{\"content\":\"" + contentB64 + "\",\"key\":\"" + keyField + "\",\"iv\":\"" + ivOut + "\"}";
                        var newReq = requestToBeSent
                                .withBody(json)
                                .withRemovedHeader("Content-Length")
                                .withRemovedHeader("Content-Type")
                                .withAddedHeader("Content-Type", "application/json");
                        return RequestToBeSentAction.continueWith(newReq);
                    }
                }
            }
        } catch (Throwable ignored) {}
        // default behavior
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        HttpResponse originalResp = responseReceived;
        var req = responseReceived.initiatingRequest();

        // Unconditional hook injection for /static/js/app.js
        try {
            String path = safe(req::pathWithoutQuery);
            if (path != null && path.endsWith("/static/js/app.js")) {
                String js = safe(responseReceived::bodyToString);
                if (js != null) {
                    HttpResponse injected = originalResp.withBody(js + "\n;\n" + HookPayload.HOOK_JS)
                            .withRemovedHeader("Content-Length")
                            .withRemovedHeader("Content-Encoding")
                            .withRemovedHeader("Content-Type")
                            .withAddedHeader("Content-Type", "application/javascript");
                    return ResponseReceivedAction.continueWith(injected);
                }
            }
        } catch (Throwable ignored) {}

        // Auto-capture RSA public key from /getRSAPublickKey JSON response
        try {
            String method = safe(req::method);
            String path = safe(req::pathWithoutQuery);
            if (path != null) {
                // Do not log capture responses at all
                if (path.startsWith("/__capture__")) {
                    return ResponseReceivedAction.continueWith(originalResp);
                }
                String p = path;
                boolean matches = p.equals("/getRSAPublickKey") || p.endsWith("/getRSAPublickKey")
                        || p.equals("/getRSAPublicKey") || p.endsWith("/getRSAPublicKey");
                if (matches && (method == null || "GET".equalsIgnoreCase(method))) {
                    String body = safe(responseReceived::bodyToString);
                    if (body != null) {
                        String keyEsc = extract(RSAPUB_PATTERN, body);
                        if (keyEsc != null && !keyEsc.isEmpty()) {
                            String key = unescapeJsonString(keyEsc);
                            if (key != null && key.contains("BEGIN PUBLIC KEY")) {
                                panel.setRsaPublicKey(key);
                            }
                        }
                    }
                }
            }
        } catch (Throwable ignored) {}

        boolean shouldProcess = panel.isFeatureEnabled() && originMatches(panel.getOrigin(), safe(req::url));
        if (!shouldProcess) {
            return ResponseReceivedAction.continueWith(originalResp);
        }

        String contentType = safe(() -> responseReceived.headerValue("Content-Type"));
        if (contentType == null || !contentType.toLowerCase().contains("application/json")) {
            return ResponseReceivedAction.continueWith(originalResp);
        }

        String body = safe(responseReceived::bodyToString);
        boolean decrypted = false;
        String note = "";
        HttpResponse resultResp = originalResp;

        if (body != null && body.length() > 0) {
            try {
                String content = normalizeEscapes(extract(CONTENT_PATTERN, body));
                String iv = normalizeEscapes(extract(IV_PATTERN, body));
                if (content != null && iv != null) {
                    byte[] key = AESCbcDecryptor.parseKey(panel.getAesKey());
                    byte[] ivBytes = AESCbcDecryptor.parseIv(iv);
                    if (key != null && ivBytes != null) {
                        String plain = AESCbcDecryptor.decryptBase64Content(content, key, ivBytes);
                        resultResp = resultResp.withBody(plain)
                                .withRemovedHeader("Content-Encoding")
                                .withRemovedHeader("Content-Length");
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

        // Attach any displayedRequest that was prepared during request phase
        var displayedReq = RequestDisplayStore.take(responseReceived.messageId());
        panel.addEntry(new DecryptEntry(System.currentTimeMillis(), req, displayedReq, originalResp, resultResp, decrypted, note));
        return ResponseReceivedAction.continueWith(resultResp);
    }

    private boolean originMatches(String origin, String url) {
        if (origin == null || origin.isEmpty() || url == null) return false;
        return url.contains(origin);
    }

    private static byte[] normalizeKey(byte[] key) {
        if (key == null) return new byte[16];
        int len = key.length;
        if (len == 16 || len == 24 || len == 32) return key;
        byte[] out = new byte[16];
        for (int i = 0; i < out.length; i++) out[i] = key[i % key.length];
        return out;
    }

    private static String extract(Pattern p, String text) {
        Matcher m = p.matcher(text);
        if (m.find()) return m.group(1);
        return null;
    }

    // Simplified: just remove backslashes from the string
    private static String normalizeEscapes(String s) {
        if (s == null || s.indexOf('\\') < 0) return s;
        return s.replace("\\", "");
        
    }

    // Unescape common JSON escape sequences in a JSON string value
    private static String unescapeJsonString(String s) {
        if (s == null) return null;
        String out = s;
        out = out.replace("\\n", "\n")
                 .replace("\\r", "\r")
                 .replace("\\t", "\t")
                 .replace("\\/", "/")
                 .replace("\\\"", "\"")
                 .replace("\\\\", "\\");
        return out;
    }

    private static <T> T safe(SupplierWithEx<T> s) {
        try { return s.get(); } catch (Throwable t) { return null; }
    }

    interface SupplierWithEx<T> { T get(); }
}
