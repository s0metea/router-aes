import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.responses.HttpResponse;

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
        try { this.api.logging().logToOutput("[AES-Decrypter] HTTP handler registered"); } catch (Throwable ignored) {}
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        try {
            String pathNoQ = safe(requestToBeSent::pathWithoutQuery);
            if (pathNoQ != null && pathNoQ.startsWith("/__capture__")) {
                try { api.logging().logToOutput("[AES-Decrypter] Skipping capture beacon in request phase: " + pathNoQ); } catch (Throwable ignored) {}
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }
            // If the body looks like encrypted JSON, extract IV and remember mapping for later correlation
            String bodyOrig = safe(requestToBeSent::bodyToString);
            if (bodyOrig != null && bodyOrig.contains("\"content\"") && bodyOrig.contains("\"iv\"")) {
                String iv = unescapeJsonString(extract(IV_PATTERN, bodyOrig));
                if (iv != null && !iv.isEmpty()) {
                    IvRequestMap.remember(iv, requestToBeSent.messageId(), requestToBeSent);
                    try { api.logging().logToOutput("[AES-Decrypter] Remembered IV mapping for message " + requestToBeSent.messageId()); } catch (Throwable ignored) {}
                    try { panel.setIv(iv); } catch (Throwable ignored) {}
                    // Consume any pending plaintext captured before mapping existed
                    try {
                        String pending = IvRequestMap.takePendingPlaintext(iv);
                        if (pending != null) {
                            var displayedReq = requestToBeSent.withBody(pending).withRemovedHeader("Content-Length");
                            RequestDisplayStore.put(requestToBeSent.messageId(), displayedReq);
                        } else {
                            // Try to decrypt request body ourselves for display if key is available
                            try { api.logging().logToOutput("[AES-Decrypter] No pending plaintext; attempting local decrypt for display"); } catch (Throwable ignored) {}
                            String content = unescapeJsonString(extract(CONTENT_PATTERN, bodyOrig));
                            byte[] k = AESCbcDecryptor.parseKey(panel.getAesKey());
                            byte[] ivBytes = AESCbcDecryptor.parseIv(iv);
                            if (content != null && k != null && ivBytes != null) {
                                try {
                                    String plain = AESCbcDecryptor.decryptBase64Content(content, k, ivBytes);
                                    var displayedReq = requestToBeSent.withBody(plain).withRemovedHeader("Content-Length");
                                    RequestDisplayStore.put(requestToBeSent.messageId(), displayedReq);
                                } catch (Exception ignore) {}
                            }
                        }
                    } catch (Throwable ignored) {}
                }
            }
        } catch (Throwable t) {
            try { api.logging().logToError("[AES-Decrypter] Error in request pre-processing", t); } catch (Throwable ignored) {}
        }

        // Repeater encryption logic
        try {
            if (panel.isEncryptRepeaterEnabled() && requestToBeSent.toolSource() != null && requestToBeSent.toolSource().isFromTool(ToolType.REPEATER)) {
                try { api.logging().logToOutput("[AES-Decrypter] Encrypting Repeater request " + requestToBeSent.messageId()); } catch (Throwable ignored) {}
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
                    if (body != null && body.contains("\"content\"") && (body.contains("\"iv\""))) {
                        return RequestToBeSentAction.continueWith(requestToBeSent);
                    }

                    // Strict encryption inputs (do not reuse decryption helpers)
                    byte[] encKeyBytes;
                    try {
                        encKeyBytes = StrictCryptoInputs.keyFromAesKeyB64(panel.getAesKey());
                    } catch (IllegalArgumentException ex) {
                        // Fail fast: cannot fabricate a key for encryption
                        return RequestToBeSentAction.continueWith(requestToBeSent);
                    }

                    // Determine IV string to put into JSON and IV bytes to use for AES
                    String encIvStrFromPanel = panel.getIv();
                    byte[] encIv16;
                    String encIvB64;

                    if (encIvStrFromPanel != null && !encIvStrFromPanel.trim().isEmpty()) {
                        // Use the exact IV string provided by the frontend/user for the JSON field
                        encIvB64 = encIvStrFromPanel;
                        try {
                            encIv16 = StrictCryptoInputs.iv16FromIvB64(encIvB64);
                        } catch (IllegalArgumentException ex) {
                            return RequestToBeSentAction.continueWith(requestToBeSent);
                        }
                    } else {
                        // Generate a 32-byte IV for JSON, AES uses first 16 bytes
                        encIvB64 = StrictCryptoInputs.generateIvB64_32();
                        encIv16 = StrictCryptoInputs.iv16FromIvB64(encIvB64);
                    }

                    if (body != null) {
                        String contentB64 = AESCbcEncryptor.encryptToBase64(body, encKeyBytes, encIv16);
                        try { panel.setIv(encIvB64); } catch (Throwable ignored) {}
                        boolean isUserLogin = false;
                        String path = safe(requestToBeSent::pathWithoutQuery);
                        if (path != null) {
                            String p = path;
                            isUserLogin = p.equals("/UserLogin") || p.endsWith("/UserLogin");
                        }
                        boolean alwaysSetKey = "always set".equalsIgnoreCase(panel.getKeyParamMode());
                        String keyField = "";
                        if (alwaysSetKey || isUserLogin) {
                            try {
                                String aesKeyB64 = panel.getAesKey();
                                if (aesKeyB64 != null && !aesKeyB64.isEmpty()) {
                                    byte[] keyAscii = aesKeyB64.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
                                    keyField = RsaUtil.encryptKeyToBase64(keyAscii, panel.getRsaPublicKey());
                                } else {
                                    keyField = "";
                                }
                            } catch (Exception e) {
                                keyField = "";
                            }
                        }
                        String json = "{\"content\":\"" + contentB64 + "\",\"key\":\"" + keyField + "\",\"iv\":\"" + encIvB64 + "\"}";
                        byte[] utf8 = json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        var newReq = requestToBeSent
                                .withBody(json)
                                .withRemovedHeader("Content-Length")
                                .withAddedHeader("Content-Length", String.valueOf(utf8.length));

                        try { api.logging().logToOutput("[AES-Decrypter] Repeater request encrypted; iv=" + encIvB64); } catch (Throwable ignored) {}

                        // Remember mapping so __capture__ can update displayed plaintext later
                        IvRequestMap.remember(encIvB64, requestToBeSent.messageId(), newReq);
                        // Also consume any pending plaintext captured before the mapping existed
                        try {
                            String pending = IvRequestMap.takePendingPlaintext(encIvB64);
                            if (pending != null) {
                                var displayedReq = newReq.withBody(pending).withRemovedHeader("Content-Length");
                                RequestDisplayStore.put(requestToBeSent.messageId(), displayedReq);
                            }
                        } catch (Throwable ignored) {}

                        return RequestToBeSentAction.continueWith(newReq);
                    }
                }
            }
        } catch (Throwable t) {
            try { api.logging().logToError("[AES-Decrypter] Error in Repeater encryption phase", t); } catch (Throwable ignored) {}
        }
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
                    HttpResponse injected = originalResp.withBody(js + "\n;\n" + HookSettings.getHook(api.persistence().preferences()))
                            .withRemovedHeader("Content-Length")
                            .withRemovedHeader("Content-Encoding")
                            .withRemovedHeader("Content-Type")
                            .withAddedHeader("Content-Type", "application/javascript");
                    try { api.logging().raiseInfoEvent("Injected hook into /static/js/app.js response"); } catch (Throwable ignored) {}
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
                boolean matches = p.equals("/getRSAPublicKey") || p.endsWith("/getRSAPublicKey");
                if (matches && (method == null || "GET".equalsIgnoreCase(method))) {
                    String body = safe(responseReceived::bodyToString);
                    if (body != null) {
                        String keyEsc = extract(RSAPUB_PATTERN, body);
                        if (keyEsc != null && !keyEsc.isEmpty()) {
                            String key = unescapeJsonString(keyEsc);
                            if (key != null && key.contains("BEGIN PUBLIC KEY")) {
                                panel.setRsaPublicKey(key);
                                try { api.logging().raiseInfoEvent("Captured RSA public key from server response"); } catch (Throwable ignored) {}
                            }
                        }
                    }
                }
            }
        } catch (Throwable ignored) {}

        boolean shouldProcess = panel.isFeatureEnabled() && originMatches(panel.getOrigin(), safe(req::url));
        if (!shouldProcess) {
            try { api.logging().logToOutput("[AES-Decrypter] Skipping response (feature off or origin mismatch)"); } catch (Throwable ignored) {}
            return ResponseReceivedAction.continueWith(originalResp);
        }

        String contentType = safe(() -> responseReceived.headerValue("Content-Type"));
        if (contentType == null || !contentType.toLowerCase().contains("application/json")) {
            try { api.logging().logToOutput("[AES-Decrypter] Skipping non-JSON response"); } catch (Throwable ignored) {}
            return ResponseReceivedAction.continueWith(originalResp);
        }

        String body = safe(responseReceived::bodyToString);
        boolean decrypted = false;
        String note = "";
        HttpResponse resultResp = originalResp;

        if (body != null && body.length() > 0) {
            try {
                String content = unescapeJsonString(extract(CONTENT_PATTERN, body));
                String iv = unescapeJsonString(extract(IV_PATTERN, body));
                try { if (iv != null) panel.setIv(iv); } catch (Throwable ignored) {}
                if (content != null && iv != null) {
                    byte[] key = AESCbcDecryptor.parseKey(panel.getAesKey());
                    byte[] ivBytes = AESCbcDecryptor.parseIv(iv);
                    if (key != null && ivBytes != null) {
                        String plain = AESCbcDecryptor.decryptBase64Content(content, key, ivBytes);
                        resultResp = resultResp.withBody(plain)
                                .withRemovedHeader("Content-Length");
                        decrypted = true;
                        note = "decrypted";
                        try { api.logging().logToOutput("[AES-Decrypter] Response decrypted (msgId=" + responseReceived.messageId() + ")"); } catch (Throwable ignored) {}
                    } else {
                        note = "missing key/iv";
                        try { api.logging().logToOutput("[AES-Decrypter] Missing key or IV for decryption"); } catch (Throwable ignored) {}
                    }
                } else {
                    note = "no content/iv";
                    try { api.logging().logToOutput("[AES-Decrypter] Response missing content/iv fields"); } catch (Throwable ignored) {}
                }
            } catch (Exception ex) {
                note = "decrypt error: " + ex.getMessage();
                try { api.logging().logToError("[AES-Decrypter] Decrypt error", ex); } catch (Throwable ignored) {}
            }
        } else {
            note = "not json";
        }

        // Attach any displayedRequest that was prepared during request phase
        var displayedReq = RequestDisplayStore.take(responseReceived.messageId());
        panel.addEntry(new DecryptEntry(System.currentTimeMillis(), req, displayedReq, originalResp, resultResp, decrypted, note));
        try { api.logging().logToOutput("[AES-Decrypter] Logged entry: decrypted=" + decrypted + ", note=" + note); } catch (Throwable ignored) {}
        return ResponseReceivedAction.continueWith(resultResp);
    }

    private boolean originMatches(String origin, String url) {
        if (origin == null || origin.isEmpty() || url == null) return false;
        return url.contains(origin);
    }

    private static String extract(Pattern p, String text) {
        Matcher m = p.matcher(text);
        if (m.find()) return m.group(1);
        return null;
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
