import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

class AESCbcDecryptor {
    private static final Logger LOG = Logger.getLogger(AESCbcDecryptor.class.getName());

    static byte[] parseKey(String keyText) {
        if (keyText == null) return null;
        String s = keyText.trim().replaceAll("\\s+", "");
        try {
            if (isHex(s)) {
                return hexToBytes(s);
            }
        } catch (Exception ex) {
            LOG.log(Level.FINE, "Failed to parse AES key as hex; will try Base64. Input length={0}", s.length());
        }
        try {
            return Base64.getDecoder().decode(s);
        } catch (Exception ex) {
            LOG.log(Level.FINE, "Failed to parse AES key as Base64; will fall back to UTF-8 bytes. Input length={0}", s.length());
        }
        // fallback: treat as UTF-8 bytes
        LOG.log(Level.INFO, "Falling back to interpreting AES key as UTF-8 bytes (non-standard). Length={0}", s.length());
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static byte[] parseIv(String ivText) {
        if (ivText == null) return null;
        String s = ivText.trim();
        try {
            if (isHex(s)) {
                byte[] raw = hexToBytes(s);
                return normalizeIv(raw);
            }
        } catch (Exception ex) {
            LOG.log(Level.FINE, "Failed to parse IV as hex; will try Base64/base64url. Input length={0}", s.length());
        }
        try {
            // support base64url variants
            String b64 = s.replace('-', '+').replace('_', '/');
            byte[] raw = Base64.getDecoder().decode(b64);
            return normalizeIv(raw);
        } catch (Exception ex) {
            LOG.log(Level.FINE, "Failed to parse IV as Base64/base64url. Returning null. Input length={0}", s.length());
        }
        return null;
    }

    static String decryptBase64Content(String base64CipherText, byte[] key, byte[] iv) throws Exception {
        String b64 = normalizeBase64(base64CipherText);
        byte[] cipherBytes = Base64.getDecoder().decode(b64);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(normalizeKey(key), "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));
        byte[] plain = cipher.doFinal(cipherBytes);
        return new String(plain, StandardCharsets.UTF_8);
    }

    private static boolean isHex(String s) {
        if (s.length() % 2 != 0) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) return false;
        }
        return true;
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    private static byte[] normalizeKey(byte[] key) {
        if (key == null) {
            LOG.log(Level.WARNING, "AES key is null; defaulting to 16 zero bytes (non-standard, insecure). Provided key=null");
            return new byte[16];
        }
        int[] allowed = {16, 24, 32};
        for (int a : allowed) {
            if (key.length == a) return key;
        }
        // resize to 16 bytes deterministically
        LOG.log(Level.INFO, "AES key length {0} is non-standard; resizing deterministically to 16 bytes (non-standard)", key.length);
        byte[] out = new byte[16];
        for (int i = 0; i < out.length; i++) {
            out[i] = key[i % key.length];
        }
        return out;
    }

    static byte[] normalizeIv(byte[] iv) {
        if (iv == null) return null;
        if (iv.length == 16) return iv;
        byte[] out = new byte[16];
        if (iv.length > 16) {
            LOG.log(Level.INFO, "IV length {0} > 16; truncating to 16 bytes", iv.length);
            System.arraycopy(iv, 0, out, 0, 16);
        } else {
            // pad with zeroes deterministically
            LOG.log(Level.INFO, "IV length {0} < 16; padding with zeros to 16 bytes", iv.length);
            System.arraycopy(iv, 0, out, 0, iv.length);
            for (int i = iv.length; i < 16; i++) out[i] = 0;
        }
        return out;
    }

    private static String normalizeBase64(String s) {
        if (s == null) return "";
        String t = s.trim();
        // Unescape common JSON escape sequences for base64
        t = t.replace("\\/", "/")
             .replace("\\u002F", "/").replace("\\u002f", "/")
             .replace("\\u002B", "+").replace("\\u002b", "+")
             .replace("\\u003D", "=").replace("\\u003d", "=");
        // base64url -> base64
        if (t.indexOf('-') >= 0 || t.indexOf('_') >= 0) {
            LOG.log(Level.FINE, "Normalizing base64url characters to base64");
        }
        t = t.replace('-', '+').replace('_', '/');
        // remove whitespace
        String before = t;
        t = t.replaceAll("\\s+", "");
        if (!before.equals(t)) {
            LOG.log(Level.FINE, "Removed whitespace from base64 input");
        }
        // pad to length % 4 == 0
        int mod = t.length() % 4;
        if (mod != 0) {
            LOG.log(Level.FINE, "Padding base64 string by {0} character(s) to reach multiple of 4", (4 - mod));
            t = t + "====".substring(mod);
        }
        return t;
    }
}
