import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

class AESCbcDecryptor {
    static byte[] parseKey(String keyText) {
        if (keyText == null) return null;
        String s = keyText.trim();
        try {
            if (isHex(s)) {
                return hexToBytes(s);
            }
        } catch (Exception ignored) {}
        try {
            return Base64.getDecoder().decode(s);
        } catch (Exception ignored) {}
        // fallback: treat as UTF-8 bytes
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static byte[] parseIv(String ivText) {
        if (ivText == null) return null;
        String s = ivText.trim();
        try {
            if (isHex(s)) {
                return hexToBytes(s);
            }
        } catch (Exception ignored) {}
        try {
            return Base64.getDecoder().decode(s);
        } catch (Exception ignored) {}
        return null;
    }

    static String decryptBase64Content(String base64CipherText, byte[] key, byte[] iv) throws Exception {
        byte[] cipherBytes = Base64.getDecoder().decode(base64CipherText);
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
        if (key == null) return new byte[16];
        int[] allowed = {16, 24, 32};
        for (int a : allowed) {
            if (key.length == a) return key;
        }
        // resize to 16 bytes deterministically
        byte[] out = new byte[16];
        for (int i = 0; i < out.length; i++) {
            out[i] = key[i % key.length];
        }
        return out;
    }
}
