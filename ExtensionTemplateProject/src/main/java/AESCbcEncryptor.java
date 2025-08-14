import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

class AESCbcEncryptor {
    static String encryptToBase64(String plainText, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(normalizeKey(key), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));
        byte[] cipherBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(cipherBytes);
    }

    private static byte[] normalizeKey(byte[] key) {
        if (key == null) return new byte[16];
        int[] allowed = {16, 24, 32};
        for (int a : allowed) {
            if (key.length == a) return key;
        }
        byte[] out = new byte[16];
        for (int i = 0; i < out.length; i++) {
            out[i] = key[i % key.length];
        }
        return out;
    }
}
