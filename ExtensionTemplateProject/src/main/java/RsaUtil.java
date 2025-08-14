import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

class RsaUtil {
    static String encryptKeyToBase64(byte[] aesKey, String publicKeyText) throws Exception {
        PublicKey pub = parsePublicKey(publicKeyText);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        byte[] enc = cipher.doFinal(aesKey);
        return Base64.getEncoder().encodeToString(enc);
    }

    private static PublicKey parsePublicKey(String text) throws Exception {
        String s = text.trim()
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(s);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }
}
