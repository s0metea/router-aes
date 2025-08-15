import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;

class RsaUtil {
    private static final Logger LOG = Logger.getLogger(RsaUtil.class.getName());

    static String encryptKeyToBase64(byte[] aesKey, String publicKeyText) throws Exception {
        PublicKey pub = parsePublicKey(publicKeyText);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        byte[] seed = aesKey;
        try {
            seed = Base64.getDecoder().decode(new String(aesKey, java.nio.charset.StandardCharsets.US_ASCII));
        } catch (Throwable t) {
            LOG.log(Level.FINE, "Failed to Base64-decode AES key for PRNG seed; falling back to ASCII bytes. Seed length={0}", (aesKey != null ? aesKey.length : 0));
        }
        SecureRandom sr = new SecureRandom();
        if (seed != null) sr.setSeed(seed);
        cipher.init(Cipher.ENCRYPT_MODE, pub, sr);
        assert aesKey != null;
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
