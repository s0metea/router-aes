import java.security.SecureRandom;
import java.util.Base64;
import java.util.Arrays;

class StrictCryptoInputs {
    static byte[] keyFromAesKeyB64(String aesKeyB64) {
        if (aesKeyB64 == null) throw new IllegalArgumentException("AES key is null");
        String s = aesKeyB64.trim();
        byte[] key = Base64.getDecoder().decode(s);
        int len = key.length;
        if (len != 16 && len != 24 && len != 32) {
            throw new IllegalArgumentException("AES key bytes must be 16/24/32, got " + len);
        }
        return key;
    }

    static byte[] iv16FromIvB64(String ivB64) {
        if (ivB64 == null) throw new IllegalArgumentException("IV is null");
        String s = ivB64.trim();
        byte[] iv32 = Base64.getDecoder().decode(s);
        if (iv32.length != 32) {
            throw new IllegalArgumentException("IV Base64 must decode to 32 bytes, got " + iv32.length);
        }
        return Arrays.copyOf(iv32, 16);
    }

    static String generateIvB64_32() {
        SecureRandom sr = new SecureRandom();
        byte[] iv32 = new byte[32];
        sr.nextBytes(iv32);
        return Base64.getEncoder().encodeToString(iv32);
    }
}
