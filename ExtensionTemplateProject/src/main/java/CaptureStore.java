import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Simple in-memory store to correlate IV to AES key captured from hook beacons.
 */
class CaptureStore {
    private static final Map<String, byte[]> IV_TO_KEY = new ConcurrentHashMap<>();
    private static final Map<String, Long> IV_TS = new ConcurrentHashMap<>();
    private static final long TTL_MS = 5 * 60 * 1000; // 5 minutes

    static void register(String ivB64, byte[] aesKey) {
        if (ivB64 == null || ivB64.isEmpty() || aesKey == null) return;
        IV_TO_KEY.put(ivB64, aesKey);
        IV_TS.put(ivB64, System.currentTimeMillis());
        purgeOld();
    }

    static byte[] getKeyForIv(String ivB64) {
        if (ivB64 == null) return null;
        Long ts = IV_TS.get(ivB64);
        if (ts != null && (System.currentTimeMillis() - ts) <= TTL_MS) {
            return IV_TO_KEY.get(ivB64);
        }
        // expired / not found
        IV_TO_KEY.remove(ivB64);
        IV_TS.remove(ivB64);
        return null;
    }

    private static void purgeOld() {
        long now = System.currentTimeMillis();
        for (var e : IV_TS.entrySet()) {
            if (now - e.getValue() > TTL_MS) {
                String k = e.getKey();
                IV_TO_KEY.remove(k);
                IV_TS.remove(k);
            }
        }
    }
}
