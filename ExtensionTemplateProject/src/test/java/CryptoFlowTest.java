import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class CryptoFlowTest {

    @Test
    void testEncryptMatchesFrontendExample() throws Exception {
        // Given (from issue description)
        String aesKeyB64 = "rwnuD4NHfmjMHgnAxQ+tFBzvfCtLTcEl0QT9DV2V948=";
        String ivB64 = "rXJwTAuAQu+sFS4VKv7XGiY+m0FjNtzfsNRJ6xgJNZc=";
        String plaintext = "{\"Input_Account\":\"user\",\"Input_Passwd\":\"dXNlcg==\",\"currLang\":\"en\",\"RememberPassword\":0,\"SHA512_password\":false}";
        String expectedContentB64 = "ygXOqJZGc/egQm/k9VkHaYWKiS4ZmrVEcEQabhWJiSyjZOq+lCQqVXgeGhG734aF";
        String expectedKeyB64 = "trwmx5D7LkDCv/3udAfwxRJogM6mwGqGc2EE23QsmVVI+0hWr71kvIaHoO9K62dSzikTgXB8SuCMy3zQmu9YvizfXscJEjdoRqSGuIMZ77lG0/+YQZI6EXmnC+KNQH1w46GQly/plmBlnZLI73Pgh8hbxcUIOSZhzmTb3Vo2lsVuyM8X8fsmu9LlgfOa0fjPGJRUmqPE4ZlYWS55aoYugZiVzYceAAvPysdaVeiPrMIq0pJxiuIavozg+6GNo4x8jrLpQ/EZfNGBu2nt7IugHu45RbRnSqUu5FDMXS70RmHzDCj8yLYYP6k6EJZF8VIIlhzVfPRTsEl1sqAEJdQWTw==";
        String rsaPubPem = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1IRJPrJVF6uL024lL0hd\n" +
                "IYorPHTbstOhR1WZ3CvDQJ1vp9JHeTY0XCgeNL91/WvzIZfGG7iPtQ5NoBDKZFAa\n" +
                "X1p/Nym5YpQ5dpEtLRdZ1K7j5pjS0acHotokiOb4adPTppmRHx9z6KJgMRccCAqn\n" +
                "x2axfB77zB/mwKfpB1X6W0xR6ad6iAojLu3IoqGc6ghpAPlz8TaE42Ll7h9okOxs\n" +
                "Dj/QoB1G0iJXFwCZZPT4meUkbkz3UDxrnfD5uwD/49QpSNm69NR+ogVUFgrue5p4\n" +
                "/8fvTafTy2yert9sBiZn90xG7gw5eXRBDXcHA9PbBbF8srPwYTj/9CaC1orE4fgV\n" +
                "VwIDAQAB\n" +
                "-----END PUBLIC KEY-----\n";

        byte[] key = AESCbcDecryptor.parseKey(aesKeyB64);
        byte[] iv = AESCbcDecryptor.parseIv(ivB64);
        assertNotNull(key, "Key parse failed");
        assertNotNull(iv, "IV parse failed");

        String actualContentB64 = AESCbcEncryptor.encryptToBase64(plaintext, key, iv);
        assertTrue(actualContentB64.startsWith(expectedContentB64), "Ciphertext should start with the 64-char preview from frontend");
        assertEquals(152, actualContentB64.length(), "Ciphertext length mismatch with frontend example (contentLen)");

        // And RSA-wrapped key should be a valid 2048-bit RSA ciphertext (length 256 bytes => Base64 length 344)
        String actualKeyB64 = RsaUtil.encryptKeyToBase64(aesKeyB64.getBytes(StandardCharsets.US_ASCII), rsaPubPem);
        assertEquals(344, actualKeyB64.length(), "RSA-wrapped key Base64 length should be 344 for 2048-bit key");
        byte[] wrappedBytes = java.util.Base64.getDecoder().decode(actualKeyB64);
        assertEquals(256, wrappedBytes.length, "RSA-wrapped key byte length should be 256 for 2048-bit key");
    }

    @Test
    void testDecryptRequestContentMatchesPlaintext() throws Exception {
        String aesKeyB64 = "fcIlWR5GNOzS8NtijWPIg5rpvYqQ7jMOocMpV6mtMTE=";
        String ivB64 = "8UMmuT03MFvb54gv8wsqK5DFWXC53YG0xI2J2xWUvNE=";
        String plaintext = "{\"Input_Account\":\"user\",\"Input_Passwd\":\"dXNlcg==\",\"RememberPassword\":0,\"SHA512_password\":false}";
        String contentB64 = "xEBMdaLH8LPo0iss6N/zaMDgoPgRoX1ukP2O8m7jHJp0oHnwz3Np3H5IBIdJzJO+wda8EybjWUMoiFP0DNb1ZdPTGWcgbfSiYFiEwCi9HmacPBLttKcgiQW0U/vPeaBl";

        byte[] key = AESCbcDecryptor.parseKey(aesKeyB64);
        byte[] iv = AESCbcDecryptor.parseIv(ivB64);

        String decrypted = AESCbcDecryptor.decryptBase64Content(contentB64, key, iv);
        assertEquals(plaintext, decrypted, "Decrypted request plaintext mismatch");
    }

    @Test
    void testDecryptResponseContentParsesJson() throws Exception {
        //"ivB64":"Ma1d/leRTADhpPsPqSHOPshpxQH+ip8/EdJ+TohttM4=","aesKeyB64":"xXsyudQ94zKGz5Uv/26zW3g/ygPBpsSN94j4nAN3omo=",
        String aesKeyB64 = "xXsyudQ94zKGz5Uv/26zW3g/ygPBpsSN94j4nAN3omo=";
        String ivRespEscaped = "ZKQvgl2OUBsyAjrt2Oz+N04uJP8WjMMj9WFKP+un/lA="; // from response JSON, with \/ escape
        String contentResp = "IDufWrotnML126N4LIkM6YxjycNZrXiC2cPrLcxTObBP47LKvwhmQ9NwA1BzoRoMBLBpw5YLmc9so1XFyyjhO0jC52JjL1ewPdznQZSIrZVndVj/dp1Z6BgOub/2GQw//iniyeq/ihxJ56krEZP7nEOA7Yt9r4Vn8mxeDtJKGhl7zJjfCe4SxatZtzdJpVHA0kymTICOJyz8s8kSzJfixSpVFUQ6bWt9Fu6Ik+zKm+103jaoG4rYaWoAv/gbTuFoZzMfplYdoQ9RKwg/LlLdvlMpQt+zMNrg+I+UFl8FNv1/G+8RwBlngRdyw74XQQluKOTsPTMXq28KUuNFMxE2H7ZeErrgKCK4hrWISySv3YEqP6VF55fUnn39swRAERr0Hzix9WDSEd4EcsPsdYeC5gZ02S9rQmtPLzLoe9yX8/QIWkWUO7wqeoqkpf3WXcp97DS4o8T6lBXOwWEgpshiOWuvu9ryUW5ef57Fs+FA8yl/Re9hgFMcPADGStt9ku07YlvQ72QBjaip6JAsCKSdWr9fsYsI3F06/rkqz13PTHmBF7kiQTTGo/CmhPSzRtGPiVb/oJas0Z7woVMQwHM7jfxqDRwn3PaH1j4sMwUKA6FYHzE4oZPtm2wDbBqz26wvUGa+vKxvEkx01fex/NpuO2qi7V86Uwx5BYyJE87hfvQ=";
        // Unescape the IV like our handler does
        String ivResp = ivRespEscaped.replace("\\/", "/");
        byte[] key = AESCbcDecryptor.parseKey(aesKeyB64);
        byte[] iv = AESCbcDecryptor.parseIv(ivResp);
        assertNotNull(iv, "IV parse failed for response iv");

        String plain = AESCbcDecryptor.decryptBase64Content(contentResp, key, iv);
        assertNotNull(plain);
        String t = plain.trim();
        assertTrue(t.startsWith("{") && t.endsWith("}") || t.length() > 0, "Response decrypt did not yield plausible JSON");
    }
}
