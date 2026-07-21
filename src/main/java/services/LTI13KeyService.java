package services;

import jakarta.enterprise.context.ApplicationScoped;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@ApplicationScoped
public class LTI13KeyService {

    private static final String PUBLIC_KEY_PATH =
            ".secrets/lti13/public.pem";

    private static final String KEY_ID =
            "codecheck-dev-key-1";

    public Map<String, Object> getPublicJwks() {
        RSAPublicKey publicKey = readPublicKey();

        Map<String, Object> jwk = Map.of(
                "kty", "RSA",
                "use", "sig",
                "alg", "RS256",
                "kid", KEY_ID,
                "n", encodeUnsigned(publicKey.getModulus()),
                "e", encodeUnsigned(publicKey.getPublicExponent())
        );

        return Map.of("keys", List.of(jwk));
    }

    private RSAPublicKey readPublicKey() {
        try {
            String pem = Files.readString(Path.of(PUBLIC_KEY_PATH))
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] encodedKey =
                    Base64.getDecoder().decode(pem);

            X509EncodedKeySpec keySpec =
                    new X509EncodedKeySpec(encodedKey);

            KeyFactory keyFactory =
                    KeyFactory.getInstance("RSA");

            return (RSAPublicKey)
                    keyFactory.generatePublic(keySpec);

        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Could not load the LTI 1.3 public key",
                    exception
            );
        }
    }

    private String encodeUnsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();

        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }
}