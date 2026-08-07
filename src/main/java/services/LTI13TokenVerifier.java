package services;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.enterprise.context.ApplicationScoped;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

@ApplicationScoped
public class LTI13TokenVerifier {

    private final ObjectMapper mapper = new ObjectMapper();

    public Claims verify(String idToken) throws Exception {

        String[] parts = idToken.split("\\.");
        JsonNode header = mapper.readTree(
                Base64.getUrlDecoder().decode(parts[0])
        );

        String kid = header.get("kid").asText();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(LTI13Platform.JWKS_ENDPOINT))
                .GET()
                .build();

        String jwksJson = HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.ofString())
                .body();

        JsonNode keys = mapper.readTree(jwksJson).get("keys");

        JsonNode matchingKey = null;

        for (JsonNode key : keys) {
            if (kid.equals(key.get("kid").asText())) {
                matchingKey = key;
                break;
            }
        }

        if (matchingKey == null) {
            throw new IllegalArgumentException("No matching Moodle public key");
        }

        BigInteger modulus = new BigInteger(
                1,
                Base64.getUrlDecoder().decode(
                        matchingKey.get("n").asText()
                )
        );

        BigInteger exponent = new BigInteger(
                1,
                Base64.getUrlDecoder().decode(
                        matchingKey.get("e").asText()
                )
        );

        PublicKey publicKey = KeyFactory
                .getInstance("RSA")
                .generatePublic(
                        new RSAPublicKeySpec(modulus, exponent)
                );

        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(idToken)
                .getPayload();
    }
}