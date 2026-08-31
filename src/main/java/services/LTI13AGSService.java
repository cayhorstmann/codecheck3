package services;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@ApplicationScoped
public class LTI13AGSService {

    @Inject
    LTI13KeyService keyService;

    private final HttpClient httpClient =
            HttpClient.newHttpClient();

    private final ObjectMapper objectMapper =
            new ObjectMapper();

    public String getAccessToken(String issuer, String scope) throws Exception {

        PrivateKey privateKey =
                keyService.getPrivateKey();

        Instant now = Instant.now();

        String clientAssertion =
                Jwts.builder()
                        .issuer(issuer)
                        .subject(issuer) 
                        .audience()
                            .add(LTI13Platform.ACCESS_TOKEN_ENDPOINT)
                            .and()
                        .issuedAt(Date.from(now))
                        .expiration(Date.from(now.plusSeconds(300)))
                        .id(UUID.randomUUID().toString())
                        .header()
                            .keyId("codecheck-dev-key-1")
                            .and()
                        .signWith(
                                privateKey,
                                Jwts.SIG.RS256
                        )
                        .compact();

        String body =
                "grant_type="
                + encode("client_credentials")
                + "&client_assertion_type="
                + encode(
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                )
                + "&client_assertion="
                + encode(clientAssertion)
                + "&scope="
                + encode(scope);

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(
                            URI.create(
                                LTI13Platform.ACCESS_TOKEN_ENDPOINT
                            )
                        )
                        .header(
                            "Content-Type",
                            "application/x-www-form-urlencoded"
                        )
                        .POST(
                            HttpRequest.BodyPublishers.ofString(body)
                        )
                        .build();

        HttpResponse<String> response =
                httpClient.send(
                        request,
                        HttpResponse.BodyHandlers.ofString()
                );

        System.out.println(
                "AGS token response status: "
                + response.statusCode()
        );

        if (response.statusCode() < 200
                || response.statusCode() >= 300) {

            throw new IllegalStateException(
                    "AGS token request failed: "
                    + response.body()
            );
        }

        JsonNode json =
                objectMapper.readTree(
                        response.body()
                );

        JsonNode accessTokenNode =
                json.get("access_token");

        if (accessTokenNode == null) {
            throw new IllegalStateException(
                    "AGS token response did not contain access_token"
            );
        }

                return accessTokenNode.asText();
    }

    public String getLineItems(
            String lineItemsUrl,
            String accessToken)
            throws Exception {

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(URI.create(lineItemsUrl))
                        .header(
                                "Authorization",
                                "Bearer " + accessToken
                        )
                        .header(
                                "Accept",
                                "application/vnd.ims.lis.v2.lineitemcontainer+json"
                        )
                        .GET()
                        .build();

        HttpResponse<String> response =
                httpClient.send(
                        request,
                        HttpResponse.BodyHandlers.ofString()
                );

        System.out.println(
                "AGS lineitems response status: "
                + response.statusCode()
        );

        if (response.statusCode() < 200
                || response.statusCode() >= 300) {

            throw new IllegalStateException(
                    "AGS lineitems request failed: "
                    + response.body()
            );
        }

        return response.body();
    }

public String createLineItem(
        String lineItemsUrl,
        String accessToken,
        String resourceLinkId)
        throws Exception {

    String requestBody =
            objectMapper.createObjectNode()
                    .put("scoreMaximum", 1.0)
                    .put("label", "CodeCheck")
                    .put("resourceId", resourceLinkId)
                    .toString();

    HttpRequest request =
            HttpRequest.newBuilder()
                    .uri(URI.create(lineItemsUrl))
                    .header(
                            "Authorization",
                            "Bearer " + accessToken
                    )
                    .header(
                            "Content-Type",
                            "application/vnd.ims.lis.v2.lineitem+json"
                    )
                    .header(
                            "Accept",
                            "application/vnd.ims.lis.v2.lineitem+json"
                    )
                    .POST(
                            HttpRequest.BodyPublishers.ofString(
                                    requestBody
                            )
                    )
                    .build();

    HttpResponse<String> response =
            httpClient.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
            );

    System.out.println(
            "AGS create lineitem response status: "
            + response.statusCode()
    );

    if (response.statusCode() < 200
            || response.statusCode() >= 300) {

        throw new IllegalStateException(
                "AGS lineitem creation failed: "
                + response.body()
        );
    }

    System.out.println(
            "AGS lineitem created successfully"
    );

        return response.body();
}

public void sendScore(
        String lineItemId,
        String accessToken,
        String userId,
        double score) throws Exception {

    URI lineItemUri =
        URI.create(lineItemId);

String scoresPath =
        lineItemUri.getPath().endsWith("/")
                ? lineItemUri.getPath() + "scores"
                : lineItemUri.getPath() + "/scores";

URI scoresUri =
        new URI(
                lineItemUri.getScheme(),
                lineItemUri.getAuthority(),
                scoresPath,
                lineItemUri.getQuery(),
                null
        );

    String timestamp =
            Instant.now().toString();

    String scoreJson =
            objectMapper.createObjectNode()
                    .put("userId", userId)
                    .put("scoreGiven", score)
                    .put("scoreMaximum", 1.0)
                    .put("timestamp", timestamp)
                    .put("activityProgress", "Completed")
                    .put("gradingProgress", "FullyGraded")
                    .toString();

    HttpRequest request =
            HttpRequest.newBuilder()
                    .uri(scoresUri)
                    .header(
                            "Authorization",
                            "Bearer " + accessToken
                    )
                    .header(
                            "Content-Type",
                            "application/vnd.ims.lis.v1.score+json"
                    )
                    .POST(
                            HttpRequest.BodyPublishers.ofString(
                                    scoreJson
                            )
                    )
                    .build();

    HttpResponse<String> response =
            httpClient.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
            );

    System.out.println(
            "AGS score response status: "
            + response.statusCode()
    );

    System.out.println(
            "AGS score response body: "
            + response.body()
    );

    if (response.statusCode() < 200
            || response.statusCode() >= 300) {

        throw new IllegalStateException(
                "AGS score POST failed: "
                + response.body()
        );
    }

    System.out.println(
            "AGS score posted successfully"
    );
}

public String extractLineItemId(
        String lineItemResponse)
        throws Exception {

    if (lineItemResponse == null
            || lineItemResponse.isBlank()) {
        return null;
    }

    JsonNode json =
            objectMapper.readTree(lineItemResponse);

    if (json.isArray()) {
        if (json.isEmpty()) {
            return null;
        }

        JsonNode firstItem =
                json.get(0);

        JsonNode idNode =
                firstItem.get("id");

        return idNode == null
                ? null
                : idNode.asText();
    }

    if (json.isObject()) {
        JsonNode idNode =
                json.get("id");

        return idNode == null
                ? null
                : idNode.asText();
    }

    return null;
}

private String encode(String value) {
    return URLEncoder.encode(
            value,
            StandardCharsets.UTF_8
    );
}
}