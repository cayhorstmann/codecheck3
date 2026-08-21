package services;

import io.jsonwebtoken.Jwts;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.security.PrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

@ApplicationScoped
public class LTI13DeepLinkResponseService {

    @Inject
    LTI13KeyService keyService;

public String createResponseJwt(
        String clientId,
        String deploymentId,
        List<Map<String, Object>> contentItems,
        String deepLinkData) {

    PrivateKey privateKey = keyService.getPrivateKey();

    Instant now = Instant.now();

    var builder = Jwts.builder()
            .issuer(clientId)
            .audience()
                .add(platformIssuer)
                .and()
            .issuedAt(Date.from(now))
            .expiration(Date.from(now.plusSeconds(300)))
            .claim(
                    "https://purl.imsglobal.org/spec/lti/claim/message_type",
                    "LtiDeepLinkingResponse"
            )
            .claim(
                    "https://purl.imsglobal.org/spec/lti/claim/version",
                    "1.3.0"
            )
            .claim(
                    "https://purl.imsglobal.org/spec/lti/claim/deployment_id",
                    deploymentId
            )
            .claim(
                    "https://purl.imsglobal.org/spec/lti-dl/claim/content_items",
                    contentItems
            );

    if (deepLinkData != null && !deepLinkData.isBlank()) {
        builder.claim(
                "https://purl.imsglobal.org/spec/lti-dl/claim/data",
                deepLinkData
        );
    }

    return builder
            .header()
                .keyId("codecheck-dev-key-1")
                .and()
            .signWith(privateKey, Jwts.SIG.RS256)
            .compact();
}

}

