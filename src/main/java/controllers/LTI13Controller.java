package controllers;

import jakarta.enterprise.context.RequestScoped;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.PathParam;
import services.LTI13Platform;
import services.LTI13KeyService;
import services.LTI13TokenVerifier;
import services.LTI13DeepLinkResponseService;
import services.LTI13AGSService;
import services.LTIProblem;
import services.CodeCheck;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.inject.Inject;

@RequestScoped
@Path("/LTI/1.3")
public class LTI13Controller {

    @Inject
    LTI13KeyService keyService;

    @Inject
    LTI13TokenVerifier tokenVerifier;

    @Inject
    LTI13DeepLinkResponseService deepLinkResponseService;

    @Inject
    LTI13AGSService agsService;

    @Inject
    LTIProblem problemService;
    

    @GET
    @Path("/keys")
    @Produces(MediaType.APPLICATION_JSON)
    public Response keys() {
        return Response.ok(keyService.getPublicJwks()).build();
    }

    private static final Map<String, PendingLogin> PENDING_LOGINS =
            new ConcurrentHashMap<>();

    private record PendingLogin(
            String nonce,
            String clientId,
            String targetLinkUri,
            Instant createdAt) {
    }

    @POST
    @Path("/login")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response login(
        @FormParam("iss") String issuer,
        @FormParam("login_hint") String loginHint,
        @FormParam("target_link_uri") String targetLinkUri,
        @FormParam("client_id") String incomingClientId,
        @FormParam("lti_message_hint") String messageHint,
        @FormParam("lti_deployment_id") String deploymentId) {        
        System.out.println("LTI 1.3 login initiation was received");
        System.out.println("Issuer: " + issuer);
        System.out.println("Incoming client ID: " + incomingClientId);
        System.out.println("Target link URI: " + targetLinkUri);
        System.out.println("Deployment ID: " + deploymentId);
        System.out.println("Login hint was present: " + (loginHint != null));
        System.out.println("Message hint was present: " + (messageHint != null));

        /*
        if (!LTI13Platform.ISSUER.equals(issuer)) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity("The issuer parameter was missing.")
                .build();
        }
                     */

        URI issuerUri;
        
        try {
            issuerUri = URI.create(issuer);
        } catch (IllegalArgumentException exception) {
            return Response.status(Response.Status.BAD_REQUEST)
            .entity("The issuer parameter was invalid.")
            .build();
}

        if (!"https".equalsIgnoreCase(issuerUri.getScheme())
                || issuerUri.getHost() == null) { 
            return Response.status(Response.Status.BAD_REQUEST)
            .entity("The issuer must be a valid HTTPS URL.")
            .build();
        }
            
        String authorizationEndpoint =
            issuer.replaceAll("/+$", "")
            + "/mod/lti/auth.php";
                
        System.out.println("Authorization endpoint: "
            + authorizationEndpoint);

        if (loginHint == null || loginHint.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("The login_hint parameter was missing.")
                    .build();
        }

        if (targetLinkUri == null || targetLinkUri.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("The target_link_uri parameter was missing.")
                    .build();
        }

        if (incomingClientId == null || incomingClientId.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
            .entity("The client_id parameter was missing.")
            .build();
}

        String clientId = incomingClientId;
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();

        PENDING_LOGINS.put(
        state,
        new PendingLogin(
                nonce,
                targetLinkUri,
                issuer,
                clientId,
                Instant.now()
        )
);

String redirectUri = targetLinkUri;

UriBuilder authorizationRequest = UriBuilder
        .fromUri(authorizationEndpoint)
        .queryParam("scope", "openid")
        .queryParam("response_type", "id_token")
        .queryParam("response_mode", "form_post")
        .queryParam("prompt", "none")
        .queryParam("client_id", clientId)
        .queryParam("redirect_uri", redirectUri)
        .queryParam("login_hint", loginHint)
        .queryParam("state", state)
        .queryParam("nonce", nonce);

        if (messageHint != null && !messageHint.isBlank()) {
                String encodedMessageHint = java.net.URLEncoder.encode(
                        messageHint,
                        java.nio.charset.StandardCharsets.UTF_8
    );
        authorizationRequest.queryParam(
            "lti_message_hint",
            encodedMessageHint
    );
}
        System.out.println("OIDC redirect URI: " + redirectUri);

        URI redirect = authorizationRequest.buildFromEncoded();

        System.out.println("Redirecting browser to Moodle authorization");

        return Response.seeOther(redirect).build();
    }

    @POST
    @Path("/deeplink")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public Response deepLink(
        @FormParam("state") String state,
        @FormParam("id_token") String idToken) {

    System.out.println("LTI 1.3 deeplink endpoint was reached");
    System.out.println("State was present: " + (state != null));
    System.out.println("ID token was present: " + (idToken != null));

    PendingLogin pending = PENDING_LOGINS.get(state);
    System.out.println("Pending login found: " + (pending != null));

    
    if (pending == null) {
        return Response.status(Response.Status.UNAUTHORIZED)
            .entity("Unknown or expired state")
            .build();
}

    try {
        var claims = tokenVerifier.verify(
            idToken,
            pending.issuer()
);

        String deploymentId = claims.get(
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id",
        String.class
);
        System.out.println("Deployment ID present: " + (deploymentId != null));

        Object messageType = claims.get(
        "https://purl.imsglobal.org/spec/lti/claim/message_type"
);
        System.out.println("LTI message type: " + messageType);

        if (!"LtiDeepLinkingRequest".equals(messageType)) {
                return Response.status(Response.Status.BAD_REQUEST)
                .entity("This endpoint expected an LTI Deep Linking Request.")
                .build();
}


        System.out.println("JWT signature verified");

        String returnedNonce = claims.get("nonce", String.class);

        System.out.println("Returned nonce was present: " + (returnedNonce != null));
        System.out.println("Nonce matched: " +
        (returnedNonce != null && pending.nonce().equals(returnedNonce)));
        
        if (returnedNonce == null ||
        !pending.nonce().equals(returnedNonce)) {
                
                return Response.status(Response.Status.UNAUTHORIZED)
                .entity("Nonce mismatch")
                .build();
        }

        Object settingsObject = claims.get(
                "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings"
);
        System.out.println("Deep linking settings present: "
        + (settingsObject != null));

        String deepLinkReturnUrl = null;

        String deepLinkData = null;

        if (settingsObject instanceof Map<?, ?> settings) {

                Object dataObject = settings.get("data");
                
                deepLinkData =
                        dataObject instanceof String ? (String) dataObject : null;
                        
                System.out.println("Deep linking data present: "
                        + (deepLinkData != null));

                Object returnUrl = settings.get("deep_link_return_url");

                System.out.println("Deep link return URL present: "
                        + (returnUrl != null));

                System.out.println("Deep link return URL: " + returnUrl);

                if (returnUrl instanceof String) {
                        deepLinkReturnUrl = (String) returnUrl;
}
}

if (deepLinkReturnUrl == null || deepLinkReturnUrl.isBlank()) {
    return Response.status(Response.Status.BAD_REQUEST)
            .entity("Missing deep_link_return_url")
            .build();
}

        System.out.println("JWT signature verified");
        System.out.println("Issuer: " + claims.getIssuer());

        URI targetUri = URI.create(pending.targetLinkUri());

        String toolBaseUrl =
            targetUri.getScheme()
            + "://"
            + targetUri.getAuthority();

        System.out.println("Tool base URL: " + toolBaseUrl);

        PENDING_LOGINS.remove(state);


        String html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Select CodeCheck Problem</title>
        </head>
        <body>
            <h2>Select a CodeCheck Problem</h2>

            <form method="POST" action="/LTI/1.3/select-problem">
                <label for="problemId">CodeCheck Problem ID:</label>
                <input type="text" id="problemId" name="problem_id" required>

                <input type="hidden" name="deep_link_return_url" value="%s">
                <input type="hidden" name="deployment_id" value="%s">
                <input type="hidden" name="client_id" value="%s">
                <input type="hidden" name="data" value="%s">
                
                <input type="hidden" name="platform_issuer" value="%s">
                <input type="hidden" name="client_id" value="%s">
                <input type="hidden" name="tool_base_url" value="%s">

                <button type="submit">Use This Problem</button>
            </form>
        </body>
        </html>
        """.formatted(
<<<<<<< HEAD
        deepLinkReturnUrl,
        deploymentId,
        deepLinkData == null ? "" : deepLinkData,
        pending.issuer(),
        pending.clientId(),
        toolBaseUrl
=======
            deepLinkReturnUrl,
            deploymentId,
            pending.clientId(),
            deepLinkData == null ? "" : deepLinkData
>>>>>>> e81679d5beef65198d03201e9618b21fa3ac3fcd
);

return Response.ok(html)
        .type(MediaType.TEXT_HTML)
        .build();

    } catch (Exception e) {
        System.out.println("JWT verification failed: " + e.getMessage());

        return Response.status(Response.Status.UNAUTHORIZED)
                .entity("JWT verification failed")
                .build();
    }
} 
                
    @POST
    @Path("/select-problem")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public Response selectProblem(
        @FormParam("problem_id") String problemId,
        @FormParam("deep_link_return_url") String deepLinkReturnUrl,
        @FormParam("deployment_id") String deploymentId,
        @FormParam("data") String deepLinkData,
        @FormParam("platform_issuer") String platformIssuer,
        @FormParam("client_id") String clientId,
        @FormParam("tool_base_url") String toolBaseUrl) {

    System.out.println("Problem selection received");
    System.out.println("Platform issuer: " + platformIssuer);
    System.out.println("Client ID present: "
    + (clientId != null && !clientId.isBlank()));
    System.out.println("Problem ID: " + problemId);
    
    if (platformIssuer == null || platformIssuer.isBlank()) {
        return Response.status(Response.Status.BAD_REQUEST)
            .entity("Missing platform issuer")
            .build();
}

    if (clientId == null || clientId.isBlank()) {
        return Response.status(Response.Status.BAD_REQUEST)
            .entity("Missing client ID")
            .build();
}

    if (toolBaseUrl == null || toolBaseUrl.isBlank()) {
        return Response.status(Response.Status.BAD_REQUEST)
            .entity("Missing tool base URL")
            .build();
}

    String launchUrl =
        toolBaseUrl + "/LTI/1.3/launch";
    
    System.out.println("Launch URL: " + launchUrl);
    
    Map<String, Object> contentItem = Map.of(
        "type", "ltiResourceLink",
        "title", "CodeCheck",
        "url", launchUrl,
        "custom", Map.of(
                "problem_id", problemId
        )
    );

    System.out.println("Content item created: " + contentItem);

    List<Map<String, Object>> contentItems = List.of(contentItem);

    String responseJwt =
        deepLinkResponseService.createResponseJwt(
            clientId,
                deploymentId,
                contentItems,
                deepLinkData
        );
    System.out.println("Deep Linking Response JWT created: "
        + (responseJwt != null && !responseJwt.isBlank()));

    System.out.println("Deep Linking Response JWT length: "
        + responseJwt.length());
    
    System.out.println("Content items: " + contentItems);

    System.out.println("Deep link return URL present: "
            + (deepLinkReturnUrl != null));


    System.out.println("Deployment ID present: "
        + (deploymentId != null));
    
    System.out.println("Deep linking data present: "
        + (deepLinkData != null && !deepLinkData.isBlank()));

    String returnHtml = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Returning to Moodle</title>
        </head>
        <body>
            <form id="deepLinkReturn"
                  method="POST"
                  action="%s">

                <input type="hidden"
                       name="JWT"
                       value="%s">
            </form>

            <script>
                document.getElementById("deepLinkReturn").submit();
            </script>
        </body>
        </html>
        """.formatted(
                deepLinkReturnUrl,
                responseJwt
        );

return Response.ok(returnHtml)
        .type(MediaType.TEXT_HTML)
        .build();
}

   @POST
   @Path("/problem")
   @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
   @Produces(MediaType.TEXT_HTML)
   public Response problemLaunch(
        @FormParam("state") String state,
        @FormParam("id_token") String idToken) {

    var problemId = "TODO: get from state or id_token"; // Placeholder for actual problem ID extraction logic
    System.out.println("LTI 1.3 problem launch endpoint was reached");
    System.out.println("Problem ID: " + problemId);
    System.out.println("State was present: " + (state != null));
    System.out.println("ID token was present: " + (idToken != null));
    
   return Response.ok(
        "LTI 1.3 problem launch reached for problem: "
        + problemId
).build();
}

    @POST
    @Path("/launch")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public Response launch(
        @FormParam("state") String state,
        @FormParam("id_token") String idToken) {

    System.out.println("LTI 1.3 launch endpoint was reached");
    System.out.println("State was present: "
            + (state != null && !state.isBlank()));
    System.out.println("ID token was present: "
            + (idToken != null && !idToken.isBlank()));

    
    if (state == null || state.isBlank()) {
        return Response.status(Response.Status.BAD_REQUEST)
                .entity("Missing state")
                .build();
    }

    if (idToken == null || idToken.isBlank()) {
        return Response.status(Response.Status.BAD_REQUEST)
                .entity("Missing id_token")
                .build();
    }

    
    PendingLogin pending = PENDING_LOGINS.get(state);

    System.out.println("Pending login found: " + (pending != null));

    if (pending == null) {
        return Response.status(Response.Status.UNAUTHORIZED)
                .entity("Unknown or expired state")
                .build();
    }

    try {
        
        var claims = tokenVerifier.verify(
                idToken,
                pending.issuer()
        );

        System.out.println("JWT signature verified");

        
        
        String returnedIssuer = claims.getIssuer();

        System.out.println("Returned issuer: " + returnedIssuer);
        System.out.println("Issuer matched: "
                + pending.issuer().equals(returnedIssuer));

        if (!pending.issuer().equals(returnedIssuer)) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("Issuer mismatch")
                    .build();
        }

        
        String returnedNonce = claims.get("nonce", String.class);

        System.out.println("Returned nonce was present: "
                + (returnedNonce != null));

        System.out.println("Nonce matched: "
                + (returnedNonce != null
                && pending.nonce().equals(returnedNonce)));

        if (returnedNonce == null
                || !pending.nonce().equals(returnedNonce)) {

            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("Nonce mismatch")
                    .build();
        }

        
        
        Object messageType = claims.get(
                "https://purl.imsglobal.org/spec/lti/claim/message_type"
        );

        System.out.println("LTI message type: " + messageType);

        if (!"LtiResourceLinkRequest".equals(messageType)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(
                        "This endpoint expected an LTI Resource Link Request."
                    )
                    .build();
        }

        
        String deploymentId = claims.get(
                "https://purl.imsglobal.org/spec/lti/claim/deployment_id",
                String.class
        );

        System.out.println("Deployment ID present: "
                + (deploymentId != null));

        Object endpointObject = claims.get(
        "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"
);

System.out.println(
        "AGS endpoint claim: " + endpointObject
);

String agsToken = agsService.getAccessToken(
         "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem"
);

System.out.println(
        "AGS access token received: "
        + (agsToken != null && !agsToken.isBlank())
);

String lineItemsUrl = null;

if (endpointObject instanceof Map<?, ?> endpoint) {
    Object lineItemsObject =
            endpoint.get("lineitems");

    if (lineItemsObject != null) {
        lineItemsUrl =
                lineItemsObject.toString();
    }
}

System.out.println(
        "AGS lineitems URL present: "
        + (lineItemsUrl != null
        && !lineItemsUrl.isBlank())
);

String lineItemsResponse = null;

if (lineItemsUrl != null
        && !lineItemsUrl.isBlank()) {

    lineItemsResponse =
            agsService.getLineItems(
                    lineItemsUrl,
                    agsToken
            );

    System.out.println(
            "AGS lineitems response received: "
            + (lineItemsResponse != null)
    );

    System.out.println(
            "AGS lineitems response: "
            + lineItemsResponse
    );
}
        
        Object customObject = claims.get(
                "https://purl.imsglobal.org/spec/lti/claim/custom"
        );

        System.out.println("Custom claim present: "
                + (customObject != null));

        String problemId = null;

        if (customObject instanceof Map<?, ?> custom) {
            Object problemIdObject = custom.get("problem_id");

            if (problemIdObject != null) {
                problemId = problemIdObject.toString();
            }
        }

        System.out.println("Problem ID from custom claim: " + problemId);

        if (problemId == null || problemId.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Missing custom.problem_id")
                    .build();
        }


    

        String userId = claims.getSubject();
        
        
        System.out.println("LTI user subject present: "
            + (userId != null && !userId.isBlank()));
            
        if (userId == null || userId.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity("Missing LTI subject")
                .build();
}

    

    Object resourceLinkObject = claims.get(
        "https://purl.imsglobal.org/spec/lti/claim/resource_link"
);

    String resourceLinkId = null;

        if (resourceLinkObject instanceof Map<?, ?> resourceLink) {
            Object idObject = resourceLink.get("id");

        if (idObject != null) {
            resourceLinkId = idObject.toString();
    }
}

        System.out.println(
            "Resource Link ID present: "
            + (resourceLinkId != null
            && !resourceLinkId.isBlank())
);


    if (resourceLinkId == null
        || resourceLinkId.isBlank()) {

        return Response.status(Response.Status.BAD_REQUEST)
            .entity("Missing resource link ID")
            .build();
}


    if (lineItemsResponse != null
        && "[]".equals(lineItemsResponse.trim())
        && lineItemsUrl != null
        && !lineItemsUrl.isBlank()) {

    String createdLineItem =
            agsService.createLineItem(
                    lineItemsUrl,
                    agsToken,
                    resourceLinkId
            );

    System.out.println(
            "AGS created lineitem response: "
            + createdLineItem
    );

    lineItemsResponse = createdLineItem;
}

        String lineItemId =
        agsService.extractLineItemId(
                lineItemsResponse
        );

System.out.println(
        "AGS lineitem ID present: "
        + (lineItemId != null
        && !lineItemId.isBlank())
);

if (lineItemId == null
        || lineItemId.isBlank()) {

    return Response.status(
            Response.Status.BAD_REQUEST
    )
    .entity("Missing AGS lineitem ID")
    .build();
}







        String submissionId =
            "lti13:"
            + pending.issuer()
            + ":"
            + resourceLinkId
            + ":"
            + userId;

        problemService.registerLTI13AGSContext(
        submissionId,
        lineItemId,
        userId
);

System.out.println(
        "LTI 1.3 AGS context registered"
);

        System.out.println(
            "LTI 1.3 submission ID created"
        );

        String ccid = userId;

        
        PENDING_LOGINS.remove(state);

        System.out.println(
                "LTI 1.3 Resource Link launch authenticated successfully"
        );

        System.out.println(
        "Rendering CodeCheck problem: " + problemId
);

String document = problemService.launchCodeCheck13(
        CodeCheck.DEFAULT_REPO,
        problemId,
        ccid,
        submissionId
);

System.out.println(
        "CodeCheck problem HTML created successfully"
);

return Response.ok(document)
        .type(MediaType.TEXT_HTML)
        .build();
        
    } catch (Exception e) {
        System.out.println(
                "LTI 1.3 launch JWT verification failed: "
                + e.getMessage()
        );

        return Response.status(Response.Status.UNAUTHORIZED)
                .entity("JWT verification failed")
                .build();
    }
}

}