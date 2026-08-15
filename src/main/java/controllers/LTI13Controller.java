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

        if (!LTI13Platform.ISSUER.equals(issuer)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Unknown Moodle issuer.")
                    .build();
        }

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

        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();

        PENDING_LOGINS.put(
                state,
            new PendingLogin(nonce, incomingClientId, targetLinkUri, Instant.now())
        );

        UriBuilder authorizationRequest = UriBuilder
                .fromUri(LTI13Platform.AUTHORIZATION_ENDPOINT)
                .queryParam("scope", "openid")
                .queryParam("response_type", "id_token")
                .queryParam("response_mode", "form_post")
                .queryParam("prompt", "none")
                .queryParam("client_id", incomingClientId)
                .queryParam("redirect_uri", targetLinkUri)
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
        var claims = tokenVerifier.verify(idToken);

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

                <button type="submit">Use This Problem</button>
            </form>
        </body>
        </html>
        """.formatted(
            deepLinkReturnUrl,
            deploymentId,
            pending.clientId(),
            deepLinkData == null ? "" : deepLinkData
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
    @Produces(MediaType.TEXT_PLAIN)
    public Response selectProblem(
        @FormParam("problem_id") String problemId,
        @FormParam("deep_link_return_url") String deepLinkReturnUrl,
        @FormParam("deployment_id") String deploymentId,
        @FormParam("client_id") String clientId,
        @FormParam("data") String deepLinkData) {

    System.out.println("Problem selection received");
    System.out.println("Problem ID: " + problemId);
    String problemUrl =
        "https://probable-space-telegram-vp5754jjgwjhwqgx-8080.app.github.dev"
        + "/LTI/1.3/problem/"
        + problemId;
    System.out.println("Problem URL: " + problemUrl);     

    Map<String, Object> contentItem = Map.of(
        "type", "ltiResourceLink",
        "title", "CodeCheck Problem",
        "url", problemUrl
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
   @Path("/problem/{problemId}")
   @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
   @Produces(MediaType.TEXT_HTML)
   public Response problemLaunch(
        @PathParam("problemId") String problemId,
        @FormParam("state") String state,
        @FormParam("id_token") String idToken) {

    System.out.println("LTI 1.3 problem launch endpoint was reached");
    System.out.println("Problem ID: " + problemId);
    System.out.println("State was present: " + (state != null));
    System.out.println("ID token was present: " + (idToken != null));
        return Response.ok(
            "LTI 1.3 problem launch reached for problem: " + problemId
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
        System.out.println("State was present: " + (state != null));
        System.out.println("ID token was present: " + (idToken != null));

        


        return Response.status(Response.Status.UNAUTHORIZED)
                .entity("""
                        Moodle reached the CodeCheck LTI 1.3 launch endpoint.

                        The request was received, but JWT authentication
                        has not been implemented yet.
                        """)
                .build();
    }
}