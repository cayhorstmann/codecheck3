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
import services.LTI13Platform;

import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.inject.Inject;
import services.LTI13KeyService;

@RequestScoped
@Path("/LTI/1.3")
public class LTI13Controller {

    @Inject
    LTI13KeyService keyService;

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

        String clientId = LTI13Platform.CLIENT_ID;
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();

        PENDING_LOGINS.put(
                state,
                new PendingLogin(nonce, targetLinkUri, Instant.now())
        );

        UriBuilder authorizationRequest = UriBuilder
                .fromUri(LTI13Platform.AUTHORIZATION_ENDPOINT)
                .queryParam("scope", "openid")
                .queryParam("response_type", "id_token")
                .queryParam("response_mode", "form_post")
                .queryParam("prompt", "none")
                .queryParam("client_id", clientId)
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

        return Response.status(Response.Status.UNAUTHORIZED)
                .entity("""
                        Moodle reached the CodeCheck LTI 1.3 deep-link endpoint.

                        The request was received, but JWT authentication
                        has not been implemented yet.
                        """)
                .build();
    }

    @POST
    @Path("/launch")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_PLAIN)
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