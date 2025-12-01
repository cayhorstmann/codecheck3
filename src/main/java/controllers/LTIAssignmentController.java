package controllers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.horstmann.codecheck.checker.Util;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import services.JWT;
import oauth.signpost.exception.OAuthException;
import services.ServiceException;
import services.StorageConnector;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.imsglobal.lti.launch.LtiOauthSigner;
import org.imsglobal.lti.launch.LtiSigningException;

@RequestScoped
@jakarta.ws.rs.Path("/")
public class LTIAssignmentController {
    @Inject services.LTIAssignment assignmentService;
    @Inject JWT jwt;
    @Inject StorageConnector connector;
    @Context UriInfo uriInfo;
    @Context HttpHeaders headers;

    @GET
    @jakarta.ws.rs.Path("/lti/config")
    @Produces(MediaType.APPLICATION_XML)
    public Response config() throws IOException {
        String host = uriInfo.getBaseUri().getHost();
        String result = assignmentService.config(host);
        return Response.ok(result).build();
    }


    @POST
    @jakarta.ws.rs.Path("/lti/contentSelection")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
public Response contentSelection(MultivaluedMap<String, String> formParams)
        throws IOException, InvalidKeyException, LtiSigningException {
    try {
            // This only produces the form for the professor to input a link
            StringBuilder form = new StringBuilder();

            // This sets the form action to the other endpoint
            // to handle content_items and signing
            form.append(String.format(contentSelectionForm, "/lti/contentSelectionReturn"));

            // This will append formParams as hidden inputs
            // so that /lti/contentSelectionReturn can access the information
            for (Map.Entry<String, List<String>> entry : formParams.entrySet()) {
                String key = entry.getKey();
                for (String value : entry.getValue()) {
                    form.append(String.format(formParamPart, key, value));
                }
            }

            form.append(formEnding);
            return Response.ok(form.toString()).build();
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    @POST
    @jakarta.ws.rs.Path("/lti/contentSelectionReturn")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public Response contentSelectionReturn(MultivaluedMap<String, String> formParams)
        throws IOException, InvalidKeyException, LtiSigningException {
        try {
            var signer = new LtiOauthSigner();
            String json = String.format(content_item.replace("\n", ""), formParams.get("problem_url").getFirst());
            var request = new HashMap<String, String>();
            request.put("lti_message_type", "ContentItemSelection");
            request.put("lti_version", "LTI-1p0");
            request.put("data", "");
            request.put("content_items", json);

            String return_url = formParams.getFirst("content_item_return_url");

            String consumer_key = formParams.get("oauth_consumer_key").getFirst();
            String shared_secret = connector.readLTISharedSecret(consumer_key);
            var signed = signer.signParameters(request, consumer_key, shared_secret, return_url, "POST");

            // Create the HTML form
            StringBuilder result = new StringBuilder();
            result.append(String.format(contentSelectionReturnForm, return_url));
            for (Map.Entry<String, String> entry : signed.entrySet()) {
                result.append(String.format(formParamPart,
                                            entry.getKey(),
                                            escapeAttribute(entry.getValue())));
            }
            result.append(formEnding);
            return Response.ok(result.toString()).build();
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    String escapeAttribute(String attr) {
         return attr.replace("&", "&amp;")
                 .replace("\"", "&quot;");
    }

    @POST
    @jakarta.ws.rs.Path("/lti/createAssignment")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public Response createAssignment(MultivaluedMap<String, String> formParams) throws IOException {
        try {
            String url = HttpUtil.prefix(uriInfo, headers) + uriInfo.getPath();
            Map<String, String[]> postParams = HttpUtil.paramsMap(formParams);
            String result = assignmentService.createAssignment(url, postParams);
            // TODO Shouldn't that change the assignment in the auth token?
            return Response.ok(result).build();
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    @POST
    @jakarta.ws.rs.Path("/lti/saveAssignment")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response saveAssignment(JsonNode params) throws IOException {
        try {
            String host = uriInfo.getBaseUri().getHost();
            ObjectNode result = assignmentService.saveAssignment(host, params);
            return Response.ok(result).build();
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    @GET
    @jakarta.ws.rs.Path("/lti/viewSubmissions")
    @Produces(MediaType.TEXT_HTML)
    public Response viewSubmissions(@CookieParam("ccauth") String ccauth, @QueryParam("resourceID") String resourceID) throws IOException {
        try {
            // TODO No deed to pass resourceID
            Map<String, Object> auth = jwt.verify(ccauth);
            if (!resourceID.equals(auth.get("resourceID")))
                return Response.status(Response.Status.UNAUTHORIZED).entity("Unauthorized").build();
            String result = assignmentService.viewSubmissions(resourceID);
            return Response.ok(result).build();
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    @GET
    @jakarta.ws.rs.Path("/lti/viewSubmission")
    @Produces(MediaType.TEXT_HTML)
    public Response viewSubmission(@CookieParam("ccauth") String ccauth, @QueryParam("resourceID") String resourceID, @QueryParam("workID") String workID) throws IOException {
        try {
            // TODO No deed to pass resourceID
            Map<String, Object> auth = jwt.verify(ccauth);
            if (!resourceID.equals(auth.get("resourceID")))
                return Response.status(Response.Status.UNAUTHORIZED).entity("Unauthorized").build();
            String result = assignmentService.viewSubmission(resourceID, workID);
            return Response.ok(result).build();
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    @GET
    @jakarta.ws.rs.Path("/lti/editAssignment/{assignmentID}")
    @Produces(MediaType.TEXT_HTML)
    public Response editAssignment(@CookieParam("ccauth") String ccauth, @PathParam("assignmentID") String assignmentID) throws IOException {
        try {
            // TODO No deed to pass assignmentID
            Map<String, Object> auth = jwt.verify(ccauth);
            if (!assignmentID.equals(assignmentService.assignmentOfResource(auth.get("resourceID").toString())))
                return Response.status(Response.Status.UNAUTHORIZED).entity("Unauthorized").build();
            String result = assignmentService.editAssignment(assignmentID, auth.get("editKey").toString());
            return Response.ok(result).build();
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    @POST
    @jakarta.ws.rs.Path("/{a:assignment|viewAssignment}/{assignmentID}") // in case someone posts a viewAssignment URL instead of cloning it
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public Response launch(@PathParam("assignmentID") String assignmentID,
                           MultivaluedMap<String, String> formParams) throws IOException {
        try {
            String url = HttpUtil.prefix(uriInfo, headers) + uriInfo.getPath();
            Map<String, String[]> postParams = HttpUtil.paramsMap(formParams);
            String result = assignmentService.launch(url, assignmentID, postParams);
            if (services.LTIAssignment.isInstructor(postParams)) {
                String toolConsumerID = Util.getParam(postParams, "tool_consumer_instance_guid");
                String resourceID = toolConsumerID + "/" +
                        Util.getParam(postParams, "context_id") + " " + assignmentID;
                String editKey = toolConsumerID + "/" +
                        Util.getParam(postParams, "user_id");

                String ccauth = jwt.generate(Map.of("resourceID", resourceID, "editKey", editKey));
                return Response.ok(result).cookie(HttpUtil.buildCookie("ccauth", ccauth)).build();
            } else { // Student
                return Response.ok(result).build();
            }
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    @POST
    @jakarta.ws.rs.Path("/lti/bridge")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public Response launchBridge(@QueryParam("url") String url,
                           MultivaluedMap<String, String> formParams) throws IOException {
        return launch(url, formParams);
    }

    @GET
    @jakarta.ws.rs.Path("/lti/allSubmissions")
    @Produces(MediaType.APPLICATION_JSON)
    public Response allSubmissions(@CookieParam("ccauth") String ccauth, @QueryParam("resourceID") String resourceID) throws IOException {
        try {
            // TODO No deed to pass resourceID
            Map<String, Object> auth = jwt.verify(ccauth);
            if (!resourceID.equals(auth.get("resourceID")))
                return Response.status(Response.Status.UNAUTHORIZED).entity("Unauthorized").build();
            ObjectNode result = assignmentService.allSubmissions(resourceID);
            return Response.ok(result).build();
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    @POST
    @jakarta.ws.rs.Path("/lti/saveWork")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response saveWork(JsonNode params) throws IOException, OAuthException, NoSuchAlgorithmException, URISyntaxException {
        try {
            ObjectNode result = assignmentService.saveWork(params);
            return Response.ok(result).build();
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    @POST
    @jakarta.ws.rs.Path("/lti/sendScore")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response sendScore(JsonNode params) throws IOException, OAuthException, NoSuchAlgorithmException, URISyntaxException {
        try {
            ObjectNode result = assignmentService.sendScore(params);
            return Response.ok(result).build();
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    @POST
    @jakarta.ws.rs.Path("/lti/saveComment")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response saveComment(@CookieParam("ccauth") String ccauth, JsonNode params) throws IOException, OAuthException, NoSuchAlgorithmException, URISyntaxException {
        try {
            Map<String, Object> auth = jwt.verify(ccauth);
            ObjectNode result = assignmentService.saveComment(auth.get("resourceID").toString(), params);
            return Response.ok(result).build();
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    private String contentSelectionForm = """
                <html>
                    <body>
                        <form method="post" action="%s">
                            <label for="problem_url">Enter a CodeCheck Problem URL:</label><br>
                            <input type="text" name="problem_url"/>
                """;

    private String contentSelectionReturnForm = """
            <html>
                <body onload="document.forms[0].submit()">
                    <p>Returning selected content to Moodle…</p>
                    <form method="post" action="%s">
            """;

    private String formParamPart = """
                            <input type="hidden" name="%s" value="%s" />
                """;

    private String formEnding ="""
                            <input type="submit" value="Submit">
                        </form>
                    </body>
                </html>
                """;

    private String content_item = """
{
   "@context" : "http://purl.imsglobal.org/ctx/lti/v1/ContentItem",
   "@graph" : [
     { "@type" : "LtiLinkItem",
       "url" : "%s",
       "mediaType" : "application/vnd.ims.lti.v1.ltilink",
       "text" : "Launch CodeCheck Problem",
       "title" : "CodeCheck Problem",
       "placementAdvice" : {
         "displayWidth" : 147,
         "displayHeight" : 184,
         "presentationDocumentTarget" : "embed"
       }
     }
   ]
}""";
}