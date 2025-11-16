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

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import org.imsglobal.lti.launch.LtiOauthSigner;
import org.imsglobal.lti.launch.LtiSigningException;

@RequestScoped
@jakarta.ws.rs.Path("/")
public class LTIAssignmentController {
    @Inject services.LTIAssignment assignmentService;
    @Inject JWT jwt;
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
    // For LTI Deeplinking launch to a LMS (LTI 1.1)
public Response contentSelection(MultivaluedMap<String, String> formParams)
        throws IOException, InvalidKeyException, LtiSigningException {
    try {
        var signer = new LtiOauthSigner();
        var json = """
{
  "@context" : "http://purl.imsglobal.org/ctx/lti/v1/ContentItem",
  "@graph" : [
    { "@type" : "FileItem",
      "url" : "https://www.imsglobal.org/sites/default/files/IMSconformancelogosm.png",
      "mediaType" : "image/png",
      "text" : "1EdTech logo for certified products",
      "title" : "The logo used to identify 1EdTech certified products",
      "placementAdvice" : {
        "displayWidth" : 147,
        "displayHeight" : 184,
        "presentationDocumentTarget" : "embed"
      }
    }
  ]
}""";
            var request = new HashMap<String, String>();
            request.put("lti_message_type", "ContentItemSelection");
            request.put("lti_version", "LTI-1p0");
            request.put("content_items", escapeJSONAttribute(json));
            // using the escaped json and non-escaped version shows double encoding(?)
            // based on Tsugi's base string comparison tool
            //request.put("content_items", json);

            String return_url = formParams.getFirst("content_item_return_url");
            // consumer key and secret hardcoded to match contentSelection tool in Moodle
            var signed = signer.signParameters(request, "consumer", "secret", return_url, "POST");
            StringBuilder result = new StringBuilder();
            result.append(String.format(part1, return_url));
            for (Map.Entry<String, String> entry : signed.entrySet()) {
                result.append(String.format(formParamPart,
                                            entry.getKey(),
                                            entry.getValue()));
            }
            result.append(part2);
            return Response.ok(result.toString()).build();
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    String escapeJSONAttribute(String attr) {
        return attr.replace("&", "&amp;")
                .replace("\"", "&quot;")
                .replaceAll("\\s+", " ");
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

    private String part1 = """
                <html>
                    <head><title>Content Selector</title></head>
                    <body>
                        <form method="post" action="%s">
                            <label for="problemURL">Enter a CodeCheck Problem URL:</label><br>
                """;

    private String formParamPart = """
                            <input type="hidden" name="%s" value="%s" />
                """;

    private String part2 ="""
                            <input type="submit" value="Submit">
                        </form>
                    </body>
                </html>
                """;

    private String content_items_example = 
    """
{"@context": [
    "http://purl.imsglobal.org/ctx/lti/v1/ContentItem",
    {
      "lineItem": "http://purl.imsglobal.org/ctx/lis/v2/LineItem",
      "res": "http://purl.imsglobal.org/ctx/lis/v2p1/Result#"
    }
  ],
  "@graph": [
    {
      "@type": "LtiLinkItem",
      "mediaType": "application/vnd.ims.lti.v1.ltilink",
      "title": "Deep Linking Test Item",
      "text": "Launch this test item from the LMS.",
      "url": "https://legendary-space-acorn-x5vr74v5vx693pw49-8080.app.github.dev/lti/problem",
      "custom": {
        "attempt_id": "test-001",
        "mode": "practice"
      },
      "lineItem": {
        "@type": "LineItem",
        "label": "Deep Linking Test Grade",
        "reportingMethod": "res:totalScore",
        "assignedActivity": {
          "@id": "https://www.wikipedia.org/",
          "activity_id": "test-001"
        },
        "scoreConstraints": {
          "@type": "NumericLimits",
          "normalMaximum": 100,
          "extraCreditMaximum": 0,
          "totalMaximum": 100
        }
      }
    }
  ]
}""";
}