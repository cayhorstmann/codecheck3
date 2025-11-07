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
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

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
    public Response contentSelection(MultivaluedMap<String, String> formParams) throws IOException {
        try {
            // result is a HTML form that gets a problem URL from the instructor
            // and POSTs it to lti/problem alongwith LMS payload
            StringBuilder result = new StringBuilder();
            result.append(part1);
            formParams.forEach((key, values) -> {
                result.append(formParamPart.formatted(key, values));
            });
            result.append(part2);
            return Response.ok(result.toString()).build();
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
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
                        <form method="post" action="/lti/problem">
                            <label for="problemURL">Enter a CodeCheck Problem URL:</label><br>
                            <input type="text" id="problemURL" name="problemURL"><br>

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
}