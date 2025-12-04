package controllers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.horstmann.codecheck.checker.Util;
import io.smallrye.common.annotation.RunOnVirtualThread;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import services.CodeCheck;
import services.ServiceException;

import javax.script.ScriptException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

@RequestScoped
@jakarta.ws.rs.Path("/")
public class CheckController {
    @Inject
    services.Check checkService;

    @POST
    @jakarta.ws.rs.Path("/run")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_PLAIN)
    public Response runFormPost(MultivaluedMap<String, String> formParams) throws ScriptException, IOException, InterruptedException, NoSuchMethodException {
        try {
            Map<Path, String> submissionFiles = new TreeMap<>();

            for (Map.Entry<String, List<String>> entry : formParams.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue().getFirst();
                submissionFiles.put(Paths.get(key), value);
            }

            String result = checkService.run(submissionFiles);
            return Response.ok(result).build();
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    @POST
    @jakarta.ws.rs.Path("/run")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.TEXT_PLAIN)
    public Response runFileUpload(List<EntityPart> parts) throws ScriptException, IOException, InterruptedException, NoSuchMethodException {
        Map<Path, String> submissionFiles = new TreeMap<>();
        try {
            for (EntityPart part : parts) {
                String name = part.getName();
                InputStream is = part.getContent();
                submissionFiles.put(Path.of(name), new String(is.readAllBytes()));
            }
            String result = checkService.run(submissionFiles);
            return Response.ok(result).build();
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    @POST
    @jakarta.ws.rs.Path("/run")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response runJSON(JsonNode json) throws ScriptException, IOException, InterruptedException, NoSuchMethodException {
        try {
            ObjectNode result = checkService.runJSON(json);
            return Response.ok(result).build();
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    @POST
    @jakarta.ws.rs.Path("/checkNJS")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @RunOnVirtualThread
    public Response checkNJS(JsonNode json, @CookieParam("ccid") String ccid) throws ScriptException, IOException, InterruptedException, NoSuchMethodException {
        try {
            if (ccid == null) ccid = Util.createPronouncableUID();
            ObjectNode result = checkService.checkNJS(json, ccid);
            return Response.ok(result).cookie(HttpUtil.buildCookie("ccid", ccid)).build();
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    @GET
    @jakarta.ws.rs.Path("/setupData/{repo}/{problem}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response setupReport(@PathParam("repo") String repo, @PathParam("problem") String problemName,
                             @CookieParam("ccid") String ccid) throws IOException, ScriptException, InterruptedException, NoSuchMethodException {
        try {
            if (ccid == null) ccid = Util.createPronouncableUID();
            String result = checkService.setupReport(repo, problemName, ccid);
            return Response.ok(result).cookie(HttpUtil.buildCookie("ccid", ccid)).build();
        } catch (ServiceException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
    }

    @GET
    @jakarta.ws.rs.Path("/setupData/{problem}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response setupReport(@PathParam("problem") String problemName,
                             @CookieParam("ccid") String ccid) throws IOException, ScriptException, InterruptedException, NoSuchMethodException {
        return setupReport(CodeCheck.DEFAULT_REPO, problemName, ccid);
    }
}
