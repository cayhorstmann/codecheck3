package services;


import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.JsonNode;
import controllers.Config;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.script.ScriptException;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.horstmann.codecheck.checker.Problem;
import com.horstmann.codecheck.checker.Util;

import oauth.signpost.exception.OAuthException;

@ApplicationScoped
public class LTIProblem {
    @Inject StorageConnector storageConn;
    @Inject LTI lti;
    @Inject CodeCheck codeCheck;
    @Inject Config config;
    @Inject Assignment assignmentService;
    @Inject LTI13AGSService agsService;

    private final Map<String, LTI13AGSContext> lti13AgsContexts =
        new ConcurrentHashMap<>();

    private record LTI13AGSContext(
        String lineItemId,
        String userId) {
}

    public void registerLTI13AGSContext(
        String submissionId,
        String lineItemId,
        String userId) {

    lti13AgsContexts.put(
            submissionId,
            new LTI13AGSContext(
                    lineItemId,
                    userId
            )
    );
}


    private ObjectNode ltiNode(String url, Map<String, String[]> postParams) {
        if (!lti.validate(url, postParams)) throw new ServiceException("Failed OAuth validation");
        
        String userID = Util.getParam(postParams, "user_id");
        if (Util.isEmpty(userID)) throw new ServiceException("No user id");

        String toolConsumerID = Util.getParam(postParams, "tool_consumer_instance_guid");
        String contextID = Util.getParam(postParams, "context_id");
        String resourceLinkID = Util.getParam(postParams, "resource_link_id");

        String resourceID = toolConsumerID + "/" + contextID + "/" + resourceLinkID; 
        
        ObjectNode ltiNode = JsonNodeFactory.instance.objectNode();

        ltiNode.put("lis_outcome_service_url", Util.getParam(postParams, "lis_outcome_service_url"));
        ltiNode.put("lis_result_sourcedid", Util.getParam(postParams, "lis_result_sourcedid"));
        ltiNode.put("oauth_consumer_key", Util.getParam(postParams, "oauth_consumer_key"));

        ltiNode.put("submissionID", resourceID + " " + userID);     
        ltiNode.put("retrieveURL", "/lti/retrieve");
        ltiNode.put("sendURL", "/lti/send");
        
        return ltiNode;
    }
    
    private String rewriteRelativeLinks(String urlString) throws IOException {
        URL url = URI.create(urlString).toURL();
        InputStream in = url.openStream();
        String contents = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        in.close();
        int i1 = urlString.indexOf("/", 8); // after https://
        String domain = urlString.substring(0, i1);
        
        Pattern pattern = Pattern.compile("\\s+(src|href)=[\"']([^\"']+)[\"']");
        Matcher matcher = pattern.matcher(contents);
        int previousEnd = 0;
        String document = "";
        while (matcher.find()) {
            int start = matcher.start();
            document += contents.substring(previousEnd, start);
            String group1 = matcher.group(1);
            String group2 = matcher.group(2);
            document += " " + group1 + "='";
            if (group2.startsWith("http:") || group2.startsWith("https:") || group2.startsWith("data:"))
                document += group2;
            else if (group2.startsWith("/"))
                document += domain + "/" + group2;
            else if (group2.equals("assets/receiveMessage.js")){ // TODO: Hack?
                document += "/" + group2;
            } else {
                int i = urlString.lastIndexOf("/");
                document += urlString.substring(0, i + 1) + group2;
            }               
            document += "'";
            previousEnd = matcher.end();
        }           
        document += contents.substring(previousEnd);        
        return document;
    }

    public String launch(String url, String qid, Map<String, String[]> postParams) throws IOException {    
        ObjectNode ltiNode = ltiNode(url, postParams);
        
        if (qid == null) throw new ServiceException("No qid");
        String urlString = assignmentService.qidURL(qid);
        if (urlString == null) throw new ServiceException("Bad qid: " + qid);
        String document = rewriteRelativeLinks(urlString);
        document = document.replace("<head>", "<head><script>const lti = " + ltiNode.toString() + "</script>");
        return document;
    }       
    
    public String launchCodeCheck(
        String url,
        String repo,
        String problemName,
        String ccid,
        Map<String, String[]> postParams)
        throws NoSuchMethodException, IOException, ScriptException {

    
    ObjectNode ltiNode = ltiNode(url, postParams);

    return renderCodeCheck(
            repo,
            problemName,
            ccid,
            ltiNode
    );
}

public String launchCodeCheck13(
        String repo,
        String problemName,
        String ccid,
        String submissionId)
        throws NoSuchMethodException, IOException, ScriptException {

    ObjectNode ltiNode =
            JsonNodeFactory.instance.objectNode();

    ltiNode.put("submissionID", submissionId);

    
    ltiNode.put("retrieveURL", "/lti/retrieve");
    ltiNode.put("sendURL", "/lti/send");

    return renderCodeCheck(
            repo,
            problemName,
            ccid,
            ltiNode
    );
}
    

    private String renderCodeCheck(
        String repo,
        String problemName,
        String ccid,
        ObjectNode ltiNode)
        throws NoSuchMethodException, IOException, ScriptException {

    Map<Path, byte[]> problemFiles =
            codeCheck.loadProblem(repo, problemName, ccid);

    Problem problem = new Problem(problemFiles);
    Problem.DisplayData data = problem.getProblemData();

    ObjectNode problemNode = Util.toJson(data);

    problemNode.put("url", "/checkNJS");
    problemNode.put("repo", repo);
    problemNode.put("problem", problemName);
    problemNode.remove("description");

    String qid =
            "codecheck-" + repo + "-" + problemName;

    String document =
            "<?xml version='1.0' encoding='UTF-8'?>\n" +
            "<html xmlns='http://www.w3.org/1999/xhtml'>\n" +
            "  <head>\n" +
            "    <meta http-equiv='content-type' content='text/html; charset=UTF-8'/>\n" +
            "    <title>Interactivities</title> \n" +
            "    <script src='/assets/download.js'></script>\n" +
            "    <script src='/assets/ace/ace.js'></script>\n" +
            "    <script src='/assets/ace/theme-kuroir.js'></script>\n" +
            "    <script src='/assets/ace/theme-chrome.js'></script>\n" +
            "    <script src='/assets/util.js'></script>\n" +
            "    <script src='/assets/codecheck2.js'></script>\n" +
            "    <script src='/assets/horstmann_codecheck.js'></script>\n" +
            "    <link type='text/css' rel='stylesheet' href='/assets/codecheck.css'/>\n" +
            "    <link type='text/css' rel='stylesheet' href='/assets/horstmann_codecheck.css'/>\n" +
            "    <style type='text/css'>\n" +
            "      ol.interactivities > li {\n" +
            "        list-style: none;\n" +
            "        margin-bottom: 2em;\n" +
            "      }\n" +
            "      body {\n" +
            "        margin-left: 2em;\n" +
            "        margin-right: 2em;\n" +
            "        overflow-y: visible;\n" +
            "      }\n" +
            "    </style>\n" +
            "    <script type='text/javascript'>//<![CDATA[\n" +
            "horstmann_config.lti = " + ltiNode.toString() +
            "\nhorstmann_codecheck.setup.push(\n" +
            problemNode.toString() +
            ")\n" +
            "\n//]]></script>\n" +
            "  </head> \n" +
            "  <body>\n" +
            "    <p>Submission ID: "
            + ltiNode.get("submissionID").asText()
            + "</p>" +
            "    <ol class='interactivities' id='interactivities'>\n" +
            "      <li title='" + qid + "' id='" + qid + "'>\n" +
            "        <div class='hc-included'>\n" +
            (data.description == null ? "" : data.description) +
            "        </div>\n" +
            "        <div class='horstmann_codecheck'>\n" +
            "        </div>\n" +
            "      </li>\n" +
            "    </ol>" +
            "  </body>" +
            "</html>";

    return document;
}
    
    private static String tracerStart = "<!DOCTYPE html>\n"
            + "<html>\n"
            + "<head>\n"
            + "  <meta charset=\"utf-8\">\n"
            + "  <link href='https://horstmann.com/codecheck/css/codecheck_tracer.css' rel='stylesheet' type='text/css'/>  "
            + "  <title>CodeCheck Tracer</title>\n"
            + "  <script src='/assets/util.js'></script>\n"
            + "  <script src='/assets/codecheck2.js'></script>\n"
            + "</head>\n"
            + "<body>\n";
    private static String tracerScriptStart = "    <div class='codecheck_tracer'>\n"
            + "      <script type='module'>//<![CDATA[\n";
    private static String tracerEnd = "// ]]>\n"
            + "      </script>\n"
            + "  </div>\n"
            + "</body>\n"
            + "</html>";    
    
    public String launchTracer(String url, String repo, String problemName, String ccid, Map<String, String[]> postParams) throws NoSuchMethodException, IOException, ScriptException {
        ObjectNode ltiNode = ltiNode(url, postParams);            
        Map<Path, byte[]> problemFiles = codeCheck.loadProblem(repo, problemName, ccid);

        Problem problem = new Problem(problemFiles);
        StringBuilder result = new StringBuilder();
        Problem.DisplayData data = problem.getProblemData();            
        result.append(tracerStart);
        result.append("    <p>Submission ID: " + ltiNode.get("submissionID").asText() + "</p>");
        if (data.description != null)
            result.append(data.description);
        result.append(tracerScriptStart);
        result.append("horstmann_config.lti = " + ltiNode.toString() + "\n");
        result.append(Util.getString(problemFiles, Path.of("tracer.js")));
        result.append(tracerEnd);
        return result.toString();
    }
    
    public ObjectNode send(JsonNode requestNode) throws IOException, NoSuchAlgorithmException, OAuthException, URISyntaxException {
        String submissionID = requestNode.get("submissionID").asText();
        String submittedAt = Instant.now().toString();
        ObjectNode submissionNode = JsonNodeFactory.instance.objectNode();
        submissionNode.put("submissionID", submissionID);
        submissionNode.put("submittedAt", submittedAt);
        submissionNode.put("state", requestNode.get("state").toString());
        double score = requestNode.get("score").asDouble();         
        submissionNode.put("score", score);
        storageConn.writeSubmission(submissionNode);
        
        JsonNode outcomeServiceUrlNode =
            requestNode.get("lis_outcome_service_url");

        JsonNode sourcedIDNode =
            requestNode.get("lis_result_sourcedid");

        JsonNode oauthConsumerKeyNode =
            requestNode.get("oauth_consumer_key");

        if (outcomeServiceUrlNode != null
            && sourcedIDNode != null
            && oauthConsumerKeyNode != null) {

    String outcomeServiceUrl =
            outcomeServiceUrlNode.asText();

    String sourcedID =
            sourcedIDNode.asText();

    String oauthConsumerKey =
            oauthConsumerKeyNode.asText();

    if (!sourcedID.startsWith("__test__")) {
        lti.passbackGradeToLMS(
                outcomeServiceUrl,
                sourcedID,
                score,
                oauthConsumerKey
        );
    }
}

    LTI13AGSContext agsContext =
        lti13AgsContexts.get(submissionID);

if (agsContext != null) {

    try {
        String agsToken =
                agsService.getAccessToken(
                        "https://purl.imsglobal.org/spec/lti-ags/scope/score"
                );

        System.out.println(
                "LTI 1.3 AGS score token received: "
                + (agsToken != null
                && !agsToken.isBlank())
        );

        agsService.sendScore(
                agsContext.lineItemId(),
                agsToken,
                agsContext.userId(),
                score
        );

        System.out.println(
                "LTI 1.3 grade return completed"
        );

    } catch (Exception exception) {

        throw new ServiceException(
                "LTI 1.3 AGS grade return failed: "
                + exception.getMessage()
        );
    }
}

        ObjectNode resultNode = JsonNodeFactory.instance.objectNode();
        resultNode.put("score", score);
        resultNode.put("submittedAt", submittedAt);
        return resultNode;
    }
    
    public ObjectNode retrieve(JsonNode requestNode) throws IOException {
    String submissionID = requestNode.get("submissionID").asText();

    ObjectNode result =
            storageConn.readNewestSubmission(submissionID);

    if (result == null) {
        result = JsonNodeFactory.instance.objectNode();
        result.putNull("state");
        return result;
    }

    result.set(
            "state",
            Util.fromJsonString(result.get("state").asText())
    );

    return result;
}

}