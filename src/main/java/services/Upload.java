package services;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.script.ScriptException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.horstmann.codecheck.checker.Util;

import controllers.HttpUtil;

@ApplicationScoped
public class Upload {
    private static final String DEFAULT_REPO = "ext";
    @Inject private CodeCheck codeCheck;

    private Map<Path, byte[]> checkEditKey(String problem, String editKey) throws IOException {
        Map<Path, byte[]> problemFiles = codeCheck.loadProblem(DEFAULT_REPO, problem);
        Path editKeyPath = Path.of("edit.key");
        if (problemFiles.containsKey(editKeyPath)) {
            String correctEditKey = new String(problemFiles.get(editKeyPath), StandardCharsets.UTF_8);
            if  (editKey.equals(correctEditKey.trim())) return problemFiles; 
        } ;
		throw new SecurityException("Bad edit key");        
    }

    private static Path longestCommonPrefix(Path p, Path q) {
        if (p == null || q == null) return null;
        int i = 0;
        boolean matching = true;
        while (matching && i < Math.min(p.getNameCount(), q.getNameCount())) {
            if (p.getName(i).equals(q.getName(i))) i++;
            else matching = false;
        }
        return i == 0 ? null : p.subpath(0, i);
    }
    
    public static Map<Path, byte[]> fixZip(Map<Path, byte[]> problemFiles) throws IOException {
        Path r = null;
        boolean first = true;
        for (Path p : problemFiles.keySet()) {
            if (first) { r = p; first = false; }
            else r = longestCommonPrefix(r, p);
        }
        if (r == null) return problemFiles;
        Map<Path, byte[]> fixedProblemFiles = new TreeMap<>();
        if(problemFiles.keySet().size() == 1) {
            fixedProblemFiles.put(r.getFileName(), problemFiles.get(r));
        }
        else {
            for (Map.Entry<Path, byte[]> entry : problemFiles.entrySet()) {
                fixedProblemFiles.put(r.relativize(entry.getKey()), entry.getValue());
            }
        }

        return fixedProblemFiles;
    }

    private String classifyFile(String filename, byte[] data) {
        if (Util.isText(data)) {
            return "text";
        } else if (Util.isImageFilename(filename)) {
            return "image";
        }
        return "binary";
    }

    private ArrayNode buildFileArray(ObjectMapper mapper, String filename, byte[] data, String fileType) {
        ObjectNode fileData = mapper.createObjectNode();
        if (!"text".equals(fileType)) {
            fileData.put(filename, Base64.getEncoder().encodeToString(data));
        } else {
            fileData.put(filename, new String(data, StandardCharsets.UTF_8));
        }

        ObjectNode metaData = mapper.createObjectNode();
        metaData.put("fileType", fileType);

        ArrayNode fileArray = mapper.createArrayNode();
        fileArray.add(fileData);
        fileArray.add(metaData);
        return fileArray;
    }

    private String renderFileBlock(int index, String fileName, String fileType, String fileContents) {
    switch (fileType) {
        case "text":
            return filePart.formatted(index, index, index, fileName, index, index, index, fileContents);
        case "image":
            byte[] decoded = Base64.getDecoder().decode(fileContents);
            return imageFilePart.formatted(index, index, index, fileName, index, index, index, Util.imageData(fileName, decoded));
        case "binary":
            return binaryFilePart.formatted(index, index, index, fileName, index, index, index);
        default:
            return "";
    }
}


    
    public String checkAndSaveProblem(String requestPrefix, String problem, byte[] problemZip, String editKey)
            throws IOException, InterruptedException, NoSuchMethodException, ScriptException {
		Map<Path, byte[]> problemFiles = Util.unzip(problemZip);
    	problemFiles = fixZip(problemFiles);
    	return checkAndSaveProblem(requestPrefix, problem, problemFiles, editKey);
    }

    public String checkAndSaveProblem(String requestPrefix, String problem, Map<Path, byte[]> problemFiles, String editKey)
            throws IOException, InterruptedException, NoSuchMethodException, ScriptException {
    	if (problem == null) { // new problem
    		problem = Util.createPublicUID();
    		editKey = Util.createPrivateUID();    		            
    	} else {
    		checkEditKey(problem, editKey);

            // Add any binary old file that is not deleted
            Map<Path, byte[]> oldProblemFiles = codeCheck.loadProblem(DEFAULT_REPO, problem);
            for (Map.Entry<Path, byte[]> entry : oldProblemFiles.entrySet()) {
                if (problemFiles.containsKey(entry.getKey()) && !Util.isText(entry.getValue())) {
                    problemFiles.put(entry.getKey(), entry.getValue());
                }
            }
    	}
    	problemFiles.put(Path.of("edit.key"), editKey.getBytes(StandardCharsets.UTF_8));    		
        StringBuilder response = new StringBuilder();
        String report = null;
        if (problemFiles.containsKey(Path.of("tracer.js"))) {
            codeCheck.saveProblem(DEFAULT_REPO, problem, problemFiles);
        } else {
            report = codeCheck.checkAndSave(problem, problemFiles);
        }
        response.append(
                "<html><head><title></title><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"/>");
        response.append("<body style=\"font-family: sans-serif\">");
        
        String problemUrl = createProblemURL(requestPrefix, problem, problemFiles);
        response.append("Public URL (for your students): ");
        response.append("<a href=\"" + problemUrl + "\" target=\"_blank\">" + problemUrl + "</a>");
        String editURL = requestPrefix + "/private/problem/" + problem + "/" + editKey;
        response.append("<br/>Edit URL (for you only): ");
        response.append("<a href=\"" + editURL + "\">" + editURL + "</a>");
        if (report != null) {
            String run = Base64.getEncoder().encodeToString(report.getBytes(StandardCharsets.UTF_8));
            response.append(
                    "<br/><iframe height=\"400\" style=\"width: 90%; margin: 2em;\" src=\"data:text/html;base64," + run
                            + "\"></iframe>");
        }
        response.append("</li>\n");
        response.append("</ul><p></body></html>\n");
        return response.toString();
    }

    private String createProblemURL(String requestPrefix, String problem, Map<Path, byte[]> problemFiles) {
        String type;
        if (problemFiles.containsKey(Path.of("tracer.js"))) {
            type = "tracer";
        } else {
            type = "files";
        }
        return requestPrefix + "/" + type + "/" + problem;
    }

    /**
     * Produces a form for editing a problem.
     */
    public String editProblem(String prefix, ObjectNode payload) throws IOException {
        String problemID = payload.get("problemID").asText();
        String editKey = payload.get("editKey").asText();
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode problemFilesJSON = mapper.createObjectNode(); 
        Map<Path, byte[]> problemFilesMap = checkEditKey(problemID, editKey);
        for (Map.Entry<Path, byte[]> entry : problemFilesMap.entrySet()) {
            String filename = entry.getKey().toString();
            byte[] data = entry.getValue();
            String fileType = classifyFile(filename, data);
            problemFilesJSON.put(filename, buildFileArray(mapper, filename, data, fileType));
        }
        payload.put("prevProblem", problemFilesJSON);
        String problemURL = createProblemURL(prefix, problemID, problemFilesMap);
        StringBuilder result = new StringBuilder();
        result.append(part1.formatted(problemURL, problemURL, problemID, editKey));

        JsonNode prevProblemNode = payload.path("prevProblem");
        if (prevProblemNode.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = prevProblemNode.fields();
            int i = 1;
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                if (List.of("_outputs", "edit.key").contains(entry.getKey().toString())) {
                    if (fields.hasNext()) {
                        entry = fields.next();
                    } else {
                        break;
                    }     
                }
                String fileName = entry.getKey(); 
                JsonNode fileArray = entry.getValue();
                String fileContents = fileArray.get(0).get(fileName).asText();
                String fileType = fileArray.get(1).get("fileType").asText();
                result.append(renderFileBlock(i, fileName, fileType, fileContents));
                i++;
            }
        }
        result.append(part2.formatted(problemID, editKey));
        return result.toString();
    }


    public ObjectNode checkProblem(String prefix, Map<Path, byte[]> problemFiles, String problem, String editKey)
        throws IOException, InterruptedException, NoSuchMethodException, ScriptException {
        if (problem == null) { // new problem
    		problem = Util.createPublicUID();
    		editKey = Util.createPrivateUID();    		            
    	} else {
    		checkEditKey(problem, editKey);

            // Add any binary old file that is not deleted
            Map<Path, byte[]> oldProblemFiles = codeCheck.loadProblem(DEFAULT_REPO, problem);
            for (Map.Entry<Path, byte[]> entry : oldProblemFiles.entrySet()) {
                if (problemFiles.containsKey(entry.getKey()) && !Util.isText(entry.getValue())) {
                    problemFiles.put(entry.getKey(), entry.getValue());
                }
            }
    	}
        problemFiles.put(Path.of("edit.key"), editKey.getBytes(StandardCharsets.UTF_8));    		
        codeCheck.saveProblem(DEFAULT_REPO, problem, problemFiles);
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode responseJSON = mapper.createObjectNode();
        responseJSON.put("problemID", problem);
        responseJSON.put("editKey", editKey);
        responseJSON.put("report", codeCheck.checkAndSave(problem, problemFiles));

        responseJSON.put("problemURL", createProblemURL(prefix, problem, problemFiles));
        String editURL = prefix + "/private/problem/" + problem + "/" + editKey;
        responseJSON.put("editURL", editURL);
        return responseJSON;
    }
    
    private String part1 = """
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Edit Problem</title>
    <script src="/assets/editProblem.js" type="text/javascript"></script>
    <script src="/assets/util.js" type="text/javascript"></script>
</head>
<body style="font-family: sans-serif;">
Public URL (for your students): 
<a href="%s" target="_blank">%s</a>
<form method="post" action="/editedFiles/%s/%s">
<div>
    <hr>
    <a href="https://horstmann.com/codecheck/authoring.html" target="_blank">View User Guide</a>
</div>
    <div>		
""";
    
    private String filePart = """
    <div id="item%d">
      <p>File name: <input type="text" id="filename%d" name="filename%d" size="25" value="%s"/> 
        <button id="delete%d" type="button">Delete</button>
      </p>
      <p><textarea id="contents%d" name="contents%d" rows="24" cols="80">%s</textarea></p>
    </div>    		
""";

private String imageFilePart = """
    <div id="item%d">
      <p>File name: <input type="text" id="filename%d" name="filename%d" size="25" value="%s"/> 
        <button id="delete%d" type="button">Delete</button>
      </p>
      <p><input id="contents%d" name="contents%d" value="" style="display:none"/></p>
      <p><img src="%s"/></p>
    </div>    		
""";

    private String binaryFilePart = """
    <div id="item%d">
      <p>File name: <input type="text" id="filename%d" name="filename%d" size="25" value="%s"/> (binary) 
        <button id="delete%d" type="button">Delete</button>
      </p>
      <p><input id="contents%d" name="contents%d" value="" style="display:none"/></p>
    </div>    		
""";

    private String part2 = """
    <div id="addfilecontainer">Need more files? <button id="addfile" type="button">Add file</button></div>
    <div><input type="button" id="codecheck" value="Submit changes"/></div><br>
    <div id="submitdisplay" class="non-editable"></div>
    <div id="iframe-container"></div>
    </div>
</form>
<p></p>
<hr/>
<form method="post" action="/editedProblem/%s/%s" enctype="multipart/form-data">
<p>Alternatively, upload a zip file. Select the file <input name="file" id="file" type="file"/></p>
<p><input id="upload" type="submit" value="Upload zip file"/></p></form>
</body>
</html>    		
""";        
}
