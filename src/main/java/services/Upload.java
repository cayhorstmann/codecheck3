package services;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.script.ScriptException;

import com.horstmann.codecheck.checker.Util;

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
    public String editProblem(String prefix, String problem, String editKey) throws IOException {
        Map<Path, byte[]> problemFiles = checkEditKey(problem, editKey);
               
        String problemURL = createProblemURL(prefix, problem, problemFiles);
        StringBuilder result = new StringBuilder();
        result.append(part1.formatted(problemURL, problemURL, problem, editKey));
        int i = 0;
        for (Map.Entry<Path, byte[]> entries : problemFiles.entrySet()) {
            Path p = entries.getKey();
            if (!List.of("_outputs", "edit.key").contains(p.getName(0).toString())) {
            	i++;
            	String name = p.toString();
                if (Util.isText(entries.getValue())) {
                    String contents = new String(entries.getValue(), StandardCharsets.UTF_8);
                    result.append(filePart.formatted(i, i, i, name, i, i, i, contents));
                } else if (Util.isImageFilename(entries.getKey().toString())) {
                    result.append(imageFilePart.formatted(i, i, i, name, i, i, i,
                            Util.imageData(entries.getKey().toString(), entries.getValue())));
                } else {
                    result.append(binaryFilePart.formatted(i, i, i, name, i, i, i));
                }
            }
        }
        result.append(part2.formatted(problem, editKey));
        return result.toString();
    }

    public String checkProblem(Map<Path, byte[]> problemFiles)
        throws IOException, InterruptedException, NoSuchMethodException, ScriptException {
            
        String report = codeCheck.checkAndSave(null, problemFiles);
            String run = Base64.getEncoder().encodeToString(report.getBytes(StandardCharsets.UTF_8));
            String response =
                    "<br/><iframe height=\"400\" style=\"width: 90%; margin: 2em;\" src=\"data:text/html;base64," + run
                            + "\"></iframe>";
        return response;
    }
    
    private String part1 = """
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Edit Problem</title>
    <script src="/assets/editProblem.js" type="text/javascript"></script>
</head>
<body style="font-family: sans-serif;">
Public URL (for your students): 
<a href="%s" target="_blank">%s</a>
<form method="post" action="/editedFiles/%s/%s">
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
    <div><input type="submit" value="Submit changes"/></div>
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
