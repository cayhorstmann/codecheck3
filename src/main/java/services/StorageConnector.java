package services;

import com.fasterxml.jackson.databind.node.ArrayNode;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.core.sync.ResponseTransformer;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.enhanced.dynamodb.document.EnhancedDocument;

/*

Test plan

http://localhost:9000/assets/uploadProblem.html

Test.py

##HIDE
print('hi')
##EDIT ...

Save, then edit and modify

http://localhost:9000/newAssignment
paste URL from problem, save

visit as student
solve
use private url in another browser
clear id
solve again, different

visit as instructor
view submissions
click on a submission
make a comment
view again to see if comment saved
view as student to see if comment saved

 */


import java.io.IOException;
import java.lang.System.Logger;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.FileLockInterruptionException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.horstmann.codecheck.checker.Util;

import controllers.Config;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

@ApplicationScoped
public class StorageConnector {
    @Inject Assignment assignmentService;
    private StorageConnection delegate;
    @Inject Config config;

    @Inject public StorageConnector(Config config) {
        String type = "local";
        if (config.hasPath("com.horstmann.codecheck.storage.type"))
            type = config.getString("com.horstmann.codecheck.storage.type");
        if (type.equalsIgnoreCase("aws"))
            delegate = new AWSStorageConnection(config);
        else if (type.equalsIgnoreCase("sql")) {
            delegate = new SQLStorageConnection(config);
        }
        else
            delegate = new LocalStorageConnection(config);
    }

    public byte[] readProblem(String repo, String key) throws IOException {
        return delegate.readProblem(repo, key);
    }

    public void writeProblem(byte[] contents, String repo, String key) throws IOException {
        delegate.writeProblem(contents, repo, key);
    }

    public ObjectNode readAssignment(String assignmentID) throws IOException {
        ObjectNode assignmentNode = delegate.readAssignment(assignmentID);
        /*
        TODO: Eventually remove
        This only relates to problems with qid which used to be stored at different URLs. These are rewritten
        to the current URLs (www.interactivities.ws -> horstmann.com/interactivities)
         */
        if (assignmentNode == null) return null;
        String legacyPrefixes = config.getString("com.horstmann.codecheck.qid.legacyPrefixes");
        if (legacyPrefixes != null) {
            boolean rewrite = false;
            ArrayNode groups = (ArrayNode) assignmentNode.get("problems");
            for (int i = 0; i < groups.size(); i++) {
                ArrayNode group = (ArrayNode) groups.get(i);
                for (int j = 0; j < group.size(); j++) {
                    ObjectNode problem = (ObjectNode) group.get(j);
                    String problemURL = problem.get("URL").asText();
                    if (problem.has("qid")) {
                        boolean isLegacy = false;
                        for (String p : legacyPrefixes.split(",")) {
                            if (problemURL.startsWith(p)) {
                                isLegacy = true;
                            }
                        }
                        if (isLegacy) {
                            String qid = problem.get("qid").asText();
                            String newURL = assignmentService.qidURL(qid);
                            if (newURL != null) {
                                problem.put("URL", newURL);
                                rewrite = true;
                            }
                        }
                    }
                }
            }
            if (rewrite) {
                delegate.writeAssignment(assignmentNode);
            }
        }
        return assignmentNode;
    }

    public String readLegacyLTIResource(String resourceID) throws IOException {
        return delegate.readLegacyLTIResource(resourceID);
    }

    public String readLTISharedSecret(String oauthConsumerKey) throws IOException {
        return delegate.readLTISharedSecret(oauthConsumerKey);
    }

    public String readComment(String assignmentID, String workID) throws IOException {
        return delegate.readComment(assignmentID, workID);
    }

    public ObjectNode readWork(String assignmentID, String workID) throws IOException {
        return delegate.readWork(assignmentID, workID);
    }

    public String readWorkString(String assignmentID, String workID) throws IOException {
        return delegate.readWorkString(assignmentID, workID);
    }

    public ObjectNode readNewestSubmission(String submissionID) throws IOException {
        return delegate.readNewestSubmission(submissionID);
    }

    public Map<String, ObjectNode> readAllWork(String assignmentID) throws IOException {
        return delegate.readAllWork(assignmentID);
    }

    public void writeAssignment(JsonNode node) throws IOException {
        delegate.writeAssignment(node);
    }

    public void writeSubmission(JsonNode node) throws IOException {
        delegate.writeSubmission(node);
    }

    public void writeComment(JsonNode node) throws IOException {
        delegate.writeComment(node);
    }

    public boolean writeWork(JsonNode node) throws IOException {
        return delegate.writeWork(node);
    }
}

interface StorageConnection {
    byte[] readProblem(String repo, String key) throws IOException;
    void writeProblem(byte[] contents, String repo, String key) throws IOException;
    ObjectNode readAssignment(String assignmentID) throws IOException;
    String readLegacyLTIResource(String resourceID) throws IOException;
    String readLTISharedSecret(String oauthConsumerKey) throws IOException;
    String readComment(String assignmentID, String workID) throws IOException;
    ObjectNode readWork(String assignmentID, String workID) throws IOException;
    String readWorkString(String assignmentID, String workID) throws IOException;
    ObjectNode readNewestSubmission(String submissionID) throws IOException;
    Map<String, ObjectNode> readAllWork(String assignmentID) throws IOException;
    void writeAssignment(JsonNode node) throws IOException;
    void writeSubmission(JsonNode node) throws IOException;
    void writeComment(JsonNode node)  throws IOException;
    boolean writeWork(JsonNode node) throws IOException; // return true if this version was saved (because it was newer)
}

/*
 CodeCheck IDs:
   course ID = potential future unique ID for a course
     (not currently implemented)
   assignment ID = the unique ID for the CodeCheck assignment
     (shared in LTI courses and potentially in non-LTI courses if we add a course feature)
   problem ID = the unique ID of a problem (a URL or a qid)

 Non-LTI IDs
   ccid = cookie of student
   editKey = edit key of student

 LTI IDs from LTI launch:
   user_id
   tool_consumer_instance_guid = server instance
   context_id = course in server
   resource_link_id

 ccauth JWT token:
   resourceID: see assignmentID below
   editKey: tool_consumer_instance_guid/user_id

 LTI IDs in JWT (TODO: Use token instead)
   resourceID: see assignmentID below
   userID: see workID below

 Tables:

 CodeCheckAssignment
   assignmentID [partition key] - the CodeCheck assignment ID
   deadline (an ISO 8601 string like "2020-12-01T23:59:59Z")
   editKey // LTI: tool_consumer_instance_guid/user_id
   problems
     array of // One per group
       array of { URL, qid?, weight } // qid for book repo

 CodeCheckLTIResources (Legacy)
   resourceID [primary key] // tool_consumer_instance_guid/context_id/resource_link_id
   assignmentID

 CodeCheckWork is a map from problem keys to scores and states. It only stores the most recent version.

 CodeCheckWork and CodeCheckComments use the following confusingly named keys
   assignmentID (not a great name--is assignment in context, use variable name resourceID in code)
     non-LTI: courseID? + assignment ID,
     LTI: tool_consumer_instance_guid/context_id + assignment ID, Legacy tool_consumer_instance_guid/context_id/resource_link_id
   workID (not a great name--identifies authenticated user in context, use variable name userID in code)
     non-LTI: ccid/editKey
     LTI: user_id

 CodeCheckWork
   assignmentID [primary key] (see above)
   workID [sort key] (see above)
   problems
     map from URL/qids to { state, score }
   submittedAt
   tab

CodeCheckComments
   assignmentID [primary key] (see above)
   workID [sort key] (see above)
   comment

   (This is a separate table from CodeCheckWork because we can't guarantee atomic updates if a student happens to update their work while the instructor updates a comment)
   TODO: In SQL, don't need separate table

 CodeCheckSubmissions is an append-only log of all submissions of a single problem.
 TODO: Only LTIProblem reads from it, so there may not be any benefit saving from assignment, and one could just keep the latest

 CodeCheckSubmissions
   submissionID [partition key]
     non-LTI: courseID? + assignment ID + problemID + ccid/editKey
     LTI: tool_consumer_instance_guid/context_id + assignment ID + user_id + problem ID
     // either way, that's the info in assignmentID + workID + problem ID
   submittedAt [sort key]
   state: as string, not JSON
   score

   with global secondary index (TODO: Not currently)
     problemID
     submitterID

 CodeCheckLTICredentials
   oauth_consumer_key [primary key]
   shared_secret
*/

class AWSStorageConnection implements StorageConnection {
    private static final Logger logger = System.getLogger("com.horstmann.codecheck");
    private final String bucketSuffix;
    private final S3Client s3Client;
    private final DynamoDbClient dynamoDbClient;

    public AWSStorageConnection(Config config) {
        String accessKey = config.getString("com.horstmann.codecheck.aws.accessKey");
        String secretKey = config.getString("com.horstmann.codecheck.aws.secretKey");
        String regionName = config.getString("com.horstmann.codecheck.s3.region");
        AwsCredentials credentials = AwsBasicCredentials.create(accessKey, secretKey);
        SdkHttpClient urlHttpClient = UrlConnectionHttpClient.create();
        s3Client = S3Client
                .builder()
                .httpClient(urlHttpClient)
                .region(Region.of(regionName))
                .crossRegionAccessEnabled(true)
                .credentialsProvider(StaticCredentialsProvider.create(credentials))
                .build();

        bucketSuffix = config.getString("com.horstmann.codecheck.s3.bucketsuffix");

        String dynamoDBregion = config.getString("com.horstmann.codecheck.dynamodb.region");
        dynamoDbClient =
                DynamoDbClient.builder()
                        .httpClient(urlHttpClient)
                        .region(Region.of(dynamoDBregion))
                        .credentialsProvider(StaticCredentialsProvider.create(credentials))
                        .build();
    }

    public byte[] readProblem(String repo, String key) {
        String bucketName = repo + "." + bucketSuffix;

        try {
            ResponseBytes<?> objectBytes = s3Client.getObject(
                    GetObjectRequest.builder()
                            .bucket(bucketName)
                            .key(key)
                            .build(),
                    ResponseTransformer.toBytes()
            );
            return objectBytes.asByteArray();
        } catch (Exception ex) {
            logger.log(Logger.Level.ERROR, "S3Connection.readFromS3: Cannot read " + key + " from " + bucketName);
            throw ex;
        }
    }

    public void writeProblem(byte[] contents, String repo, String key) {
        String bucketName = repo + "." + bucketSuffix;
        try {
            s3Client.putObject(
                    PutObjectRequest.builder()
                            .bucket(bucketName)
                            .key(key)
                            .build(),
                    RequestBody.fromBytes(contents));
        } catch (Exception ex) {
            String bytes = Arrays.toString(contents);
            logger.log(Logger.Level.ERROR, "S3Connection.putToS3: Cannot put " + bytes.substring(0, Math.min(50, bytes.length())) + "... to " + bucketName);
            throw ex;
        }
    }

    public ObjectNode readAssignment(String assignmentID) throws IOException {
        return readJsonObjectFromDB("CodeCheckAssignments", "assignmentID", assignmentID);
    }

    public String readLegacyLTIResource(String resourceID) {
        Map<String, AttributeValue> item = readAttributeValueMapFromDB("CodeCheckLTIResources", "resourceID", resourceID);
        if (item == null) return null;
        else return item.get("assignmentID").s();
    }

    public String readLTISharedSecret(String oauthConsumerKey) {
        Map<String, AttributeValue> item = readAttributeValueMapFromDB("CodeCheckLTICredentials", "oauth_consumer_key", oauthConsumerKey);
        if (item == null) return null;
        else return item.get("shared_secret").s();
    }

    public String readComment(String assignmentID, String workID) {
        Map<String, AttributeValue> item = readAttributeValueMapFromDB("CodeCheckComments", "assignmentID", assignmentID, "workID", workID);
        if (item == null) return "";
        else return item.get("comment").s();
    }

    public ObjectNode readWork(String assignmentID, String workID) throws IOException {
        return readJsonObjectFromDB("CodeCheckWork", "assignmentID", assignmentID, "workID", workID);
    }

    public String readWorkString(String assignmentID, String workID) {
        return readJsonStringFromDB("CodeCheckWork", "assignmentID", assignmentID, "workID", workID);
    }

    public ObjectNode readNewestSubmission(String submissionID) throws JsonProcessingException {
        return readNewestJsonObjectFromDB("CodeCheckSubmissions", "submissionID", submissionID);
    }

    public Map<String, ObjectNode> readAllWork(String assignmentID) throws IOException {
        return readJsonObjectsFromDB("CodeCheckWork", "assignmentID", assignmentID, "workID");
    }

    public void writeAssignment(JsonNode node) {
        writeJsonObjectToDB("CodeCheckAssignments", node);
    }

    public void writeSubmission(JsonNode node) {
        writeJsonObjectToDB("CodeCheckSubmissions", node);
    }

    public void writeComment(JsonNode node) {
        writeJsonObjectToDB("CodeCheckComments", node);
    }

    public boolean writeWork(JsonNode node) {
        return writeNewerJsonObjectToDB("CodeCheckWork", node, "assignmentID", "submittedAt");
    }

    private ObjectNode readJsonObjectFromDB(String tableName, String primaryKeyName, String primaryKeyValue) throws IOException {
        String result = readJsonStringFromDB(tableName, primaryKeyName, primaryKeyValue);
        return result == null ? null : Util.fromJsonString(result);
    }

    private ObjectNode readJsonObjectFromDB(String tableName, String primaryKeyName, String primaryKeyValue, String sortKeyName, String sortKeyValue) throws IOException {
        String result = readJsonStringFromDB(tableName, primaryKeyName, primaryKeyValue, sortKeyName, sortKeyValue);
        return result == null ? null : Util.fromJsonString(result);
    }

    private String readJsonStringFromDB(String tableName, String primaryKeyName, String primaryKeyValue) {
        Map<String, AttributeValue> item = readAttributeValueMapFromDB(tableName, primaryKeyName, primaryKeyValue);
        return item == null ? null : EnhancedDocument.fromAttributeValueMap(item).toJson();
    }

    private Map<String, AttributeValue> readAttributeValueMapFromDB(String tableName, String primaryKeyName, String primaryKeyValue) {
        Map<String, AttributeValue> key = new HashMap<>();
        key.put(primaryKeyName, AttributeValue.builder().s(primaryKeyValue).build());

        GetItemRequest request = GetItemRequest.builder()
                .tableName(tableName)
                .key(key)
                .build();
        GetItemResponse response = dynamoDbClient.getItem(request);
        if (response.hasItem()) {
            return response.item();
        } else {
            return null;
        }
    }

    private ObjectNode readNewestJsonObjectFromDB(String tableName, String primaryKeyName, String primaryKeyValue) throws JsonProcessingException {
        String keyConditionExpression = primaryKeyName + " = :primaryKey";
        Map<String, AttributeValue> expressionAttributeValues = new HashMap<>();
        expressionAttributeValues.put(":primaryKey", AttributeValue.builder().s(primaryKeyValue).build());
        QueryRequest queryRequest = QueryRequest.builder()
                .tableName(tableName)
                .keyConditionExpression(keyConditionExpression)
                .expressionAttributeValues(expressionAttributeValues)
                .scanIndexForward(false) // For reverse order of query results
                .build();

        List<Map<String, AttributeValue>> items = dynamoDbClient.query(queryRequest).items();
        if (items.size() > 0) {
            return Util.fromJsonString(EnhancedDocument.fromAttributeValueMap(items.getFirst()).toJson());
        } else {
            return null;
        }
    }

    private String readJsonStringFromDB(String tableName, String primaryKeyName, String primaryKeyValue, String sortKeyName, String sortKeyValue) {
        Map<String, AttributeValue> item = readAttributeValueMapFromDB(tableName, primaryKeyName, primaryKeyValue, sortKeyName, sortKeyValue);
        return item == null ? null : EnhancedDocument.fromAttributeValueMap(item).toJson();
    }

    private Map<String, AttributeValue> readAttributeValueMapFromDB(String tableName, String primaryKeyName, String primaryKeyValue, String sortKeyName, String sortKeyValue) {
        // Define the key condition expression and value map
        String keyConditionExpression = primaryKeyName + " = :primaryKey AND " + sortKeyName + " = :sortKey";
        Map<String, AttributeValue> expressionAttributeValues = new HashMap<>();
        expressionAttributeValues.put(":primaryKey", AttributeValue.builder().s(primaryKeyValue).build());
        expressionAttributeValues.put(":sortKey", AttributeValue.builder().s(sortKeyValue).build());

        QueryRequest queryRequest = QueryRequest.builder()
                .tableName(tableName)
                .keyConditionExpression(keyConditionExpression)
                .expressionAttributeValues(expressionAttributeValues)
                .build();
        List<Map<String, AttributeValue>> items = dynamoDbClient.query(queryRequest).items();
        if (items.size() > 0) {
            return items.getFirst();
        } else {
            return null;
        }
    }

    private Map<String, ObjectNode> readJsonObjectsFromDB(String tableName, String primaryKeyName, String primaryKeyValue, String sortKeyName) throws IOException {
        String keyConditionExpression = primaryKeyName + " = :primaryKey";
        Map<String, AttributeValue> expressionAttributeValues = new HashMap<>();
        expressionAttributeValues.put(":primaryKey", AttributeValue.builder().s(primaryKeyValue).build());

        QueryRequest queryRequest = QueryRequest.builder()
                .tableName(tableName)
                .keyConditionExpression(keyConditionExpression)
                .expressionAttributeValues(expressionAttributeValues)
                .build();

        List<Map<String, AttributeValue>> items = dynamoDbClient.query(queryRequest).items();
        Map<String, ObjectNode> itemMap = new HashMap<>();
        for (Map<String, AttributeValue> item : items) {
            String key = item.get(sortKeyName).s();
            itemMap.put(key, Util.fromJsonString(EnhancedDocument.fromAttributeValueMap(item).toJson()));
        }
        return itemMap;
    }

    private void writeJsonObjectToDB(String tableName, JsonNode obj) {
        Map<String, AttributeValue> item = EnhancedDocument.fromJson(obj.toString()).toMap();
        PutItemRequest putItemRequest = PutItemRequest.builder()
                .tableName(tableName)
                .item(item)
                .build();
        dynamoDbClient.putItem(putItemRequest);
    }

    private boolean writeNewerJsonObjectToDB(String tableName, JsonNode obj, String primaryKeyName, String timeStampKeyName) {
        try {
            Map<String, AttributeValue> item = EnhancedDocument.fromJson(obj.toString()).toMap();
            Map<String, AttributeValue> expressionAttributeValues = new HashMap<>();
            String conditionalExpression = "attribute_not_exists(" + primaryKeyName + ") OR " + timeStampKeyName + " < :" + timeStampKeyName;
            expressionAttributeValues.put(":" + timeStampKeyName,
                    AttributeValue.builder().s(obj.get(timeStampKeyName).asText()).build());
            PutItemRequest putItemRequest = PutItemRequest.builder()
                    .tableName(tableName)
                    .item(item)
                    .conditionExpression(conditionalExpression)
                    .expressionAttributeValues(expressionAttributeValues)
                    .build();
            dynamoDbClient.putItem(putItemRequest);
            return true;
        } catch (ConditionalCheckFailedException e) {
            return false;
        }
    }
}

/*

Stores the assignment data in the local file system.

root/
  Problems/
    repo1
      key11.zip
      key12.zip
      ...
    repo2
      key21.zip
      key22.zip
      ...

  CodeCheckAssignments/
    assignmentID1 <- JSON file like in DynamoDB
    assignmentID2
    ...

  CodeCheckLTICredentials  <- JSON object mapping consumer keys to shared secrets

  CodeCheckComments
    assignmentID1
      workID11 <- the comment
      workID12
      ...
   assignmentID2
      workID21
      workID22
      ...
   ...

  CodeCheckWork
    assignmentID1
      workID11 <- JSON file like in DynamoDB
      workID12
      ...
   assignmentID2
      workID21
      workID22
      ...
   ...

  CodeCheckSubmissions
    submissionID1
      timestamp11 <- JSON file like in DynamoDB
      timestamp12
      ...
    submissionID2
      timestamp21
      timestamp22
      ...
    ...

Legacy LTI resources are not supported.

*/

class LocalStorageConnection implements StorageConnection {
    private Path root;
    private static Logger logger = System.getLogger("com.horstmann.codecheck");
    private ObjectNode credentials;

    public LocalStorageConnection(Config config) {
        this.root = Path.of(config.getString("com.horstmann.codecheck.storage.local"));
        try {
            Files.createDirectories(root);
        } catch (IOException ex) {
            logger.log(Logger.Level.ERROR, "Cannot create " + root);
        }
    }

    public byte[] readProblem(String repo, String key) throws IOException {
        byte[] result = null;
        try {
            Path repoPath = root.resolve("Problems").resolve(repo);
            Path filePath = repoPath.resolve(key + ".zip");
            result = Files.readAllBytes(filePath);
        } catch (IOException ex) {
            logger.log(Logger.Level.ERROR, "ProblemLocalConnection.read : Cannot read " + key + " from " + repo);
            throw ex;
        }

        return result;
    }

    public void writeProblem(byte[] contents, String repo, String key) throws IOException {
        try {
            Path repoPath = root.resolve("Problems").resolve(repo);
            Files.createDirectories(repoPath);
            Path newFilePath = repoPath.resolve(key + ".zip");
            Files.write(newFilePath, contents);
        } catch (IOException ex) {
            String bytes = Arrays.toString(contents);
            logger.log(Logger.Level.ERROR, "ProblemLocalConnection.write : Cannot put " + bytes.substring(0, Math.min(50, bytes.length())) + "... to " + repo);
            throw ex;
        }
    }


    public ObjectNode readAssignment(String assignmentID) throws IOException {
        return readJsonObject("CodeCheckAssignments", assignmentID);
    }

    public String readLegacyLTIResource(String resourceID) {
        return null;
    }

    public String readLTISharedSecret(String oauthConsumerKey) throws IOException {
        if (credentials == null)
            credentials = Util.fromJsonString(Files.readString(path("CodeCheckLTICredentials")));
        return credentials.get(oauthConsumerKey).asText();
    }

    public String readComment(String assignmentID, String workID) throws IOException {
        Path path = path("CodeCheckComments", assignmentID, workID);
        if (Files.exists(path)) return Files.readString(path);
        else return "";
    }

    public ObjectNode readWork(String assignmentID, String workID) throws IOException {
        return readJsonObject("CodeCheckWork", assignmentID, workID);
    }

    public String readWorkString(String assignmentID, String workID) throws IOException {
        return readJsonString("CodeCheckWork", assignmentID, workID);
    }

    public ObjectNode readNewestSubmission(String submissionID) {
        Path path = path("CodeCheckSubmissions", submissionID);

        try (Stream<Path> entries = Files.list(path)) {
            Path latest = entries.filter(Files::isRegularFile).max(Path::compareTo).orElse(null);
            if (latest == null) return null;
            String content = Files.readString(latest);
            try {
                return Util.fromJsonString(content);
            } catch (JsonProcessingException ex) {
                logger.log(Logger.Level.WARNING, "AssignmentConnector.readNewestJsonObjectFromDB: cannot read " + latest + "***File content: " + content);
                return null;
            }
        } catch (IOException ex) {
            return null;
        }
    }

    public Map<String, ObjectNode> readAllWork(String assignmentID) throws IOException {
        Map<String, ObjectNode> itemMap = new HashMap<>();
        Path path = path("CodeCheckWork", assignmentID);
        try {
            try (Stream<Path> entries = Files.list(path)) {
                List<Path> files = entries.filter(Files::isRegularFile).collect(Collectors.toList());
                for (Path file : files) {
                    String fileData = Files.readString(file);
                    ObjectNode node = Util.fromJsonString(fileData);
                    String key = node.get("workID").asText();
                    itemMap.put(key, node);
                }
            }
        } catch (IOException ex){
            logger.log(Logger.Level.WARNING, Util.getStackTrace(ex));
        }
        return itemMap;
    }

    public void writeAssignment(JsonNode node) throws IOException {
        String assignmentID = node.get("assignmentID").asText();
        Path path = path("CodeCheckAssignments", assignmentID);
        Files.createDirectories(path.getParent());
        Files.writeString(path, node.toString());
    }

    public void writeSubmission(JsonNode node) throws IOException {
        String submissionID = node.get("submissionID").asText();
        String submittedAt = node.get("submittedAt").asText();
        Path path = path("CodeCheckSubmissions", submissionID, submittedAt);
        Files.createDirectories(path.getParent());
        Files.writeString(path, node.toString());
    }

    public void writeComment(JsonNode node)  throws IOException {
        String assignmentID = node.get("assignmentID").asText();
        String workID = node.get("workID").asText();
        Path path = path("CodeCheckComments", assignmentID, workID);
        Files.createDirectories(path.getParent());
        Files.writeString(path, node.get("comment").asText());
    }

    public boolean writeWork(JsonNode node) throws IOException {
        String assignmentID = node.get("assignmentID").asText();
        String workID = node.get("workID").asText();
        Path path = path("CodeCheckWork", assignmentID, workID);
        Files.createDirectories(path.getParent());
        String newTimeStampVal = node.get("submittedAt").asText();

        int tries = 10;
        while (tries > 0) {
            FileChannel channel = FileChannel.open(path,
                    StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
            try (FileLock lock = channel.lock()) {
                ByteBuffer readBuffer = ByteBuffer.allocate((int) channel.size());
                channel.read(readBuffer);
                byte[] contents = readBuffer.array();
                boolean replace = false;
                if (contents.length == 0) replace = true;
                else {
                    ObjectNode prevNode = Util.fromJsonString(readBuffer.array());
                    String prevTimeStampVal = prevNode.get("submittedAt").asText();
                    replace = prevTimeStampVal.compareTo(newTimeStampVal) < 0;
                }
                if (replace) {
                    channel.truncate(0);
                    ByteBuffer writeBuffer = ByteBuffer.wrap(node.toString().getBytes());
                    channel.write(writeBuffer);
                    return true;
                }
                else return false;
            } catch (FileLockInterruptionException ex) {
                try { Thread.sleep(1000); } catch (InterruptedException ex2) {}
                tries--;
            }
        }
        throw new IOException("Could not acquire lock for " + path);
    }

    private Path path(String first, String... rest) {
        Path result = root.resolve(first);
        for (String r : rest) result = result.resolve(r.replaceAll("[^a-zA-Z0-9_-]", ""));
        return result;
    }

    private ObjectNode readJsonObject(String tableName, String primaryKeyValue) throws IOException {
        String result = readJsonString(tableName, primaryKeyValue);
        return result == null ? null : Util.fromJsonString(result);
    }

    private ObjectNode readJsonObject(String tableName, String primaryKeyValue, String sortKeyValue) throws IOException {
        String result = readJsonString(tableName, primaryKeyValue, sortKeyValue);
        return result == null ? null : Util.fromJsonString(result);
    }

    public String readJsonString(String tableName, String primaryKeyValue) throws IOException {
        Path path = path(tableName, primaryKeyValue);

        try {
            return Files.readString(path);
        } catch (IOException ex) {
            logger.log(Logger.Level.WARNING, "AssignmentLocalConnection.readJsonString: Cannot read " + path);
            return null;
        }
    }

    public String readJsonString(String tableName, String primaryKeyValue, String sortKeyValue) throws IOException {
        Path path = path(tableName, primaryKeyValue, sortKeyValue);

        try {
            return Files.readString(path);
        } catch (IOException ex) {
            logger.log(Logger.Level.WARNING, "AssignmentLocalConnection.readJsonString: Cannot read " + path);
            return null;
        }
    }
}

/*

CREATE TABLE CodeCheckAssignments (assignmentID VARCHAR PRIMARY KEY, json VARCHAR)
CREATE TABLE CodeCheckLTICredentials (oauth_consumer_key VARCHAR PRIMARY KEY, shared_secret VARCHAR)
CREATE TABLE CodeCheckComments (assignmentID VARCHAR, workID VARCHAR, comment VARCHAR, UNIQUE (assignmentID, workID))
CREATE TABLE CodeCheckWork (assignmentID VARCHAR, workID VARCHAR, submittedAt VARCHAR, json VARCHAR, UNIQUE (assignmentID, workID))
CREATE TABLE CodeCheckSubmissions (submissionID VARCHAR, submittedAt VARCHAR, json VARCHAR)

 */

class SQLStorageConnection implements StorageConnection {
    private static Logger logger = System.getLogger("com.horstmann.codecheck");
    private Config config;

    public SQLStorageConnection(Config config) {
        this.config = config;
    }

    public byte[] readProblem(String repo, String key) throws IOException {
        try (Connection conn = config.getDatabaseConnection()) {
            PreparedStatement ps = conn.prepareStatement("SELECT contents FROM Problems WHERE repo = ? AND key = ?");
            ps.setString(1, repo);
            ps.setString(2, key);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return rs.getBytes(1);
            else return null;
        } catch (SQLException ex) {
            logger.log(Logger.Level.ERROR, ex.getMessage());
            throw new IOException(ex);
        }
    }

    public void writeProblem(byte[] contents, String repo, String key) throws IOException {
        try {
            try (Connection conn = config.getDatabaseConnection()) {
                // https://www.postgresql.org/docs/current/ddl-constraints.html#DDL-CONSTRAINTS-UNIQUE-CONSTRAINTS
                PreparedStatement ps = conn.prepareStatement("""
INSERT INTO Problems VALUES (?, ?, ?) 
ON CONFLICT (repo, key) 
DO UPDATE SET contents = EXCLUDED.contents                		
""");
                ps.setString(1, repo);
                ps.setString(2, key);
                ps.setBytes(3, contents);
                ps.executeUpdate();
            }
        } catch (SQLException ex) {
            logger.log(Logger.Level.ERROR, ex.getMessage());
            throw new IOException(ex);
        }
    }

    public ObjectNode readAssignment(String assignmentID) throws IOException {
        try (Connection conn = config.getDatabaseConnection()) {
            PreparedStatement ps = conn.prepareStatement("SELECT json FROM CodeCheckAssignments WHERE assignmentID = ?");
            ps.setString(1, assignmentID);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return Util.fromJsonString(rs.getString(1));
            else return null;
        } catch (SQLException ex) {
            throw new IOException(ex);
        }
    }

    public String readLegacyLTIResource(String resourceID) throws IOException{
        return null;
    }

    public String readLTISharedSecret(String oauthConsumerKey) throws IOException{
        try (Connection conn = config.getDatabaseConnection()) {
            PreparedStatement ps = conn.prepareStatement("SELECT shared_secret FROM CodeCheckLTICredentials WHERE oauth_consumer_key = ?");
            ps.setString(1, oauthConsumerKey);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return rs.getString(1);
            else return null;
        } catch (SQLException ex) {
            throw new IOException(ex);
        }
    }

    public String readComment(String assignmentID, String workID) throws IOException{
        try (Connection conn = config.getDatabaseConnection()) {
            PreparedStatement ps = conn.prepareStatement("SELECT comment FROM CodeCheckComments WHERE assignmentID = ? AND workID = ?");
            ps.setString(1, assignmentID);
            ps.setString(2, workID);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return rs.getString(1);
            else return null;
        } catch (SQLException ex) {
            throw new IOException(ex);
        }
    }

    public ObjectNode readWork(String assignmentID, String workID) throws IOException{
        String result = readWorkString(assignmentID, workID);
        return result == null ? null : Util.fromJsonString(result);
    }

    public String readWorkString(String assignmentID, String workID) throws IOException{
        try (Connection conn = config.getDatabaseConnection()) {
            PreparedStatement ps = conn.prepareStatement("SELECT json FROM CodeCheckWork WHERE assignmentID = ? AND workID = ?");
            ps.setString(1, assignmentID);
            ps.setString(2, workID);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return rs.getString(1);
            else return null;
        } catch (SQLException ex) {
            throw new IOException(ex);
        }
    }

    public ObjectNode readNewestSubmission(String submissionID) throws IOException{
        try (Connection conn = config.getDatabaseConnection()) {
            PreparedStatement ps = conn.prepareStatement(
                    """
                    SELECT json FROM CodeCheckSubmissions WHERE submissionID = ? AND submittedAT = 
                      (SELECT MAX(submittedAt) FROM CodeCheckSubmissions WHERE submissionID = ?)           		
                    """);
            ps.setString(1, submissionID);
            ps.setString(2, submissionID);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) return Util.fromJsonString(rs.getString(1));
            else return null;
        } catch (SQLException ex) {
            throw new IOException(ex);
        }

    }

    public Map<String, ObjectNode> readAllWork(String assignmentID) throws IOException{
        Map<String, ObjectNode> result = new HashMap<>();
        try (Connection conn = config.getDatabaseConnection()) {
            PreparedStatement ps = conn.prepareStatement("SELECT workID, json FROM CodeCheckWork WHERE assignmentID = ?");
            ps.setString(1, assignmentID);
            ResultSet rs = ps.executeQuery();
            while (rs.next())
                result.put(rs.getString(1), Util.fromJsonString(rs.getString(2)));
            return result;
        } catch (SQLException ex) {
            throw new IOException(ex);
        }
    }

    public void writeAssignment(JsonNode node) throws IOException {
        try {
            try (Connection conn = config.getDatabaseConnection()) {
                // https://wiki.postgresql.org/wiki/What's_new_in_PostgreSQL_9.5#INSERT_..._ON_CONFLICT_DO_NOTHING.2FUPDATE_.28.22UPSERT.22.29
                PreparedStatement ps = conn.prepareStatement("""
INSERT INTO CodeCheckAssignments VALUES (?, ?) 
ON CONFLICT (assignmentID) 
DO UPDATE SET json = EXCLUDED.json                		
""");
                ps.setString(1, node.get("assignmentID").asText());
                ps.setString(2, node.toString());
                ps.executeUpdate();
            }
        } catch (SQLException ex) {
            logger.log(Logger.Level.ERROR, ex.getMessage());
            throw new IOException(ex);
        }
    }

    public void writeSubmission(JsonNode node) throws IOException {
        try {
            try (Connection conn = config.getDatabaseConnection()) {
                PreparedStatement ps = conn.prepareStatement("INSERT INTO CodeCheckSubmissions VALUES (?, ?, ?)");
                ps.setString(1, node.get("submissionID").asText());
                ps.setString(2, node.get("submittedAt").asText());
                ps.setString(3, node.toString());
                ps.executeUpdate();
            }
        } catch (SQLException ex) {
            logger.log(Logger.Level.ERROR, ex.getMessage());
            throw new IOException(ex);
        }
    }

    public void writeComment(JsonNode node)  throws IOException {
        try {
            try (Connection conn = config.getDatabaseConnection()) {
                // https://www.postgresql.org/docs/current/ddl-constraints.html#DDL-CONSTRAINTS-UNIQUE-CONSTRAINTS
                PreparedStatement ps = conn.prepareStatement("""
INSERT INTO CodeCheckComments VALUES (?, ?, ?) 
ON CONFLICT (assignmentID, workID) 
DO UPDATE SET comment = EXCLUDED.comment                		
""");
                ps.setString(1, node.get("assignmentID").asText());
                ps.setString(2, node.get("workID").asText());
                ps.setString(3, node.get("comment").asText());
                ps.executeUpdate();
            }
        } catch (SQLException ex) {
            logger.log(Logger.Level.ERROR, ex.getMessage());
            throw new IOException(ex);
        }
    }

    public boolean writeWork(JsonNode node) throws IOException {
        try {
            try (Connection conn = config.getDatabaseConnection()) {
                // https://www.postgresql.org/docs/current/ddl-constraints.html#DDL-CONSTRAINTS-UNIQUE-CONSTRAINTS
                PreparedStatement ps = conn.prepareStatement("""
INSERT INTO CodeCheckWork VALUES (?, ?, ?, ?) 
ON CONFLICT (assignmentID, workID) 
DO UPDATE SET submittedAt = EXCLUDED.submittedAt, json = EXCLUDED.json
WHERE CodeCheckWork.submittedAt < EXCLUDED.submittedAt                 		
""");
                ps.setString(1, node.get("assignmentID").asText());
                ps.setString(2, node.get("workID").asText());
                ps.setString(3, node.get("submittedAt").asText());
                ps.setString(4, node.toString());
                int rowcount = ps.executeUpdate();
                return rowcount > 0;
            }
        } catch (SQLException ex) {
            logger.log(Logger.Level.ERROR, ex.getMessage());
            throw new IOException(ex);
        }
    }
}

