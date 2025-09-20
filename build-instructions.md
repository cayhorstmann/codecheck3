# CodeCheck<sup>®</sup> Build Instructions

## Program Structure

CodeCheck has three parts:

-   A web application that manages submission and assignments. It is
    called `codecheck-webapp`.
-   A service that compiles and runs programs, called
    `comrun`. You can find a description in the `comrun/bin/comrun` script.
-   An optional command-line tool `codecheck` for running the checker locally.    

The `codecheck-webapp` program has these responsibilities:

-   Display problems, collect submissions from students, and check them
-   Manage problems from instructors
-   Manage assignments (consisting of multiple problems)
-   Interface with learning management systems through the LTI protocol

## Prepare your environment

If you are running Linux or Github Codespaces, you don't need to install Ubuntu 24.04. Otherwise, make yourself a virtual machine. These instructions should be helpful: https://horstmann.com/pfh/2021/vm.html (but use the Ubuntu 24.04 ISO).

If you are using Codespaces, make a new codespace for the repository `cayhorstmann/codecheck3`

## Building the Command Line Tool

Install some packages:

```
sudo apt update
sudo apt -y install openjdk-21-jdk maven git curl zip unzip
```

Clone the repo (unless you are in Codespaces, where it is already cloned)

    git clone https://github.com/cayhorstmann/codecheck3

Some housekeeping:

    cd codecheck3 # if not already there
    cd cli
    mkdir lib
    cd lib
    curl -LOs https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-core/2.6.4/jackson-core-2.6.4.jar
    curl -LOs https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-annotations/2.6.4/jackson-annotations-2.6.4.jar
    curl -LOs https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.6.4/jackson-databind-2.6.4.jar
    cd ../../comrun/bin
    mkdir lib
    cd lib
    curl -LOs https://repo1.maven.org/maven2/com/puppycrawl/tools/checkstyle/10.21.2/checkstyle-10.21.2-all.jar
    curl -LOs https://repo1.maven.org/maven2/org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar
    curl -LOs https://repo1.maven.org/maven2/junit/junit/4.13.2/junit-4.13.2.jar
    cd ../../..
    mkdir -p /opt/codecheck/repo 
        # If this fails, use sudo and give yourself ownership of /opt/codecheck and /opt/codecheck/repo
    cp -R comrun/bin/* /opt/codecheck
    chmod +x /opt/codecheck/comrun
    sudo useradd -u 1012 -ms /bin/bash comrunner

## Special Steps for Github Codespaces

Open a terminal. Run 

```
sudo sed -i -e 's/root/ALL/' /etc/sudoers.d/codespace
sudo cat /etc/sudoers.d/codespace
```

and verify that the contents starts with

```
codespace ALL=(ALL) NOPASSWD:ALL 
```

Run

```
sudo apt install acl
sudo setfacl -PRdm u::rwx,g::rx,o::rx /tmp
```

Type the following into the terminal without hitting Enter:

```
sdk default java 21
```

Now hit the Tab key. It should autocomplete to something like `21.0.7-ms`. Then hit Enter.

Type

```
java -version
```

and see that you get a Java 21 version. 

## Building the Checker

Build CodeCheck:

    cd path/to/codecheck3 # i.e. whereever you cloned the repo
        # On CodeSpaces, cd /workspaces/codecheck3
    mvn package -Dmaven.test.skip

Test that the checker works:

    chmod +x cli/codecheck 
    cli/codecheck -t samples/java/example1

If you omit the `-t`, you get a report with your default browser instead
of the text report. (Only locally, not in Codespaces.)

## IntelliJ

If you work on your own machine, use the free "community" edition of IntelliJ as the IDE. If you use Codespaces, skip this section and read about the Visual Studio Code configuration instead.

Import the Maven project.

Make a debugger configuration. Before starting, review that the setting below for `com.horstmann.codecheck.comrun.local` is appropriate. If you want to use that setting, copy the `codecheck3/comrun` directory and its subdirectories to `/opt/codecheck/bin/comrun`. Otherwise, use the path to the `comrun` directory inside your `codecheck3` project.

Select Run → Debug...

-   Name: Command Line Tool
-   Main class: `com.horstmann.codecheck.checker.Main`
-   Program arguments:

        -Duser.language=en -Duser.country=US -Dcom.horstmann.codecheck.comrun.local=/opt/codecheck/comrun -Dcom.horstmann.codecheck.report=HTML -Dcom.horstmann.codecheck.debug /tmp/submission /tmp/problem

-   Environment variable `COMRUN_USER=`(your username)

Use this debugging configuration to debug the command line tool. Use the already prepared `codecheck-webapp` configuration to debug the server. 

## Codespaces and Visual Studio Code

If you use Codespaces, you need to use Visual Studio Code as your IDE. If not, skip this section and follow the section about configuring IntelliJ instead. 

Install the Extension Pack for Java (from  vscjava), and Quarkus (from Red Hat) extensions into Visual Studio Code.

You may need to click on the teensy word "Java" in the status line and wait until it says "Java: ready". 

Click on the Run and Debug (triangle and bug) icon on the left. Select Run → Add Configuration from the menu. The file `.vscode/launch.json` is opened up. Set it to the following contents:

```
{
    "version": "0.2.0",
    "configurations": [
        {
            "preLaunchTask": "quarkus:dev",
            "type": "java",
            "request": "attach",
            "hostName": "localhost",
            "name": "Debug Quarkus application",
            "port": 5005
        },
        {
            "type": "java",
            "name": "Command Line Tool",
            "request": "launch",
            "mainClass": "com.horstmann.codecheck.Main",
            "args": "/tmp/submission /tmp/problem",
            "vmArgs": [
                "-Duser.language=en",
                "-Duser.country=US",
                "-Dcom.horstmann.codecheck.comrun.local=/opt/codecheck/comrun",
                "-Dcom.horstmann.codecheck.report=text",
                "-Dcom.horstmann.codecheck.debug"
            ],
            "env": { "COMRUN_USER": "codespace" }
        }
    ]
}
```

## Debugging the Command Line Tool

If you are making changes to the part of CodeCheck that does the actual
code checking, such as adding a new language, it is easiest to debug the command line tool.

Make directories for the submission and problem files, and populate them
with samples. For example,

```
rm -rf /tmp/submission /tmp/problem
mkdir /tmp/submission
mkdir /tmp/problem
cd path/to/codecheck3 # i.e. whereever you cloned the repo
    # On CodeSpaces, cd /workspaces/codecheck3
cp samples/java/example1/*.java /tmp/submission
cp -R samples/java/example1 /tmp/problem
```
Set a breakpoint in app/com/horstmann/codecheck/checker/Main.java and launch the debugger with the Command Line Tool configuration.

## Building the Server

Review the configuration in `src/main/resources/application.properties`. (The default configuration should work if you followed all instructions.)

Run the `codecheck-webapp` server:

    cd path/to/codecheck3 # i.e. whereever you cloned the repo
        # On CodeSpaces, cd /workspaces/codecheck3
    COMRUN_USER=$(whoami) mvn quarkus:dev

Point your browser to <http://localhost:8080/assets/uploadProblem.html>.
Upload a problem and test it.

Note: The problem files will be located inside the `/opt/codecheck/repo/ext`
directory.

If you do this inside CodeSpaces, you need to forward port 8080. On a good day, it will do this automatically, but on a really bad day it will offer to port 5005 instead. That's the debugger port which should not be forwarded. You can add port 8080 manually. Make sure it is *public*.

When you click on the link for the port (in the Ports tab of Visual Studio Code), you get a URL such as https://friendly-engine-asdf112358-8080.app.github.dev. Unfortunately, when you click on it, CodeCheck will reroute to https://friendly-engine-asdf112358-8080.app.github.dev:8080/assets/uploadProblem.html since it senses that it runs on port 8080. You need to remove that extra :8080 from the URL. 

## Debugging the Server

With IntelliJ, just run the debugger. 

With Visual Studio Code, hit F1 and select Quarkus: Debug current Quarkus project. If that is not available, make sure that the status line says: Java ready, or click on the word Java to kick it into action. 

## Podman/Docker Installation

Skip this step if you are on Codespaces. Codespaces already has Docker installed.

Install Podman and Podman-Docker:

```
sudo apt-get podman podman-docker
sudo touch /etc/containers/nodocker 
```

## Docker Local Testing

Build and run the Docker container for the `comrun` service:

    cd path/to/codecheck3 # i.e. whereever you cloned the repo
        # On CodeSpaces, cd /workspaces/codecheck3
    docker build --tag comrun:1.0-SNAPSHOT comrun
    docker run -p 8080:8080 -it comrun:1.0-SNAPSHOT &

Test that it works:

    cli/codecheck -lt samples/java/example1

Build the Docker container for the `codecheck-webapp` server. 

    LOCAL_TAG=codecheck-webapp:1.0-SNAPSHOT
    mvn clean package -Dmaven.test.skip
    docker build --tag $LOCAL_TAG -f src/main/docker/Dockerfile.jvm .
    
Run the container. If you do this on your own computer:

    docker run -p 9090:8080 -it codecheck-webapp:1.0-SNAPSHOT
    
Test that it works by pointing your browser to
<http://localhost:9090/assets/uploadProblem.html>.     

On Codespaces:

    docker run -p 9090:8080 -it --add-host host.docker.internal:host-gateway codecheck-webapp:1.0-SNAPSHOT &

Then locate the Ports tab and open the local address for port 9090. Ignore the nginx error and paste `/assets/uploadProblem.html` after the URL. 

To complete the test locally or on Codespaces, upload a problem: File name `Numbers.java`, file contents:

```
public class Numbers
{
//CALL 3, 4
//CALL -3, 3
//CALL 3, 0
   public double average(int x, int y)
   {
      //HIDE
      return 0.5 * (x + y);
      //SHOW // Compute the average of x and y
   }
}
```

Click the Submit Files button. You should see three passing test cases.

Kill both containers by running this command in the terminal:

    docker container kill $(docker ps -q)    

Comrun Service Deployment on AWS
--------------------------------

[Install the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)

Confirm the installation with the following command

```
aws --version
```

[Configure the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-quickstart.html)

```
 aws configure –-profile your-username
```

Set
* Access key ID
* Secret access key
* AWS Region
* Output format

You should now have the two files, `.aws/credentials` and `.aws/config`. 

The ```.aws/credentials``` file should contain:
```
[your-username]
aws_access_key_id=...
aws_secret_access_key=...
```

And the ```.aws/config``` file:
```
[profile your-username]
region = your-region #example: us-west-2
output = json

```

Set environment variables: 

```
export AWS_DEFAULT_PROFILE=your-username
ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
echo Account ID: $ACCOUNT_ID
REGION=$(aws configure get region)
echo Region: $REGION
```

If ```REGION=$(aws configure get region)``` shows up to be the incorrect region, check out this link https://docs.aws.amazon.com/general/latest/gr/apprunner.html and set your region to the correct one by typing 

```
REGION = your-region
```

Create an IAM Accesss Role and attach a pre-existing policy for access to container repositories.

```
export TEMPFILE=$(mktemp)
export ROLE_NAME=AppRunnerECRAccessRole
cat <<EOF | tee $TEMPFILE
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "build.apprunner.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam create-role --role-name $ROLE_NAME --assume-role-policy-document file://$TEMPFILE

rm $TEMPFILE

aws iam attach-role-policy --role-name $ROLE_NAME --policy-arn arn:aws:iam::aws:policy/service-role/AWSAppRunnerServicePolicyForECRAccess 
```

Next we set up a repository for Docker images:

```
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

ECR_REPOSITORY=ecr-comrun

aws ecr create-repository \
     --repository-name $ECR_REPOSITORY \
     --region $REGION
```

Now push the image to that repository:

```
docker images
PROJECT=comrun

docker tag $PROJECT:1.0-SNAPSHOT $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$ECR_REPOSITORY

docker push $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$ECR_REPOSITORY
```

To see if we have pushed the docker image into the ECR repository, run:

```
aws ecr describe-images --repository-name $ECR_REPOSITORY --region $REGION
```

Finally, we deploy the comrun service to AWS App Runner:

```
export TEMPFILE=$(mktemp)

cat <<EOF | tee $TEMPFILE
{
     "ImageRepository": {
         "ImageIdentifier": "$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$ECR_REPOSITORY:latest",
         "ImageConfiguration": {
            "Port": "8080"
        },
         "ImageRepositoryType": "ECR"
     },
     "AutoDeploymentsEnabled": true,
     "AuthenticationConfiguration": {
         "AccessRoleArn": "arn:aws:iam::$ACCOUNT_ID:role/AppRunnerECRAccessRole"
     }
}
EOF

aws apprunner --region $REGION create-service --service-name comrun --source-configuration file://$TEMPFILE
```

Save the service URL. Then wait until has the service status as  ```RUNNING```. 

 ```
 aws apprunner --region $REGION list-services
 ```

Then test it: 

```
curl service-URL
```

If you get

```
<form action="/api/upload" enctype="multipart/form-data" method="post">
   <div>File: <input type="file" name="job"/></div>
   <input type="submit" value="Upload" />
</form>
```

the comrun service was deployed.

To test that the service is working properly, do this:

    cd path-to-codecheck2-repo
    export REMOTE_URL=service-URL
    /opt/codecheck/codecheck -rt samples/java/example1

You should get a report that was obtained by sending the compile and run
jobs to your remote service.

Alternatively, you can test with the locally running web app. In
`src/main/resources/application-prod.properties`, you need to add

    com.horstmann.codecheck.comrun.remote=service-URL/api/upload    

Using AWS Data Storage
----------------------

Set environment variables and create a user in your Amazon AWS account:

```
ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
echo Account ID: $ACCOUNT_ID
REGION=$(aws configure get region)
echo Region: $REGION

USERNAME=codecheck

aws iam create-user --user-name $USERNAME
aws iam create-access-key --user-name $USERNAME

# IMPORTANT: Record AccessKeyId and SecretAccessKey
```

In Amazon S3, create a bucket whose name starts with the four characters `ext.` and an arbitrary suffix, such as `ext.mydomain.com` to hold
the uploaded CodeCheck problems. Set the ACL so that the bucket owner has all access rights and nobody else has any.

```
# Change the suffix below
SUFFIX=mydomain.com

aws s3 mb s3://ext.$SUFFIX

cat <<EOF > CodeCheckS3.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:*"
            ],
            "Resource": [
                "arn:aws:s3:::ext.$SUFFIX"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:*"
            ],
            "Resource": [
                "arn:aws:s3:::ext.$SUFFIX/*"
            ]
        }
    ]
}
EOF

aws iam create-policy --policy-name CodeCheckS3 --policy-document file://./CodeCheckS3.json

aws iam attach-user-policy --user-name $USERNAME \
  --policy-arn arn:aws:iam::$ACCOUNT_ID:policy/CodeCheckS3
```

If you use CodeCheck with LTI, you need to set up an Amazon Dynamo database. Create the following tables:

| Name                      | Partition key      | Sort key    |
| ------------------------- | ------------------ | ----------- |
| CodeCheckAssignments      | assignmentID       |             |
| CodeCheckLTICredentials   | oauth_consumer_key |             |
| CodeCheckLTIResources     | resourceID         |             |
| CodeCheckSubmissions      | submissionID       | submittedAt |
| CodeCheckWork             | assignmentID       | workID      |
| CodeCheckComments         | assignmentID       | workID      |

The first three tables have no sort key. All types are `String`.

```
aws --region $REGION dynamodb create-table \
    --table-name CodeCheckAssignments \
    --attribute-definitions AttributeName=assignmentID,AttributeType=S \
    --key-schema AttributeName=assignmentID,KeyType=HASH \
    --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1

aws --region $REGION dynamodb create-table \
    --table-name CodeCheckLTICredentials \
    --attribute-definitions AttributeName=oauth_consumer_key,AttributeType=S \
    --key-schema AttributeName=oauth_consumer_key,KeyType=HASH \
    --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1

aws --region $REGION dynamodb create-table \
    --table-name CodeCheckLTIResources \
    --attribute-definitions AttributeName=resourceID,AttributeType=S \
    --key-schema AttributeName=resourceID,KeyType=HASH \
    --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1

aws --region $REGION dynamodb create-table \
    --table-name CodeCheckSubmissions \
    --attribute-definitions AttributeName=submissionID,AttributeType=S AttributeName=submittedAt,AttributeType=S \
    --key-schema AttributeName=submissionID,KeyType=HASH AttributeName=submittedAt,KeyType=RANGE \
    --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1

aws --region $REGION dynamodb create-table \
    --table-name CodeCheckWork \
    --attribute-definitions AttributeName=assignmentID,AttributeType=S AttributeName=workID,AttributeType=S \
    --key-schema AttributeName=assignmentID,KeyType=HASH AttributeName=workID,KeyType=RANGE \
    --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1
    
aws --region $REGION dynamodb create-table \
    --table-name CodeCheckComments \
    --attribute-definitions AttributeName=assignmentID,AttributeType=S AttributeName=workID,AttributeType=S \
    --key-schema AttributeName=assignmentID,KeyType=HASH AttributeName=workID,KeyType=RANGE \
    --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1
    
cat <<EOF > CodeCheckDynamo.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
                "dynamodb:DeleteItem",
                "dynamodb:BatchWriteItem",
                "dynamodb:GetItem",
                "dynamodb:BatchGetItem",
                "dynamodb:Scan",
                "dynamodb:Query",
                "dynamodb:ConditionCheckItem"
            ],
            "Resource": [
                "arn:aws:dynamodb:us-west-1:$ACCOUNT_ID:table/CodeCheck*",
                "arn:aws:dynamodb:us-west-1:$ACCOUNT_ID:table/CodeCheck*/index/*"
            ]
        }
    ]
}
EOF

aws iam create-policy --policy-name CodeCheckDynamo --policy-document file://./CodeCheckDynamo.json

aws iam attach-user-policy --user-name $USERNAME \
  --policy-arn arn:aws:iam::$ACCOUNT_ID:policy/CodeCheckDynamo

aws iam list-attached-user-policies --user-name $USERNAME    
```

You need to populate the `CodeCheckLTICredentials` table with at least one pair `oauth_consumer_key` and `shared_secret` (both of type `String`). These can be any values. I recommend to use the admin's email for `oauth_consumer_key` and a random password for `shared_secret`. 

```
USERNAME=codecheck
PASSWORD=$(strings /dev/urandom | grep -E '[^ ]{8}' | head -1)
echo Password: $PASSWORD
aws dynamodb put-item --table-name CodeCheckLTICredentials --item '{"oauth_consumer_key":{"S":"'${USERNAME}'"},"shared_secret":{"S":"'${PASSWORD}'"}}'
```

Server Deployment (AWS)
-----------------------

Make another ECR repository to store in the codecheck-webapp service. Note that you need the `ACCOUNT_ID` and `REGION` environment variables from the comrun deployment.


    ECR_REPOSITORY=ecr-codecheck-webapp

    aws ecr create-repository \
         --repository-name $ECR_REPOSITORY \
         --region $REGION

Make a file `src/main/resources/application-prod.properties`. *DO NOT* check it into version control.

Add the following entries:

    com.horstmann.codecheck.jwt.secret.key= Description TODO
    com.horstmann.codecheck.comrun.remote="comrun host URL/api/upload"
    com.horstmann.codecheck.storage.type=aws
    com.horstmann.codecheck.aws.accessKey= your AWS credentials
    com.horstmann.codecheck.aws.secretKey=
    com.horstmann.codecheck.s3.bucketsuffix="mydomain.com"
    com.horstmann.codecheck.s3.region=your AWS region such as "us-west-1"
    com.horstmann.codecheck.dynamodb.region=your AWS region such as "us-west-1"

Run

    LOCAL_TAG=codecheck-webapp:1.0-SNAPSHOT
    mvn clean package -Dmaven.test.skip
    docker build --tag $LOCAL_TAG -f src/main/docker/Dockerfile.jvm .

Upload the container image to the ECR repository

    docker images 
    PROJECT=codecheck-webapp

    docker tag $PROJECT:1.0-SNAPSHOT $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$ECR_REPOSITORY

    docker push $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$ECR_REPOSITORY
    
To see that we have pushed the docker image into the ECR repository run:

    aws ecr describe-images --repository-name $ECR_REPOSITORY --region $REGION

Then deploy the codecheck-webapp service

```
export TEMPFILE=$(mktemp)

cat <<EOF | tee $TEMPFILE
{
     "ImageRepository": {
         "ImageIdentifier": "$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$ECR_REPOSITORY:latest",
         "ImageConfiguration": {
            "Port": "8080"
        },
         "ImageRepositoryType": "ECR"
     },
     "AutoDeploymentsEnabled": true,
     "AuthenticationConfiguration": {
         "AccessRoleArn": "arn:aws:iam::$ACCOUNT_ID:role/AppRunnerECRAccessRole"
     }
}
EOF

aws apprunner --region $REGION create-service --service-name $PROJECT --source-configuration file://$TEMPFILE

rm $TEMPFILE

```

Make note of the service URL. Then wait until it has the service status as  `RUNNING`. 

    aws apprunner --region $REGION list-services

You will get a URL for the service. Now point your browser to
`https://service url/assets/uploadProblem.html`

SQL Data Storage (Alternative to AWS S3 and Dynamo)
---------------------------------------------------

If you have access to a SQL database or want to use a free tier for testing, SQL data storage is much simpler to configure than AWS S3 and Dynamo. However, it is likely to be more expensive in the long run.

These instructions assume that your database is PostgreSQL. If not, you need to change the driver in pom.xml.

In `src/main/resources/application-prod.conf`, define

    db.default.url="postgres://username:password@host:database"

Make sure that 

    com.horstmann.codecheck.s3.region
    com.horstmann.codecheck.dynamodb.region
    
are *not* defined.    

Create tables as follows:

    CREATE TABLE Problems (repo VARCHAR, key VARCHAR, contents BYTEA)
    CREATE TABLE CodeCheckAssignments (assignmentID VARCHAR, json VARCHAR)
    CREATE TABLE CodeCheckLTICredentials (oauth_consumer_key VARCHAR, shared_secret VARCHAR)
    CREATE TABLE CodeCheckComments (assignmentID VARCHAR, workID VARCHAR, comment VARCHAR)
    CREATE TABLE CodeCheckWork (assignmentID VARCHAR, workID VARCHAR, json VARCHAR)
    CREATE TABLE CodeCheckSubmissions (submissionID VARCHAR, submittedAt VARCHAR, json VARCHAR)

