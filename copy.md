# GitHub-GitLab Bidirectional Sync API Documentation

Github sync to Gitlab and gitlab to github bidirectional sync
Description
The goal of this process app is to synchronize changes commit, branch between GitHub and GitLab in real-time using webhooks. Whenever an event  occurs in GitHub or GitLab, it will trigger the corresponding flow in MuleSoft to perform the sync.
Key Components
GitHub Webhook: Configured in GitHub to notify MuleSoft whenever an event  happens.
GitLab Webhook: Configured in GitLab to notify MuleSoft when a change occurs in GitLab repositories.
MuleSoft Integration Layer: MuleSoft listens for events from both webhooks, processes the data, and synchronizes it between GitHub and GitLab.
mule 4
i need a separate root raml, datatype(should have necessary fields) raml, example raml, trait raml, libraries raml, security schema(basic authentication) and also should have 5 http status code responses for bidirectional sync
create global xml, pom xml, config xml and secure properties yaml
i will be deploy mule app in cloudhub for webhook testing



## POM XML

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         https://maven.apache.org/xsd/maven-4.0.0.xsd">

    <modelVersion>4.0.0</modelVersion>
    <groupId>com.company.sync</groupId>
    <artifactId>github-gitlab-sync</artifactId>
    <version>1.0.0</version>
    <packaging>mule-application</packaging>
    <name>github-gitlab-sync</name>
    <description>Bidirectional synchronization between GitHub and GitLab repositories</description>

    <properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
        <app.runtime>4.6.0</app.runtime>
        <mule.maven.plugin.version>4.2.0</mule.maven.plugin.version>
        <maven.compiler.source>8</maven.compiler.source>
        <maven.compiler.target>8</maven.compiler.target>
    </properties>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-clean-plugin</artifactId>
                <version>3.2.0</version>
            </plugin>
            <plugin>
                <groupId>org.mule.tools.maven</groupId>
                <artifactId>mule-maven-plugin</artifactId>
                <version>${mule.maven.plugin.version}</version>
                <extensions>true</extensions>
                <configuration>
                    <sharedLibraries>
                        <sharedLibrary>
                            <groupId>mysql</groupId>
                            <artifactId>mysql-connector-java</artifactId>
                        </sharedLibrary>
                    </sharedLibraries>
                    <classifier>mule-application</classifier>
                    <cloudhub2Deployment>
                        <uri>https://anypoint.mulesoft.com</uri>
                        <provider>MC</provider>
                        <environment>${env}</environment>
                        <target>${target}</target>
                        <muleVersion>${app.runtime}</muleVersion>
                        <username>${username}</username>
                        <password>${password}</password>
                        <applicationName>${cloudhub.application.name}</applicationName>
                        <businessGroupId>${business.group.id}</businessGroupId>
                        <replicas>${workers}</replicas>
                        <vCores>${worker.type}</vCores>
                        <properties>
                            <env>${env}</env>
                            <encryption.key>${encryption.key}</encryption.key>
                        </properties>
                    </cloudhub2Deployment>
                </configuration>
            </plugin>
        </plugins>
    </build>

    <dependencies>
        <!-- Mule Runtime -->
        <dependency>
            <groupId>org.mule.connectors</groupId>
            <artifactId>mule-http-connector</artifactId>
            <version>1.9.3</version>
            <classifier>mule-plugin</classifier>
        </dependency>
        <dependency>
            <groupId>org.mule.connectors</groupId>
            <artifactId>mule-sockets-connector</artifactId>
            <version>1.2.4</version>
            <classifier>mule-plugin</classifier>
        </dependency>
        <dependency>
            <groupId>org.mule.modules</groupId>
            <artifactId>mule-apikit-module</artifactId>
            <version>1.10.4</version>
            <classifier>mule-plugin</classifier>
        </dependency>
        <dependency>
            <groupId>org.mule.connectors</groupId>
            <artifactId>mule-validation-module</artifactId>
            <version>2.0.4</version>
            <classifier>mule-plugin</classifier>
        </dependency>
        
        <!-- Secure Properties -->
        <dependency>
            <groupId>com.mulesoft.modules</groupId>
            <artifactId>mule-secure-configuration-property-module</artifactId>
            <version>1.2.5</version>
            <classifier>mule-plugin</classifier>
        </dependency>
        
        <!-- JSON Module -->
        <dependency>
            <groupId>org.mule.modules</groupId>
            <artifactId>mule-json-module</artifactId>
            <version>2.3.2</version>
            <classifier>mule-plugin</classifier>
        </dependency>
        
        <!-- Crypto Module -->
        <dependency>
            <groupId>org.mule.modules</groupId>
            <artifactId>mule-crypto-module</artifactId>
            <version>1.4.2</version>
            <classifier>mule-plugin</classifier>
        </dependency>
        
        <!-- OAuth Module -->
        <dependency>
            <groupId>org.mule.modules</groupId>
            <artifactId>mule-oauth-module</artifactId>
            <version>1.2.4</version>
            <classifier>mule-plugin</classifier>
        </dependency>
        
        <!-- Batch Module -->
        <dependency>
            <groupId>org.mule.modules</groupId>
            <artifactId>mule-batch-module</artifactId>
            <version>1.1.3</version>
            <classifier>mule-plugin</classifier>
        </dependency>
        
        <!-- MySQL Connector -->
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>8.0.30</version>
        </dependency>
        
        <!-- Test Dependencies -->
        <dependency>
            <groupId>org.mule.weave</groupId>
            <artifactId>assertions</artifactId>
            <version>1.2.1</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.mule.tests</groupId>
            <artifactId>mule-tests-functional</artifactId>
            <version>${app.runtime}</version>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <repositories>
        <repository>
            <id>anypoint-exchange-v3</id>
            <name>Anypoint Exchange</name>
            <url>https://maven.anypoint.mulesoft.com/api/v3/maven</url>
            <layout>default</layout>
        </repository>
        <repository>
            <id>mulesoft-releases</id>
            <name>MuleSoft Releases Repository</name>
            <url>https://repository.mulesoft.org/releases/</url>
            <layout>default</layout>
        </repository>
    </repositories>

    <pluginRepositories>
        <pluginRepository>
            <id>mulesoft-releases</id>
            <name>MuleSoft Releases Repository</name>
            <layout>default</layout>
            <url>https://repository.mulesoft.org/releases/</url>
            <snapshots>
                <enabled>false</enabled>
            </snapshots>
        </pluginRepository>
    </pluginRepositories>

</project>


## GLOBAL XML

```xml
<?xml version="1.0" encoding="UTF-8"?>

<mule xmlns:secure-properties="http://www.mulesoft.org/schema/mule/secure-properties"
      xmlns:apikit="http://www.mulesoft.org/schema/mule/mule-apikit"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns:crypto="http://www.mulesoft.org/schema/mule/crypto"
      xmlns:json="http://www.mulesoft.org/schema/mule/json"
      xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="
        http://www.mulesoft.org/schema/mule/core http://www.mulesoft.org/schema/mule/core/current/mule.xsd
        http://www.mulesoft.org/schema/mule/http http://www.mulesoft.org/schema/mule/http/current/mule-http.xsd
        http://www.mulesoft.org/schema/mule/mule-apikit http://www.mulesoft.org/schema/mule/mule-apikit/current/mule-apikit.xsd
        http://www.mulesoft.org/schema/mule/secure-properties http://www.mulesoft.org/schema/mule/secure-properties/current/mule-secure-properties.xsd
        http://www.mulesoft.org/schema/mule/crypto http://www.mulesoft.org/schema/mule/crypto/current/mule-crypto.xsd
        http://www.mulesoft.org/schema/mule/json http://www.mulesoft.org/schema/mule/json/current/mule-json.xsd">

    <!-- Secure Properties Configuration -->
    <secure-properties:config name="Secure_Properties_Config" 
                             file="secure-config-${mule.env}.yaml" 
                             key="${encryption.key}"
                             doc:name="Secure Properties Config" />

    <!-- Configuration Properties -->
    <configuration-properties file="config-${mule.env}.properties" doc:name="Configuration properties" />

    <!-- Global Error Handler -->
    <error-handler name="Global_Error_Handler" doc:name="Global Error Handler">
        <on-error-propagate enableNotifications="true" logException="true" doc:name="On Error Propagate" type="ANY">
            <set-variable value="#[correlationId]" doc:name="Set Correlation ID" variableName="correlationId"/>
            <set-variable value="#[now()]" doc:name="Set Timestamp" variableName="timestamp"/>
            <set-payload value='#[{
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred while processing the request",
                "status_code": 500,
                "timestamp": vars.timestamp,
                "correlation_id": vars.correlationId,
                "details": {
                    "error_code": error.errorType.identifier,
                    "error_description": error.description
                }
            }]' doc:name="Set Error Response"/>
            <set-variable value="500" doc:name="Set Status Code" variableName="httpStatus"/>
        </on-error-propagate>
    </error-handler>

    <!-- HTTP Listener Configuration -->
    <http:listener-config name="HTTP_Listener_config" doc:name="HTTP Listener config">
        <http:listener-connection host="0.0.0.0" 
                                port="${http.port}" 
                                protocol="HTTPS"
                                tlsContext="TLS_Context"/>
    </http:listener-config>

    <!-- TLS Context for HTTPS -->
    <tls:context name="TLS_Context" doc:name="TLS Context">
        <tls:key-store type="pkcs12" 
                      path="${secure::tls.keystore.path}" 
                      keyPassword="${secure::tls.keystore.password}" 
                      password="${secure::tls.keystore.password}"/>
    </tls:context>

    <!-- APIKit Configuration -->
    <apikit:config name="github-gitlab-sync-config" 
                  api="github-gitlab-sync-api.raml" 
                  outboundHeadersMapName="outboundHeaders" 
                  httpStatusVarName="httpStatus" 
                  doc:name="APIKit Config"/>

    <!-- HTTP Request Configuration for GitHub API -->
    <http:request-config name="GitHub_API_Config" doc:name="GitHub API Config" protocol="HTTPS" host="api.github.com" port="443">
        <http:request-connection>
            <http:authentication>
                <http:basic-authentication username="${secure::github.username}" password="${secure::github.token}"/>
            </http:authentication>
            <http:client-socket-properties>
                <http:tcp-client-socket-properties connectionTimeout="30000" clientTimeout="60000"/>
            </http:client-socket-properties>
        </http:request-connection>
        <http:default-headers>
            <http:default-header key="Accept" value="application/vnd.github.v3+json"/>
            <http:default-header key="User-Agent" value="GitHub-GitLab-Sync/1.0"/>
        </http:default-headers>
    </http:request-config>

    <!-- HTTP Request Configuration for GitLab API -->
    <http:request-config name="GitLab_API_Config" doc:name="GitLab API Config" protocol="HTTPS" host="gitlab.com" port="443">
        <http:request-connection>
            <http:authentication>
                <http:basic-authentication username="${secure::gitlab.username}" password="${secure::gitlab.token}"/>
            </http:authentication>
            <http:client-socket-properties>
                <http:tcp-client-socket-properties connectionTimeout="30000" clientTimeout="60000"/>
            </http:client-socket-properties>
        </http:request-connection>
        <http:default-headers>
            <http:default-header key="Accept" value="application/json"/>
            <http:default-header key="User-Agent" value="GitHub-GitLab-Sync/1.0"/>
        </http:default-headers>
    </http:request-config>

    <!-- Crypto Configuration for HMAC Verification -->
    <crypto:hmac-config name="HMAC_Config" doc:name="HMAC Config" algorithm="HmacSHA256"/>

    <!-- JSON Schema Validator Configuration -->
    <json:schema-validator-config name="JSON_Schema_Validator_Config" doc:name="JSON Schema Validator Config"/>

    <!-- Global Variables -->
    <global-property name="api.version" value="v1" doc:name="API Version"/>
    <global-property name="sync.batch.size" value="100" doc:name="Sync Batch Size"/>
    <global-property name="sync.timeout" value="300000" doc:name="Sync Timeout (5 minutes)"/>
    <global-property name="retry.max.attempts" value="3" doc:name="Max Retry Attempts"/>
    <global-property name="retry.delay" value="5000" doc:name="Retry Delay (5 seconds)"/>

    <!-- Correlation ID Generation -->
    <configuration doc:name="Configuration" defaultErrorHandler-ref="Global_Error_Handler"/>

</mule>


## GitHub-GitLab Sync Implemenatation Flows

```xml
<?xml version="1.0" encoding="UTF-8"?>

<mule xmlns:crypto="http://www.mulesoft.org/schema/mule/crypto"
      xmlns:validation="http://www.mulesoft.org/schema/mule/validation"
      xmlns:json="http://www.mulesoft.org/schema/mule/json"
      xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core"
      xmlns:apikit="http://www.mulesoft.org/schema/mule/mule-apikit"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="
        http://www.mulesoft.org/schema/mule/core http://www.mulesoft.org/schema/mule/core/current/mule.xsd
        http://www.mulesoft.org/schema/mule/http http://www.mulesoft.org/schema/mule/http/current/mule-http.xsd
        http://www.mulesoft.org/schema/mule/mule-apikit http://www.mulesoft.org/schema/mule/mule-apikit/current/mule-apikit.xsd
        http://www.mulesoft.org/schema/mule/ee/core http://www.mulesoft.org/schema/mule/ee/core/current/mule-ee.xsd
        http://www.mulesoft.org/schema/mule/json http://www.mulesoft.org/schema/mule/json/current/mule-json.xsd
        http://www.mulesoft.org/schema/mule/validation http://www.mulesoft.org/schema/mule/validation/current/mule-validation.xsd
        http://www.mulesoft.org/schema/mule/crypto http://www.mulesoft.org/schema/mule/crypto/current/mule-crypto.xsd">

    <!-- Main API Router Flow -->
    <flow name="github-gitlab-sync-main">
        <http:listener doc:name="HTTP Listener" 
                      config-ref="HTTP_Listener_config" 
                      path="/api/*">
            <http:response statusCode="#[vars.httpStatus default 200]">
                <http:headers>#[vars.outboundHeaders default {}]</http:headers>
            </http:response>
            <http:error-response statusCode="#[vars.httpStatus default 500]">
                <http:headers>#[vars.outboundHeaders default {}]</http:headers>
            </http:error-response>
        </http:listener>
        
        <!-- Set Correlation ID -->
        <set-variable value="#[correlationId]" doc:name="Set Correlation ID" variableName="correlationId"/>
        <set-variable value="#[now()]" doc:name="Set Timestamp" variableName="timestamp"/>
        
        <!-- Add CORS Headers -->
        <set-variable value='#[{
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With, X-GitHub-Event, X-GitLab-Event",
            "X-Correlation-ID": vars.correlationId
        }]' doc:name="Set CORS Headers" variableName="outboundHeaders"/>
        
        <!-- APIKit Router -->
        <apikit:router config-ref="github-gitlab-sync-config" doc:name="APIKit Router"/>
        
        <error-handler>
            <on-error-propagate enableNotifications="true" logException="true" doc:name="On Error Propagate" type="APIKIT:BAD_REQUEST">
                <ee:transform doc:name="Transform Message">
                    <ee:message>
                        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
    "error": "BAD_REQUEST",
    "message": "Invalid request format or missing required parameters",
    "status_code": 400,
    "timestamp": vars.timestamp,
    "correlation_id": vars.correlationId
}]]></ee:set-payload>
                    </ee:message>
                </ee:transform>
                <set-variable value="400" doc:name="Set Status 400" variableName="httpStatus"/>
            </on-error-propagate>
            
            <on-error-propagate enableNotifications="true" logException="true" doc:name="On Error Propagate" type="APIKIT:NOT_FOUND">
                <ee:transform doc:name="Transform Message">
                    <ee:message>
                        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
    "error": "NOT_FOUND",
    "message": "The requested resource was not found",
    "status_code": 404,
    "timestamp": vars.timestamp,
    "correlation_id": vars.correlationId
}]]></ee:set-payload>
                    </ee:message>
                </ee:transform>
                <set-variable value="404" doc:name="Set Status 404" variableName="httpStatus"/>
            </on-error-propagate>
            
            <on-error-propagate enableNotifications="true" logException="true" doc:name="On Error Propagate" type="APIKIT:METHOD_NOT_ALLOWED">
                <ee:transform doc:name="Transform Message">
                    <ee:message>
                        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
    "error": "METHOD_NOT_ALLOWED",
    "message": "HTTP method not allowed for this resource",
    "status_code": 405,
    "timestamp": vars.timestamp,
    "correlation_id": vars.correlationId
}]]></ee:set-payload>
                    </ee:message>
                </ee:transform>
                <set-variable value="405" doc:name="Set Status 405" variableName="httpStatus"/>
            </on-error-propagate>
        </error-handler>
    </flow>

    <!-- GitHub Webhook Handler Flow -->
    <flow name="post:\github\webhook:github-gitlab-sync-config">
        <logger level="INFO" doc:name="Log GitHub Webhook Received" 
                message="GitHub webhook received - Event: #[attributes.headers.'X-GitHub-Event' default 'unknown'], Delivery: #[attributes.headers.'X-GitHub-Delivery' default 'unknown']"/>
        
        <!-- Authentication Check -->
        <flow-ref doc:name="Validate Authentication" name="validate-authentication-subflow"/>
        
        <!-- Validate GitHub Webhook Signature -->
        <flow-ref doc:name="Validate GitHub Signature" name="validate-github-signature-subflow"/>
        
        <!-- Validate Request Payload -->
        <flow-ref doc:name="Validate GitHub Payload" name="validate-github-payload-subflow"/>
        
        <!-- Process GitHub Event -->
        <flow-ref doc:name="Process GitHub Event" name="process-github-event-subflow"/>
        
        <!-- Sync to GitLab -->
        <flow-ref doc:name="Sync to GitLab" name="sync-to-gitlab-subflow"/>
        
        <!-- Return Success Response -->
        <ee:transform doc:name="Success Response">
            <ee:message>
                <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
    "status": "success",
    "message": "GitHub webhook processed and synced to GitLab successfully",
    "sync_id": "sync-" ++ uuid(),
    "timestamp": now(),
    "source_platform": "github",
    "target_platform": "gitlab",
    "event_type": attributes.headers.'X-GitHub-Event' default "unknown",
    "repository_name": payload.repository.full_name default "unknown",
    "details": {
        "commits_synced": sizeOf(payload.commits default []),
        "branches_synced": if (attributes.headers.'X-GitHub-Event' == "push") 1 else 0,
        "pull_requests_synced": if (attributes.headers.'X-GitHub-Event' contains "pull_request") 1 else 0
    }
}]]></ee:set-payload>
            </ee:message>
        </ee:transform>
        
        <error-handler>
            <on-error-propagate enableNotifications="true" logException="true" doc:name="On Error Propagate" type="VALIDATION:INVALID_SIGNATURE">
                <ee:transform doc:name="Unauthorized Response">
                    <ee:message>
                        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
    "error": "UNAUTHORIZED",
    "message": "Invalid webhook signature",
    "status_code": 401,
    "timestamp": vars.timestamp,
    "correlation_id": vars.correlationId
}]]></ee:set-payload>
                    </ee:message>
                </ee:transform>
                <set-variable value="401" doc:name="Set Status 401" variableName="httpStatus"/>
            </on-error-propagate>
            
            <on-error-propagate enableNotifications="true" logException="true" doc:name="On Error Propagate" type="VALIDATION:INVALID_INPUT_EXCEPTION">
                <ee:transform doc:name="Bad Request Response">
                    <ee:message>
                        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
    "error": "BAD_REQUEST",
    "message": "Invalid GitHub webhook payload",
    "status_code": 400,
    "timestamp": vars.timestamp,
    "correlation_id": vars.correlationId,
    "details": {
        "validation_errors": [error.description]
    }
}]]></ee:set-payload>
                    </ee:message>
                </ee:transform>
                <set-variable value="400" doc:name="Set Status 400" variableName="httpStatus"/>
            </on-error-propagate>
            
            <on-error-propagate enableNotifications="true" logException="true" doc:name="On Error Propagate" type="HTTP:CONNECTIVITY, HTTP:TIMEOUT">
                <ee:transform doc:name="Unprocessable Entity Response">
                    <ee:message>
                        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
    "error": "UNPROCESSABLE_ENTITY",
    "message": "Unable to synchronize data to GitLab",
    "status_code": 422,
    "timestamp": vars.timestamp,
    "correlation_id": vars.correlationId,
    "details": {
        "sync_errors": [
            {
                "field": "gitlab_api_connection",
                "error": error.description
            }
        ]
    }
}]]></ee:set-payload>
                    </ee:message>
                </ee:transform>
                <set-variable value="422" doc:name="Set Status 422" variableName="httpStatus"/>
            </on-error-propagate>
        </error-handler>
    </flow>

    <!-- GitLab Webhook Handler Flow -->
    <flow name="post:\gitlab\webhook:github-gitlab-sync-config">
        <logger level="INFO" doc:name="Log GitLab Webhook Received" 
                message="GitLab webhook received - Event: #[attributes.headers.'X-GitLab-Event' default 'unknown'], Token: #[if (isEmpty(attributes.headers.'X-GitLab-Token')) 'missing' else 'present']"/>
        
        <!-- Authentication Check -->
        <flow-ref doc:name="Validate Authentication" name="validate-authentication-subflow"/>
        
        <!-- Validate GitLab Webhook Token -->
        <flow-ref doc:name="Validate GitLab Token" name="validate-gitlab-token-subflow"/>
        
        <!-- Validate Request Payload -->
        <flow-ref doc:name="Validate GitLab Payload" name="validate-gitlab-payload-subflow"/>
        
        <!-- Process GitLab Event -->
        <flow-ref doc:name="Process GitLab Event" name="process-gitlab-event-subflow"/>
        
        <!-- Sync to GitHub -->
        <flow-ref doc:name="Sync to GitHub" name="sync-to-github-subflow"/>
        
        <!-- Return Success Response -->
        <ee:transform doc:name="Success Response">
            <ee:message>
                <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
    "status": "success",
    "message": "GitLab webhook processed and synced to GitHub successfully",
    "sync_id": "sync-" ++ uuid(),
    "timestamp": now(),
    "source_platform": "gitlab",
    "target_platform": "github",
    "event_type": payload.object_kind default "unknown",
    "repository_name": payload.project.path_with_namespace default "unknown",
    "details": {
        "commits_synced": sizeOf(payload.commits default []),
        "branches_synced": if (payload.object_kind == "push") 1 else 0,
        "pull_requests_synced": if (payload.object_kind == "merge_request") 1 else 0
    }
}]]></ee:set-payload>
            </ee:message>
        </ee:transform>
        
        <error-handler>
            <on-error-propagate enableNotifications="true" logException="true" doc:name="On Error Propagate" type="VALIDATION:INVALID_TOKEN">
                <ee:transform doc:name="Unauthorized Response">
                    <ee:message>
                        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
    "error": "UNAUTHORIZED",
    "message": "Invalid GitLab webhook token",
    "status_code": 401,
    "timestamp": vars.timestamp,
    "correlation_id": vars.correlationId
}]]></ee:set-payload>
                    </ee:message>
                </ee:transform>
                <set-variable value="401" doc:name="Set Status 401" variableName="httpStatus"/>
            </on-error-propagate>
            
            <on-error-propagate enableNotifications="true" logException="true" doc:name="On Error Propagate" type="VALIDATION:INVALID_INPUT_EXCEPTION">
                <ee:transform doc:name="Bad Request Response">
                    <ee:message>
                        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
    "error": "BAD_REQUEST",
    "message": "Invalid GitLab webhook payload",
    "status_code": 400,
    "timestamp": vars.timestamp,
    "correlation_id": vars.correlationId,
    "details": {
        "validation_errors": [error.description]
    }
}]]></ee:set-payload>
                    </ee:message>
                </ee:transform>
                <set-variable value="400" doc:name="Set Status 400" variableName="httpStatus"/>
            </on-error-propagate>
            
            <on-error-propagate enableNotifications="true" logException="true" doc:name="On Error Propagate" type="HTTP:CONNECTIVITY, HTTP:TIMEOUT">
                <ee:transform doc:name="Unprocessable Entity Response">
                    <ee:message>
                        <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
    "error": "UNPROCESSABLE_ENTITY",
    "message": "Unable to synchronize data to GitHub",
    "status_code": 422,
    "timestamp": vars.timestamp,
    "correlation_id": vars.correlationId,
    "details": {
        "sync_errors": [
            {
                "field": "github_api_connection",
                "error": error.description
            }
        ]
    }
}]]></ee:set-payload>
                    </ee:message>
                </ee:transform>
                <set-variable value="422" doc:name="Set Status 422" variableName="httpStatus"/>
            </on-error-propagate>
        </error-handler>
    </flow>

    <!-- Health Check Flow -->
    <flow name="get:\health:github-gitlab-sync-config">
        <logger level="INFO" doc:name="Log Health Check" message="Health check requested"/>
        
        <!-- Check GitHub Connectivity -->
        <try doc:name="Try GitHub Connection">
            <http:request method="GET" 
                         doc:name="GitHub API Health" 
                         config-ref="GitHub_API_Config" 
                         path="/rate_limit"
                         responseTimeout="10000"/>
            <set-variable value="UP" doc:name="GitHub Status UP" variableName="githubStatus"/>
            <error-handler>
                <on-error-continue enableNotifications="true" logException="false" doc:name="On Error Continue">
                    <set-variable value="DOWN" doc:name="GitHub Status DOWN" variableName="githubStatus"/>
                </on-error-continue>
            </error-handler>
        </try>
        
        <!-- Check GitLab Connectivity -->
        <try doc:name="Try GitLab Connection">
            <http:request method="GET" 
                         doc:name="GitLab API Health" 
                         config-ref="GitLab_API_Config" 
                         path="/api/v4/version"
                         responseTimeout="10000"/>
            <set-variable value="UP" doc:name="GitLab Status UP" variableName="gitlabStatus"/>
            <error-handler>
                <on-error-continue enableNotifications="true" logException="false" doc:name="On Error Continue">
                    <set-variable value="DOWN" doc:name="GitLab Status DOWN" variableName="gitlabStatus"/>
                </on-error-continue>
            </error-handler>
        </try>
        
        <!-- Determine Overall Status -->
        <choice doc:name="Determine Overall Status">
            <when expression="#[vars.githubStatus == 'UP' and vars.gitlabStatus == 'UP']">
                <set-variable value="UP" doc:name="Overall Status UP" variableName="overallStatus"/>
            </when>
            <when expression="#[vars.githubStatus == 'DOWN' and vars.gitlabStatus == 'DOWN']">
                <set-variable value="DOWN" doc:name="Overall Status DOWN" variableName="overallStatus"/>
            </when>
            <otherwise>
                <set-variable value="DEGRADED" doc:name="Overall Status DEGRADED" variableName="overallStatus"/>
            </otherwise>
        </choice>
        
        <!-- Build Health Response -->
        <ee:transform doc:name="Health Response">
            <ee:message>
                <ee:set-payload><![CDATA[%dw 2.0
output application/json
---
{
    "status": vars.overallStatus,
    "timestamp": now(),
    "version": "1.0.0",
    "uptime": "Runtime uptime not available in Mule 4",
    "services": {
        "github_connectivity": vars.githubStatus,
        "gitlab_connectivity": vars.gitlabStatus
    }
}]]></ee:set-payload>
            </ee:message>
        </ee:transform>
    </flow>

</mule>


## SubFlows Implementation

```xml

<?xml version="1.0" encoding="UTF-8"?>

<mule xmlns:crypto="http://www.mulesoft.org/schema/mule/crypto"
      xmlns:validation="http://www.mulesoft.org/schema/mule/validation"
      xmlns:json="http://www.mulesoft.org/schema/mule/json"
      xmlns:ee="http://www.mulesoft.org/schema/mule/ee/core"
      xmlns:http="http://www.mulesoft.org/schema/mule/http"
      xmlns="http://www.mulesoft.org/schema/mule/core"
      xmlns:doc="http://www.mulesoft.org/schema/mule/documentation"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="
        http://www.mulesoft.org/schema/mule/core http://www.mulesoft.org/schema/mule/core/current/mule.xsd
        http://www.mulesoft.org/schema/mule/http http://www.mulesoft.org/schema/mule/http/current/mule-http.xsd
        http://www.mulesoft.org/schema/mule/ee/core http://www.mulesoft.org/schema/mule/ee/core/current/mule-ee.xsd
        http://www.mulesoft.org/schema/mule/json http://www.mulesoft.org/schema/mule/json/current/mule-json.xsd
        http://www.mulesoft.org/schema/mule/validation http://www.mulesoft.org/schema/mule/validation/current/mule-validation.xsd
        http://www.mulesoft.org/schema/mule/crypto http://www.mulesoft.org/schema/mule/crypto/current/mule-crypto.xsd">

    <!-- Authentication Validation Subflow -->
    <sub-flow name="validate-authentication-subflow">
        <logger level="DEBUG" doc:name="Log Authentication Check" message="Validating authentication for request"/>
        
        <choice doc:name="Check Auth Type">
            <when expression="#[!isEmpty(attributes.headers.authorization)]">
                <!-- Basic Authentication -->
                <validation:is-true expression="#[attributes.headers.authorization startsWith 'Basic ']" 
                                   doc:name="Validate Basic Auth Format" 
                                   message="Invalid authorization header format"/>
                
                <ee:transform doc:name="Extract Credentials">
                    <ee:message>
                        <ee:set-variable variableName="encodedCredentials"><![CDATA[%dw 2.0
output text/plain
---
attributes.headers.authorization[6 to -1]]]></ee:set-variable>
                    </ee:message>
                </ee:transform>
                
                <ee:transform doc:name="Decode Credentials">
                    <ee:message>
                        <ee:set-variable variableName="credentials"><![CDATA[%dw 2.0
import * from dw::core::Binaries
output application/java
---
fromBase64(vars.encodedCredentials) as String]]></ee:set-variable>
                    </ee:message>
                </ee:transform>
                
                <validation:is-true expression="#[vars.credentials contains ':']" 
                                   doc:name="Validate Credentials Format" 
                                   message="Invalid credentials format"/>
                
                <ee:transform doc:name="Parse Username/Password">
                    <ee:message>
                        <ee:set-variable variableName="username"><![CDATA[%dw 2.0
output text/plain
---
(vars.credentials splitBy ":")[0]]]></ee:set-variable>
                        <ee:set-variable variableName="password"><![CDATA[%dw 2.0
output text/plain
---
(vars.credentials splitBy ":")[1]]]></ee:set-variable>
                    </ee:message>
                </ee:transform>
                
                <validation:is-true expression="#[vars.username == p('secure::api.username') and vars.password == p('secure::api.password')]" 
                                   doc:name="Validate Credentials" 
                                   message="Invalid username or password"/>
            </when>
            <otherwise>
                <raise-error doc:name="Auth Required" 
                            description="Authentication required" 
                            type="VALIDATION:UNAUTHORIZED"/>
            </otherwise>
        </choice>
        
        <logger level="DEBUG" doc:name="Auth Success" message="Authentication successful"/>
    </sub-flow>

    <!-- GitHub Signature Validation Subflow -->
    <sub-flow name="validate-github-signature-subflow">
        <logger level="DEBUG" doc:name="Log Signature Validation" message="Validating GitHub webhook signature"/>
        
        <choice doc:name="Check Signature Header">
            <when expression="#[!isEmpty(attributes.headers.'X-Hub-Signature-256')]">
                <set-variable value="#[attributes.headers.'X-Hub-Signature-256']" 
                             doc:name="Set Signature" 
                             variableName="receivedSignature"/>
                
                <validation:is-true expression="#[vars.receivedSignature startsWith 'sha256=']" 
                                   doc:name="Validate Signature Format" 
                                   message="Invalid signature format"/>
                
                <ee:transform doc:name="Get Raw Payload">
                    <ee:message>
                        <ee:set-variable variableName="rawPayload"><![CDATA[%dw 2.0
output text/plain
---
payload]]></ee:set-variable>
                    </ee:message>
                </ee:transform>
                
                <crypto:hmac-binary config-ref="HMAC_Config" 
                                  doc:name="Calculate HMAC" 
                                  algorithm="HmacSHA256" 
                                  key="${secure::github.webhook.secret}">
                    <crypto:content>#[vars.rawPayload]</crypto:content>
                </crypto:hmac-binary>
                
                <ee:transform doc:name="Create Expected Signature">
                    <ee:message>
                        <ee:set-variable variableName="expectedSignature"><![CDATA[%dw 2.0
import * from dw::core::Binaries
output text/plain
---
"sha256=" ++ toHex(payload)]]></ee:set-variable>
                    </ee:message>
                </ee:transform>
                
                <validation:is-true expression="#[vars.receivedSignature == vars.expectedSignature]" 
                                   doc:name="Validate Signature" 
                                   message="Invalid webhook signature"/>
            </when>
            <otherwise>
                <logger level="WARN" doc:name="No Signature Warning" 
                        message="GitHub webhook signature not provided - proceeding without validation"/>
            </otherwise>
        </choice>
        
        <logger level="DEBUG" doc:name="Signature Valid" message="GitHub signature validation successful"/>
    </sub-flow>

    <!-- GitLab Token Validation Subflow -->
    <sub-flow name="validate-gitlab-token-subflow">
        <logger level="DEBUG" doc:name="Log Token Validation" message="Validating GitLab webhook token"/>
        
        <choice doc:name="Check Token Header">
            <when expression="#[!isEmpty(attributes.headers.'X-GitLab-Token')]">
                <validation:is-true expression="#[attributes.headers.'X-GitLab-Token' == p('secure::gitlab.webhook.token')]" 
                                   doc:name="Validate Token" 
                                   message="Invalid GitLab webhook token"/>
            </when>
            <otherwise>
                <logger level="WARN" doc:name="No Token Warning" 
                        message="GitLab webhook token not provided - proceeding without validation"/>
            </otherwise>
        </choice>
        
        <logger level="DEBUG" doc:name="Token Valid" message="GitLab token validation successful"/>
    </sub-flow>

    <!-- GitHub Payload Validation Subflow -->
    <sub-flow name="validate-github-payload-subflow">
        <logger level="DEBUG" doc:name="Log Payload Validation" message="Validating GitHub webhook payload"/>
        
        <validation:is-not-null value="#[payload]" 
                               doc:name="Validate Payload Not Null" 
                               message="Payload cannot be null"/>
        
        <validation:is-not-null value="#[payload.repository]" 
                               doc:name="Validate Repository" 
                               message="Repository information is required"/>
        
        <validation:is-not-null value="#[payload.sender]" 
                               doc:name="Validate Sender" 
                               message="Sender information is required"/>
        
        <choice doc:name="Validate Event Type">
            <when expression="#[attributes.headers.'X-GitHub-Event' == 'push']">
                <validation:is-not-null value="#[payload.ref]" 
                                       doc:name="Validate Push Ref" 
                                       message="Push events require ref information"/>
            </when>
            <when expression="#[attributes.headers.'X-GitHub-Event' contains 'pull_request']">
                <validation:is-not-null value="#[payload.pull_request]" 
                                       doc:name="Validate Pull Request" 
                                       message="Pull request events require pull_request object"/>
            </when>
            <otherwise>
                <logger level="DEBUG" doc:name="Other Event Type" 
                        message="Processing event type: #[attributes.headers.'X-GitHub-Event']"/>
            </otherwise>
        </choice>
        
        <logger level="DEBUG" doc:name="Payload Valid" message="GitHub payload validation successful"/>
    </sub-flow>

    <!-- GitLab Payload Validation Subflow -->
    <sub-flow name="validate-gitlab-payload-subflow">
        <logger level="DEBUG" doc:name="Log Payload Validation" message="Validating GitLab webhook payload"/>
        
        <validation:is-not-null value="#[payload]" 
                               doc:name="Validate Payload Not Null" 
                               message="Payload cannot be null"/>
        
        <validation:is-not-null value="#[payload.project]" 
                               doc:name="Validate Project" 
                               message="Project information is required"/>
        
        <validation:is-not-null value="#[payload.user]" 
                               doc:name="Validate User" 
                               message="User information is required"/>
        
        <validation:is-not-null value="#[payload.object_kind]" 
                               doc:name="Validate Object Kind" 
                               message="Object kind is required"/>
        
        <choice doc:name="Validate Event Type">
            <when expression="#[payload.object_kind == 'push']">
                <validation:is-not-null value="#[payload.ref]" 
                                       doc:name="Validate Push Ref" 
                                       message="Push events require ref information"/>
            </when>
            <when expression="#[payload.object_kind == 'merge_request']">
                <validation:is-not-null value="#[payload.object_attributes]" 
                                       doc:name="Validate Merge Request" 
                                       message="Merge request events require object