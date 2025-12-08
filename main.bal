// Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

import afm_ballerina.everit.validator;

import ballerina/ai;
import ballerina/data.yaml;
import ballerina/http;
import ballerina/io;
import ballerina/log;
import ballerina/lang.runtime;
import ballerina/os;
import ballerina/websub;

configurable int port = 8085;

const FRONTMATTER_DELIMITER = "---";

type InputError distinct error;
type AgentError distinct error;

public function main(string filePath, string? input = ()) returns error? {
    log:printInfo(string `Starting AFM agent from file: ${filePath}`);

    string content = check io:fileReadString(filePath);

    AFMRecord afm = check parseAfm(content);

    AgentMetadata metadata = afm.metadata;

    Interface interface = metadata.interface;

    if interface is FunctionInterface {
        if input is () {
            return error("Input must be provided when running an AFM function interface");
        }
        return createAndRunAgentAsFunction(afm, input);
    }

    Exposure exposure = interface.exposure;

    if exposure.a2a is A2AExposure {
        log:printWarn("A2A exposure configured but not yet supported; continuing with HTTP/Webhook exposure only");
    }

    HTTPExposure? httpExposure = exposure.http;
    if httpExposure is () {
        return error(string `No HTTP exposure defined for ${interface.'type} agent`);
    }

    if interface is ChatInterface|ServiceInterface {
        return createAndExposeAgentAsService(interface, afm, httpExposure);
    }

    return createAndExposeAgentAsWebhook(interface, afm, httpExposure);
}

function createAndExposeAgentAsService(ChatInterface|ServiceInterface interface, AFMRecord afm, HTTPExposure httpExposure) returns error? {
    http:Listener ln = check new (port);
    http:Service httpService = check new HttpService(afm);
    check ln.attach(httpService, httpExposure.path);
    check ln.start();
    runtime:registerListener(ln);
    log:printInfo(string `HTTP ${interface.'type} agent started at path: ${httpExposure.path}`);    
}

function createAndExposeAgentAsWebhook(WebhookInterface interface, AFMRecord afm, HTTPExposure httpExposure) returns error? {
    Subscription subscription = interface.subscription;
    log:printInfo(string `Webhook subscription configured: ${subscription.protocol} protocol`);
    
    // Doesn't work due to a bug.
    // Subscription {hub, topic, callback, secret, authentication} = subscription;

    final ai:Agent agent = check createAgent(afm); 
    
    // Can't specify inline due to a bug.
    http:ClientAuthConfig? auth = check mapToHttpClientAuth(subscription.authentication);

    websub:SubscriberService webhookService = 
        @websub:SubscriberServiceConfig {
            target: [subscription.hub, subscription.topic],
            secret: subscription.secret,
            httpConfig: {
                auth
            },
            callback: subscription.callback
        }
        isolated service object {
            remote function onEventNotification(readonly & websub:ContentDistributionMessage msg) 
                    returns websub:Acknowledgement|error {
                // TODO: revisit the result handling
                json result = check runAgent(agent, msg.content.toJson());
                log:printInfo("Webhook payload handled: " + result.toJsonString());
                return websub:ACKNOWLEDGEMENT;
            }
        };

    websub:Listener ln = check new (port);
    check ln.attach(webhookService, httpExposure.path);
    check ln.start();
    runtime:registerListener(ln);
    log:printInfo(string `Webhook listener started at path: ${httpExposure.path}`);
}

type AgentWithSchema record {|
    readonly map<json> inputSchema;
    readonly map<json> outputSchema;
    ai:Agent agent;
|};

function createAndRunAgentAsFunction(AFMRecord afmRecord, string input) returns error? {
    AgentWithSchema {inputSchema, outputSchema, agent} = check createAgentWithSchema(afmRecord);
    // TODO: Ignore result?
    json result = check runAgent(agent, check input.fromJsonString(), inputSchema, outputSchema);
    io:println(result);
}

service class HttpService {
    *http:Service;

    private final readonly & map<json> inputSchema;
    private final readonly & map<json> outputSchema;
    private final ai:Agent agent;

    function init(AFMRecord afmRecord) returns error? {
        AgentWithSchema {inputSchema, outputSchema, agent} = check createAgentWithSchema(afmRecord);
        self.inputSchema = inputSchema;
        self.outputSchema = outputSchema;
        self.agent = agent;
    }

    resource function post .(@http:Payload json payload) returns json|http:BadRequest|http:InternalServerError {
        json|InputError|AgentError runAgentResult = runAgent(self.agent, payload, self.inputSchema, self.outputSchema);
        if runAgentResult is json {
            return runAgentResult;
        }

        if runAgentResult is InputError {
            return <http:BadRequest> {body: runAgentResult.message()};
        }
        return <http:InternalServerError> {body: runAgentResult.message()};
    }
}

function resolveVariables(string content) returns string {
    string result = content;
    
    // Simple iterative approach to find and replace ${VAR} patterns
    int startPos = 0;
    while true {
        int? dollarPos = result.indexOf("${", startPos);
        if dollarPos is () {
            break;
        }
        
        int? closeBracePos = result.indexOf("}", dollarPos);
        if closeBracePos is () {
            break;
        }
        
        // Extract variable name
        string varName = result.substring(dollarPos + 2, closeBracePos);
        
        // Try to resolve from environment
        string? envValue = os:getEnv(varName);
        if envValue is string {
            // Replace the variable with its value
            string before = result.substring(0, dollarPos);
            string after = result.substring(closeBracePos + 1);
            result = before + envValue + after;
            startPos = before.length() + envValue.length();
        } else {
            log:printError(string `Variable ${varName} not found in environment`);
            startPos = closeBracePos + 1;
        }
    }
    
    return result;
}

function parseAfm(string content) returns AFMRecord|error {
    // Resolve variables first
    string resolvedContent = resolveVariables(content);
    
    string[] lines = splitLines(resolvedContent);
    int length = lines.length();
    
    AgentMetadata? metadata = ();
    int bodyStart = 0;
    
    // Extract and parse YAML frontmatter
    if length > 0 && lines[0].trim() == FRONTMATTER_DELIMITER {
        int i = 1;
        while i < length && lines[i].trim() != FRONTMATTER_DELIMITER {
            i += 1;
        }
        
        if i < length {
            string[] fmLines = [];
            foreach int j in 1 ..< i {
                fmLines.push(lines[j]);
            }
            string yamlContent = string:'join("\n", ...fmLines);
            map<json> intermediate = check yaml:parseString(yamlContent);
            metadata = check intermediate.fromJsonWithType();
            bodyStart = i + 1;
        }
    }
    
    // Extract Role and Instructions sections
    string role = "";
    string instructions = "";
    boolean inRole = false;
    boolean inInstructions = false;
    
    foreach int k in bodyStart ..< length {
        string line = lines[k];
        string trimmed = line.trim();
        
        if trimmed.startsWith("# ") {
            string heading = trimmed.substring(2).toLowerAscii();
            inRole = heading.startsWith("role");
            inInstructions = heading.startsWith("instructions");
            continue;
        }
        
        if inRole {
            role = role == "" ? line : role + "\n" + line;
        } else if inInstructions {
            instructions = instructions == "" ? line : instructions + "\n" + line;
        }
    }
    
    return {
        metadata: check metadata.ensureType(),
        role: role.trim(),
        instructions: instructions.trim()
    };
}

function splitLines(string content) returns string[] {
    string[] result = [];
    string remaining = content;
    
    while true {
        int? idx = remaining.indexOf("\n");
        if idx is int {
            result.push(remaining.substring(0, idx));
            remaining = remaining.substring(idx + 1);
        } else {
            if remaining.length() > 0 {
                result.push(remaining);
            }
            break;
        }
    }
    
    return result;
}

function getFilteredTools(ToolFilter? toolFilter) returns string[]? {
    if toolFilter is () {
        return (); // No filtering - all tools allowed
    }
    
    string[]? allow = toolFilter.allow;
    string[]? deny = toolFilter.deny;
    
    // If no filters specified, return null (all tools)
    if allow is () && deny is () {
        return ();
    }
    
    // If only allow is specified, return it
    if allow is string[] && deny is () {
        return allow;
    }
    
    // If only deny is specified, we can't handle it with current API
    // (would need to fetch all tools first, then filter)
    if allow is () && deny is string[] {
        log:printWarn("Deny-only tool filter not fully supported - ignoring deny list");
        return (); // Return all for now
    }
    
    // If both specified: apply allow first, then remove denied tools
    if allow is string[] && deny is string[] {
        string[] filtered = [];
        foreach string tool in allow {
            boolean isDenied = false;
            foreach string deniedTool in deny {
                if tool == deniedTool {
                    isDenied = true;
                    break;
                }
            }
            if !isDenied {
                filtered.push(tool);
            }
        }
        return filtered;
    }
    
    return ();
}

function createAgent(AFMRecord afmRecord) returns ai:Agent|error {
    AFMRecord {metadata, role, instructions} = afmRecord;

    ai:McpToolKit[] mcpToolkits = [];
    MCPConnections? mcpConnections = metadata?.tools?.mcp;
    if mcpConnections is MCPConnections {
        foreach MCPServer mcpConn in mcpConnections.servers {
            Transport transport = mcpConn.transport;
            if transport !is HttpTransport || (transport.'type != STREAMABLE_HTTP && transport.'type != HTTP_SSE) {
                log:printWarn("Only streamable_http and http_sse transports are supported for MCP connections");
                continue;
            }
            
            string[]? filteredTools = getFilteredTools(mcpConn.tool_filter);
            mcpToolkits.push(check new ai:McpToolKit(
                transport.url,
                permittedTools = filteredTools,
                auth = check mapToHttpClientAuth(mcpConn.authentication)
            ));
        }
    }

    string? accessToken = os:getEnv("WSO2_MODEL_PROVIDER_TOKEN");
    if accessToken is () {
        return error("Environment variable WSO2_MODEL_PROVIDER_TOKEN must be set for Wso2ModelProvider");
    }
    
    ai:AgentConfiguration agentConfig = {
        systemPrompt: {
            role, 
            instructions
        },
        tools: mcpToolkits,
        model: check new ai:Wso2ModelProvider(
            "https://dev-tools.wso2.com/ballerina-copilot/v2.0",
            accessToken),
        verbose: true
    };
    
    int? maxIterations = metadata?.max_iterations;
    if maxIterations is int {
        agentConfig.maxIter = maxIterations;
    }
    
    ai:Agent|ai:Error agent = new (agentConfig);
    if agent is ai:Error {
        return error("Failed to create agent", agent);
    }
    return agent;
}

function createAgentWithSchema(AFMRecord afmRecord) returns AgentWithSchema|error {
    AgentMetadata metadata = afmRecord.metadata;

    ai:Agent agent = check createAgent(afmRecord);

    Signature signature = check metadata?.interface?.signature.ensureType();
    map<json> & readonly inputSchema = transformToJsonObjectSchema(signature.input);
    map<json> & readonly outputSchema = transformToJsonObjectSchema(signature.output);

    return {inputSchema, outputSchema, agent};
}

function transformToJsonObjectSchema(Parameter[] params) returns map<json> & readonly {
    map<json> properties = {};
    string[] requiredFields = [];
    
    foreach Parameter param in params {
        map<json> paramSchema = {};
        paramSchema["type"] = param.'type;
        if param.description is string {
            paramSchema["description"] = param.description;
        }
        string paramName = param.name;
        properties[paramName] = paramSchema;
        
        boolean isRequired = let boolean? required = param.required in
            required is boolean ? required : false;
        if isRequired {
            requiredFields.push(paramName);
        }
    }
    
    map<json> schema = {
        "type": "object",
        "properties": properties.cloneReadOnly()
    };
    
    if requiredFields.length() > 0 {
        schema["required"] = requiredFields.cloneReadOnly();
    }
    
    return schema.cloneReadOnly();
}

function runAgent(ai:Agent agent, json payload, map<json>? inputSchema = (), map<json>? outputSchema = ()) 
        returns json|InputError|AgentError {
    error? validateJsonSchemaResult = validateJsonSchema(inputSchema, payload);
    if validateJsonSchemaResult is error {
        log:printError("Invalid input payload", 'error = validateJsonSchemaResult);
        return error InputError("Invalid input payload");
    }
    
    string|ai:Error run = agent.run(
        string `${payload.toJsonString()}
        
        ${inputSchema is map<json> ? 
        string `The final response MUST conform to the following JSON schema: ${
            outputSchema.toJsonString()}` : ""}

        Respond only with the value enclosed between ${"```json"} and ${"```"}.
        `);

    if run is ai:Error {
        log:printError("Agent run failed", 'error = run);
        return error AgentError("Agent run failed", run);
    }

    string responseJsonStr = run;
    if run.startsWith("```json") && run.endsWith("```") {
        responseJsonStr = run.substring(7, run.length() - 3);
    }

    json|error responseJson = responseJsonStr.fromJsonString();

    if responseJson is error {
        log:printError("Failed to parse agent response JSON", 'error = responseJson);
        return error AgentError("Failed to parse agent response JSON");
    }

    error? validateOutputSchemaResult = validateJsonSchema(outputSchema, responseJson);
    if validateOutputSchemaResult is error {
        log:printError("Agent response does not conform to output schema", 'error = validateOutputSchemaResult);
        return error AgentError("Agent response does not conform to output schema", validateOutputSchemaResult);
    }
    return responseJson;
}

isolated function validateJsonSchema(map<json>? jsonSchemaVal, json sampleJson) returns error? {
    if jsonSchemaVal is () {
        return ();
    }

    // Create JSONObject from schema
    validator:JSONObject schemaObject = validator:newJSONObject7(jsonSchemaVal.toJsonString());
    
    // Build the schema using SchemaLoader
    validator:SchemaLoaderBuilder builder = validator:newSchemaLoaderBuilder1();
    validator:SchemaLoader schemaLoader = builder.schemaJson(schemaObject).build();
    validator:Schema schema = schemaLoader.load().build();
    
    // Create JSONObject from the JSON to validate
    validator:JSONObject jsonObject = validator:newJSONObject7(sampleJson.toJsonString());
    
    // Validate - throws ValidationException if invalid
    error? validationResult = trap schema.validate(jsonObject);
    
    if validationResult is error {
        return error("JSON validation failed: " + validationResult.message());
    }
    
    return ();
}

function mapToHttpClientAuth(ClientAuthentication? auth) returns http:ClientAuthConfig|error? {
    if auth is () {
        return ();
    }
    
    ClientAuthentication {'type, ...rest} = auth;

    'type = 'type.toLowerAscii();
    
    match 'type {
        "basic" => {
            return rest.cloneWithType(http:CredentialsConfig);
        }
        "bearer" => {
            return rest.cloneWithType(http:BearerTokenConfig);
        }
        "oauth2" => {
            // record {string grantType;}|error oauth2Config = check rest.cloneWithType();
            // if oauth2Config is error {
            //     return error("OAuth2 authentication requires 'grantType' field", oauth2Config);
            // }
            
            // var {grantType, ...oauth2ConfigRest} = oauth2Config;

            // match grantType.toLowerAscii() {
            //     "client_credentials" => {
            //         return oauth2ConfigRest.cloneWithType(http:OAuth2ClientCredentialsGrantConfig);
            //     }
            //     "password" => {
            //         return oauth2ConfigRest.cloneWithType(http:OAuth2PasswordGrantConfig);
            //     }
            //     "refresh_token" => {
            //         return oauth2ConfigRest.cloneWithType(http:OAuth2RefreshTokenGrantConfig);
            //     }
            //     "jwt" => {
            //         return oauth2Config.cloneWithType(http:OAuth2JwtBearerGrantConfig);
            //     }
            // }
            // panic error(string `Unsupported OAuth2 grant type: ${grantType}`);
            return error("OAuth2 authentication not yet supported");
        }
        "jwt" => {
            // return rest.cloneWithType(http:JwtIssuerConfig);
            return error("JWT authentication not yet supported");
        }
        _ => {
            return error(string `Unsupported authentication type: ${'type}`);
        }
    }
}
