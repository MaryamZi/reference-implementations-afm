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

public function main(string filePath) returns error? {
    log:printInfo(string `Starting AFM agent from file: ${filePath}`);

    string content = check io:fileReadString(filePath);

    AFMRecord afm = check parseAfm(content);

    AgentMetadata metadata = afm.metadata;

    Interface[] agentInterfaces = metadata.interfaces ?: [<ConsoleChatInterface>{}];

    var [consoleChatInterface, webChatInterface, webhookInterface] = 
                        check validateAndExtractInterfaces(agentInterfaces);

    // Create a single shared agent instance for all interfaces
    ai:Agent agent = check createAgent(afm);

    // Start all service-based interfaces first (non-blocking)
    http:Listener? httpListener = ();
    websub:Listener? websubListener = ();

    if webChatInterface is WebChatInterface {
        HTTPExposure httpExposure = webChatInterface.exposure.http ?: {path: "/chat"};

        http:Listener ln = check new (port);
        httpListener = ln;
        check attachChatService(ln, agent, webChatInterface, httpExposure);
        log:printInfo(string `Attached webchat interface at path: ${httpExposure.path}`);
    }

    if webhookInterface is WebhookInterface {
        HTTPExposure httpExposure = webhookInterface.exposure.http ?: {path: "/webhook"};

        websub:Listener ln = check new websub:Listener(
            httpListener is () ? port : httpListener);
        websubListener = ln;
        check attachWebhookService(ln, agent, webhookInterface, httpExposure);
        log:printInfo(string `Attached webhook interface at path: ${httpExposure.path}`);
    }

    if websubListener is websub:Listener {
        check websubListener.start();
        runtime:registerListener(websubListener);
        log:printInfo(string `WebSub server started on port ${port}`);
    } if httpListener is http:Listener {
        check httpListener.start();
        runtime:registerListener(httpListener);
        log:printInfo(string `HTTP server started on port ${port}`);
    }

    // Run consolechat last (it's blocking/interactive)
    if consoleChatInterface is ConsoleChatInterface {
        log:printInfo("Starting interactive consolechat interface");
        return runInteractiveChat(agent);
    }
}

function validateAndExtractInterfaces(Interface[] interfaces) 
        returns [ConsoleChatInterface?, WebChatInterface?, WebhookInterface?]|error {
    int consoleChatCount = 0;
    int webChatCount = 0;
    int webhookCount = 0;

    ConsoleChatInterface? consoleChatInterface = ();
    WebChatInterface? webChatInterface = ();
    WebhookInterface? webhookInterface = ();

    foreach Interface interface in interfaces {
        if interface is ConsoleChatInterface {
            consoleChatCount += 1;
            consoleChatInterface = interface;
        } else if interface is WebChatInterface {
            webChatCount += 1;
            webChatInterface = interface;
        } else {
            webhookCount += 1;
            webhookInterface = interface;
        }
    }

    if consoleChatCount > 1 || webChatCount > 1 || webhookCount > 1 {
        return error("Multiple interfaces of the same type are not supported");
    }

    return [consoleChatInterface, webChatInterface, webhookInterface];
}

function attachChatService(http:Listener httpListener, ai:Agent agent, WebChatInterface webChatInterface, HTTPExposure httpExposure) returns error? {
    http:Service httpService = check new HttpService(agent, webChatInterface);
    return httpListener.attach(httpService, httpExposure.path);
}

function attachWebhookService(websub:Listener websubListener, ai:Agent agent, WebhookInterface webhookInterface, HTTPExposure httpExposure) returns error? {
    Subscription subscription = webhookInterface.subscription;
    log:printInfo(string `Webhook subscription configured: ${subscription.protocol} protocol`);

    // Doesn't work due to a bug.
    // Subscription {hub, topic, callback, secret, authentication} = subscription;

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

    check websubListener.attach(webhookService, httpExposure.path);
}

type AgentWithSchema record {|
    readonly map<json> inputSchema;
    readonly map<json> outputSchema;
    ai:Agent agent;
|};

function runInteractiveChat(ai:Agent agent) returns error? {
    printWelcomeBanner();

    int messageCount = 0;
    while true {
        // Read user input with enhanced prompt
        io:print("\n> ");
        string userInput = io:readln();

        // Check for special commands
        string trimmedInput = userInput.trim();
        if trimmedInput == "" {
            continue;
        }

        // Handle special commands
        if trimmedInput.toLowerAscii() == "exit" || trimmedInput.toLowerAscii() == "quit" {
            printGoodbyeMessage(messageCount);
            break;
        }

        if trimmedInput.toLowerAscii() == "help" || trimmedInput == "?" {
            printHelpMessage();
            continue;
        }

        if trimmedInput.toLowerAscii() == "clear" || trimmedInput.toLowerAscii() == "cls" {
            clearScreen();
            printWelcomeBanner();
            continue;
        }

        // Show thinking indicator
        io:print("[Thinking...]");

        // Run the agent
        string|ai:Error response = agent.run(userInput);

        // Clear the thinking indicator line
        io:print("\r             \r");

        if response is ai:Error {
            io:println(string `[ERROR] ${response.message()}`);
            continue;
        }

        // Print agent response with formatting
        io:println(string `Agent: ${response}`);
        messageCount += 1;
    }
}

function printWelcomeBanner() {
    io:println("╔════════════════════════════════════════╗");
    io:println("║     Interactive Console Chat           ║");
    io:println("╚════════════════════════════════════════╝");
    io:println("Type 'help' for commands, 'exit' to quit\n");
}

function printHelpMessage() {
    io:println("\nAvailable Commands:");
    io:println("  help, ?       - Show this help message");
    io:println("  clear, cls    - Clear the screen");
    io:println("  exit, quit    - Exit the chat");
    io:println("\nJust type your message to chat with the agent.");
}

function printGoodbyeMessage(int messageCount) {
    io:println("\n👋 Goodbye!");
    if messageCount > 0 {
        io:println(string `You exchanged ${messageCount} message${messageCount == 1 ? "" : "s"} in this session.`);
    }
}

function clearScreen() {
    // Print multiple newlines to simulate clearing
    foreach int i in 0...50 {
        io:println("");
    }
}

service class HttpService {
    *http:Service;

    private final readonly & map<json> inputSchema;
    private final readonly & map<json> outputSchema;
    private final ai:Agent agent;

    function init(ai:Agent agent, WebChatInterface webChatInterface) returns error? {
        self.inputSchema = webChatInterface.signature.input.cloneReadOnly();
        self.outputSchema = webChatInterface.signature.output.cloneReadOnly();
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
    MCPServer[]? mcpServers = metadata?.tools?.mcp;
    if mcpServers is MCPServer[] {
        foreach MCPServer mcpConn in mcpServers {
            Transport transport = mcpConn.transport;
            if transport.'type != "http" {
                log:printWarn(string `Unsupported transport type: ${transport.'type}, only 'http' is supported`);
                continue;
            }

            string[]? filteredTools = getFilteredTools(mcpConn.tool_filter);
            mcpToolkits.push(check new ai:McpToolKit(
                transport.url,
                permittedTools = filteredTools,
                auth = check mapToHttpClientAuth(transport.authentication)
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
            accessToken)
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

function runAgent(ai:Agent agent, json payload, map<json>? inputSchema = (), map<json>? outputSchema = ()) 
        returns json|InputError|AgentError {
    error? validateJsonSchemaResult = validateJsonSchema(inputSchema, payload);
    if validateJsonSchemaResult is error {
        log:printError("Invalid input payload", 'error = validateJsonSchemaResult);
        return error InputError("Invalid input payload");
    }

    boolean isUpdatedSchema = false;
    map<json>? effectiveOutputSchema = outputSchema;

    if outputSchema is map<json> {
        string|error schemaType = outputSchema["type"].ensureType();
        if schemaType is error {
            log:printError("Invalid output schema", 'error = schemaType);
            return error AgentError("Invalid output schema, expected a 'type' field", schemaType);
        }

        if schemaType !is "object"|"array" {
            effectiveOutputSchema = {
                "type": "object",
                "properties": { "value": { "type": schemaType } },
                "required": ["value"]
            };
            isUpdatedSchema = true;
        }
    }
    string|ai:Error run = agent.run(
        string `${payload.toJsonString()}
        
        ${effectiveOutputSchema is map<json> ? 
        string `The final response MUST conform to the following JSON schema: ${
            effectiveOutputSchema.toJsonString()}` : ""}

        Respond only with the value enclosed between ${"```json"} and ${"```"}.
        `);

    if run is ai:Error {
        log:printError("Agent run failed", 'error = run);
        return error AgentError("Agent run failed", run);
    }

    string responseJsonStr = run;
    
    int? lastJsonStart = run.lastIndexOf("```json");
    int? lastJsonEnd = run.lastIndexOf("```");
    if lastJsonStart is int && lastJsonEnd is int && lastJsonEnd > lastJsonStart {
        responseJsonStr = run.substring(lastJsonStart + 7, lastJsonEnd).trim();
    }

    json|error responseJson = responseJsonStr.fromJsonString();

    if responseJson is error {
        log:printError("Failed to parse agent response JSON", 'error = responseJson);
        return error AgentError("Failed to parse agent response JSON");
    }

    error? validateOutputSchemaResult = validateJsonSchema(effectiveOutputSchema, responseJson);
    if validateOutputSchemaResult is error {
        log:printError("Agent response does not conform to output schema", 'error = validateOutputSchemaResult);
        return error AgentError("Agent response does not conform to output schema", validateOutputSchemaResult);
    }
    return isUpdatedSchema ? (<map<json>> responseJson).get("value") : responseJson;
}

isolated function validateJsonSchema(map<json>? jsonSchemaVal, json sampleJson) returns error? {
    if jsonSchemaVal is () {
        return ();
    }

    string schemaType = check jsonSchemaVal["type"].ensureType();
    if schemaType == "object" {
        validator:JSONObject schemaObject = validator:newJSONObject7(jsonSchemaVal.toJsonString());
        validator:SchemaLoaderBuilder builder = validator:newSchemaLoaderBuilder1();
        validator:SchemaLoader schemaLoader = builder.schemaJson(schemaObject).build();
        validator:Schema schema = schemaLoader.load().build();
        validator:JSONObject jsonObject = validator:newJSONObject7(sampleJson.toJsonString());
        error? validationResult = trap schema.validate(jsonObject);
        if validationResult is error {
            return error("JSON validation failed: " + validationResult.message());
        }
        return (); 
    }

    // Wrap value and validate using generated object schema
    map<json> valueSchema = {
        "type": "object",
        "properties": { "value": { "type": schemaType } },
        "required": ["value"]
    };
    validator:JSONObject schemaObject = validator:newJSONObject7(valueSchema.toJsonString());
    validator:SchemaLoaderBuilder builder = validator:newSchemaLoaderBuilder1();
    validator:SchemaLoader schemaLoader = builder.schemaJson(schemaObject).build();
    validator:Schema schema = schemaLoader.load().build();
    map<json> wrapped = { "value": sampleJson };
    validator:JSONObject jsonObject = validator:newJSONObject7(wrapped.toJsonString());
    error? validationResult = trap schema.validate(jsonObject);
    if validationResult is error {
        return error("JSON validation failed: " + validationResult.message());
    }
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
