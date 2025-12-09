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

type Provider record {|
    string organization?;
    string url?;
|};

enum TransportType {
    HTTP_SSE = "http_sse",
    STDIO = "stdio",
    STREAMABLE_HTTP = "streamable_http"
}

type HttpTransport record {|
    HTTP_SSE|STREAMABLE_HTTP 'type;
    string url;
|};

type StdIoTransport record {|
    STDIO 'type;
    string command;
|};

type Transport HttpTransport|StdIoTransport;

type ClientAuthentication record {
    string 'type;
};

type ToolFilter record {|
    string[] allow?;
    string[] deny?;
|};

type MCPServer record {|
    string name;
    Transport transport;
    ClientAuthentication authentication?;
    ToolFilter tool_filter?;
|};

type MCPConnections record {|
    MCPServer[] servers;
|};

type A2APeer record {|
    string name;
    string endpoint;
|};

type A2AConnections record {|
    A2APeer[] peers?;
|};

type Tools record {|
    MCPConnections mcp?;
|};


type Parameter record {| 
    string name;
    string 'type;
    string description?;
    boolean required?;
|};

type JSONSchema record {| 
    string 'type;
    // For object type
    map<JSONSchema>? properties?;
    string[]? required?;
    // For array type
    JSONSchema? items?;
    // For string/number/boolean types, can add more fields as needed
    string? description?;
    // // Allow additional fields for extensibility
    // map<json>? additionalProperties?;
|};

type Signature record {| 
    JSONSchema input = { 'type: "string" };
    JSONSchema output = { 'type: "string" };
|};

type HTTPExposure record {|
    string path;
    // ClientAuthentication authentication?;
|};

type AgentCard record {|
    string name?;
    string description?;
    string icon?;
|};

type A2AExposure record {|
    boolean discoverable?;
    AgentCard agent_card?;
|};

type Exposure record {|
    HTTPExposure http?;
    A2AExposure a2a?;
|};

enum InterfaceType {
    SERVICE = "service",
    FUNCTION = "function",
    CHAT = "chat",
    WEBHOOK = "webhook"
}

type Subscription record {|
    string protocol;
    string hub;
    string topic;
    string callback?;
    string secret?;
    ClientAuthentication authentication?;
|};

type ServiceInterface record {|
    SERVICE 'type = SERVICE;
    Signature signature = {};
    Exposure exposure;
|};

type FunctionInterface record {|
    FUNCTION 'type = FUNCTION;
    Signature signature = {};
|};

type ChatInterface record {|
    CHAT 'type = CHAT;
    Signature signature = {};
    Exposure exposure;
|};

type WebhookInterface record {|
    WEBHOOK 'type = WEBHOOK;
    Signature signature = {};
    Exposure exposure;
    Subscription subscription;
|};

type Interface ServiceInterface|FunctionInterface|ChatInterface|WebhookInterface;

type AgentMetadata record {|
    string spec_version?;
    string name?;
    string description?;
    string 'version?;
    string namespace?;
    string author?;
    string[] authors?;
    string iconUrl?;
    Provider provider?;
    string license?;
    Interface interface = <FunctionInterface>{};
    Tools tools?;
    int max_iterations?;
|};

type AFMRecord record {|
    AgentMetadata metadata;
    string role;
    string instructions;
|};
