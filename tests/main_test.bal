import ballerina/io;
import ballerina/test;

@test:Config {}
function testParseAfm() returns error? {
    string afmContent = check io:fileReadString("tests/sample_agent.afm.md");
    AFMRecord parsed = check parseAfm(afmContent);
    AFMRecord expected = {
        metadata: {
            spec_version: "0.3.0",
            name: "TestAgent",
            description: "A test agent for AFM parsing.",
            authors: ["Maryam", "Copilot"],
            version: "0.1.0",
            icon_url: "https://example.com/icon.png",
            license: "Apache-2.0",
            interfaces: [
                <WebChatInterface>{
                    'type: "webchat",
                    signature: {
                        input: {
                            'type: "object",
                            properties: {
                                user_prompt: {
                                    'type: "string",
                                    description: "Prompt from user."
                                }
                            },
                            required: ["user_prompt"]
                        },
                        output: {
                            'type: "object",
                            properties: {
                                response: {
                                    'type: "string",
                                    description: "Agent response."
                                }
                            },
                            required: ["response"]
                        }
                    },
                    exposure: {
                        http: {
                            path: "/chat"
                        }
                    }
                }
            ],
            tools: {
                mcp: [
                    {
                        name: "TestServer",
                        transport: {
                            'type: "http",
                            url: "https://test-server.com/api",
                            authentication: {
                                'type: "bearer",
                                "token": "dummy-token"
                            }
                        },
                        tool_filter: {
                            allow: ["tool1", "tool2"]
                        }
                    }
                ]
            },
            max_iterations: 5
        },
        role: "This is a test role for the agent. It should be parsed correctly.",
        instructions: "These are the instructions for the agent. They should also be parsed correctly."
    };
    test:assertEquals(parsed, expected);
}


