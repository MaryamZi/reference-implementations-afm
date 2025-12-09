---
spec_version: '0.3.0'
name: "TestAgent"
description: "A test agent for AFM parsing."
authors:
  - "Maryam"
  - "Copilot"
version: "0.1.0"
namespace: "test"
iconUrl: "https://example.com/icon.png"
license: "Apache-2.0"
interface:
  type: function
  signature:
    input:
      type: object
      properties:
        user_prompt:
          type: string
          description: Prompt from user.
      required: [user_prompt]
    output:
      type: object
      properties:
        response:
          type: string
          description: Agent response.
      required: [response]
tools:
  mcp:
    servers:
      - name: "TestServer"
        transport:
          type: streamable_http
          url: "https://test-server.com/api"
        authentication:
          type: bearer
          token: "dummy-token"
        tool_filter:
          allow:
            - "tool1"
            - "tool2"
max_iterations: 5
---
# Role
This is a test role for the agent. It should be parsed correctly.

# Instructions
These are the instructions for the agent. They should also be parsed correctly.
