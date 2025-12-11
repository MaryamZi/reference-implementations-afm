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

import ballerina/data.yaml;
import ballerina/os;

function parseAfm(string content) returns AFMRecord|error {
    string resolvedContent = check resolveVariables(content);
    
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

function resolveVariables(string content) returns string|error {
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

        // Check if this variable is in a commented line (YAML comment: #)
        // Find the start of the line containing this variable
        int lineStart = dollarPos;
        while lineStart > 0 && result[lineStart - 1] != "\n" {
            lineStart -= 1;
        }

        // Check if the line starts with # (after whitespace)
        string linePrefix = result.substring(lineStart, dollarPos).trim();
        if linePrefix.startsWith("#") {
            // Skip variables in commented lines
            startPos = closeBracePos + 1;
            continue;
        }

        // Extract variable expression (e.g., "VAR", "env:VAR", "file:path")
        string varExpr = result.substring(dollarPos + 2, closeBracePos);

        // Parse prefix and value
        string prefix = "";
        string varName = varExpr;
        int? colonPos = varExpr.indexOf(":");
        if colonPos is int {
            prefix = varExpr.substring(0, colonPos);
            varName = varExpr.substring(colonPos + 1);
        }

        // Resolve based on prefix
        string resolvedValue;
        if prefix == "" || prefix == "env" {
            // No prefix or env: prefix -> environment variable
            string? envValue = os:getEnv(varName);
            if envValue is () || envValue == "" {
                return error(string `Environment variable '${varName}' not found`);
            }
            resolvedValue = envValue;
        } else {
            // Unsupported prefix - return error
            return error(string `Unsupported variable prefix '${prefix}:' in '${varExpr}'. Only 'env:' is supported.`);
        }

        // Replace the variable with its value
        string before = result.substring(0, dollarPos);
        string after = result.substring(closeBracePos + 1);
        result = before + resolvedValue + after;
        startPos = before.length() + resolvedValue.length();
    }

    return result;
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
