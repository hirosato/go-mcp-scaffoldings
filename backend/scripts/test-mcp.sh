#!/bin/bash

# Test script for MCP server
# This script sends JSON-RPC requests to test the MCP server implementation

echo "Testing MCP Server..."
echo "===================="

# Test 1: Initialize
echo -e "\n1. Testing Initialize..."
curl -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": {
        "name": "test-client",
        "version": "1.0.0"
      }
    }
  }' | jq .

# Test 2: List Resources
echo -e "\n2. Testing List Resources..."
curl -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "resources/list"
  }' | jq .

# Test 3: Read Resource
echo -e "\n3. Testing Read Resource..."
curl -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "resources/read",
    "params": {
      "uri": "demo://hello"
    }
  }' | jq .

# Test 4: List Tools
echo -e "\n4. Testing List Tools..."
curl -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/list"
  }' | jq .

# Test 5: Call Tool
echo -e "\n5. Testing Call Tool..."
curl -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 5,
    "method": "tools/call",
    "params": {
      "name": "echo",
      "arguments": {
        "message": "Hello from MCP!"
      }
    }
  }' | jq .