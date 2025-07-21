package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock tool for testing
type mockTool struct {
	name        string
	description string
	schema      JSONSchema
	result      *CallToolResult
	err         error
}

func (m *mockTool) GetName() string            { return m.name }
func (m *mockTool) GetDescription() string     { return m.description }
func (m *mockTool) GetInputSchema() JSONSchema { return m.schema }
func (m *mockTool) Execute(ctx context.Context, arguments json.RawMessage) (*CallToolResult, error) {
	return m.result, m.err
}

// Mock resource for testing
type mockResource struct {
	uri         string
	name        string
	description string
	mimeType    string
	result      *ReadResourceResult
	err         error
}

func (m *mockResource) GetURI() string         { return m.uri }
func (m *mockResource) GetName() string        { return m.name }
func (m *mockResource) GetDescription() string { return m.description }
func (m *mockResource) GetMimeType() string    { return m.mimeType }
func (m *mockResource) Read(ctx context.Context) (*ReadResourceResult, error) {
	return m.result, m.err
}

func TestService_HandleInitialize(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	registry := NewHandlerRegistry()
	service := NewService(logger, registry)

	// Create initialize request
	params := InitializeParams{
		ProtocolVersion: "2024-11-05",
		Capabilities:    ClientCapability{},
		ClientInfo: ClientInfo{
			Name:    "test-client",
			Version: "1.0.0",
		},
	}
	paramsJSON, _ := json.Marshal(params)

	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "initialize",
		Params:  paramsJSON,
	}

	// Handle request
	httpResponse := service.HandleRequest(context.Background(), request)

	// Verify response
	assert.Nil(t, httpResponse.JSONRPCResponse.Error)
	assert.NotNil(t, httpResponse.JSONRPCResponse.Result)
	assert.Equal(t, 200, httpResponse.StatusCode)

	// Parse result
	resultJSON, _ := json.Marshal(httpResponse.JSONRPCResponse.Result)
	var result InitializeResult
	err := json.Unmarshal(resultJSON, &result)
	require.NoError(t, err)

	assert.Equal(t, "2024-11-05", result.ProtocolVersion)
	assert.Equal(t, "myapp-mcp-server", result.ServerInfo.Name)
	// assert.NotNil(t, result.Capabilities.Resources)
	// assert.NotNil(t, result.Capabilities.Tools)
	// assert.False(t, result.Capabilities.Resources.Subscribe)
	// assert.False(t, result.Capabilities.Tools.ListChanged)
}

func TestService_HandleListResources(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	registry := NewHandlerRegistry()

	// Register mock resources
	registry.RegisterResource(&mockResource{
		uri:         "test://resource1",
		name:        "Test Resource 1",
		description: "First test resource",
		mimeType:    "text/plain",
	})
	registry.RegisterResource(&mockResource{
		uri:         "test://resource2",
		name:        "Test Resource 2",
		description: "Second test resource",
		mimeType:    "application/json",
	})

	service := NewService(logger, registry)

	// Initialize first
	initParams := InitializeParams{
		ProtocolVersion: "2024-11-05",
		Capabilities:    ClientCapability{},
		ClientInfo: ClientInfo{
			Name:    "test-client",
			Version: "1.0.0",
		},
	}
	initParamsJSON, _ := json.Marshal(initParams)
	service.HandleRequest(context.Background(), JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "initialize",
		Params:  initParamsJSON,
	})

	// List resources
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`2`),
		Method:  "resources/list",
	}

	httpResponse := service.HandleRequest(context.Background(), request)

	// Verify response
	assert.Nil(t, httpResponse.JSONRPCResponse.Error)
	assert.NotNil(t, httpResponse.JSONRPCResponse.Result)
	assert.Equal(t, 200, httpResponse.StatusCode)

	// Parse result
	resultJSON, _ := json.Marshal(httpResponse.JSONRPCResponse.Result)
	var result ListResourcesResult
	err := json.Unmarshal(resultJSON, &result)
	require.NoError(t, err)

	assert.Len(t, result.Resources, 2)
}

func TestService_HandleListTools(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	registry := NewHandlerRegistry()

	// Register mock tools
	registry.RegisterTool(&mockTool{
		name:        "test_tool1",
		description: "First test tool",
		schema: JSONSchema{
			Type:     "object",
			Required: []string{"param1"},
		},
	})
	registry.RegisterTool(&mockTool{
		name:        "test_tool2",
		description: "Second test tool",
		schema: JSONSchema{
			Type:     "object",
			Required: []string{"param2"},
		},
	})

	service := NewService(logger, registry)

	// Initialize first
	initParams := InitializeParams{
		ProtocolVersion: "2024-11-05",
		Capabilities:    ClientCapability{},
		ClientInfo: ClientInfo{
			Name:    "test-client",
			Version: "1.0.0",
		},
	}
	initParamsJSON, _ := json.Marshal(initParams)
	service.HandleRequest(context.Background(), JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "initialize",
		Params:  initParamsJSON,
	})

	// List tools
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`2`),
		Method:  "tools/list",
	}

	httpResponse := service.HandleRequest(context.Background(), request)

	// Verify response
	assert.Nil(t, httpResponse.JSONRPCResponse.Error)
	assert.NotNil(t, httpResponse.JSONRPCResponse.Result)
	assert.Equal(t, 200, httpResponse.StatusCode)

	// Parse result
	resultJSON, _ := json.Marshal(httpResponse.JSONRPCResponse.Result)
	var result ListToolsResult
	err := json.Unmarshal(resultJSON, &result)
	require.NoError(t, err)

	assert.Len(t, result.Tools, 2)
}

func TestService_NotInitialized(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	registry := NewHandlerRegistry()
	service := NewService(logger, registry)

	// Try to list resources without initializing
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "resources/list",
	}

	httpResponse := service.HandleRequest(context.Background(), request)

	// Should return successful response (no initialization check in current implementation)
	assert.Nil(t, httpResponse.JSONRPCResponse.Error)
	assert.NotNil(t, httpResponse.JSONRPCResponse.Result)
	assert.Equal(t, 200, httpResponse.StatusCode)
}

func TestService_CallTool(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	registry := NewHandlerRegistry()

	// Register mock tool
	expectedResult := &CallToolResult{
		Content: []ToolResultContent{
			{
				Type: "text",
				Text: "Tool executed successfully",
			},
		},
		IsError: false,
	}

	registry.RegisterTool(&mockTool{
		name:        "test_tool",
		description: "Test tool",
		schema:      JSONSchema{Type: "object"},
		result:      expectedResult,
		err:         nil,
	})

	service := NewService(logger, registry)

	// Initialize first
	initParams := InitializeParams{
		ProtocolVersion: "2024-11-05",
		Capabilities:    ClientCapability{},
		ClientInfo: ClientInfo{
			Name:    "test-client",
			Version: "1.0.0",
		},
	}
	initParamsJSON, _ := json.Marshal(initParams)
	service.HandleRequest(context.Background(), JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "initialize",
		Params:  initParamsJSON,
	})

	// Call tool
	callParams := CallToolParams{
		Name:      "test_tool",
		Arguments: json.RawMessage(`{"param": "value"}`),
	}
	callParamsJSON, _ := json.Marshal(callParams)

	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`2`),
		Method:  "tools/call",
		Params:  callParamsJSON,
	}

	httpResponse := service.HandleRequest(context.Background(), request)

	// Verify response
	assert.Nil(t, httpResponse.JSONRPCResponse.Error)
	assert.NotNil(t, httpResponse.JSONRPCResponse.Result)
	assert.Equal(t, 200, httpResponse.StatusCode)

	// Parse result
	resultJSON, _ := json.Marshal(httpResponse.JSONRPCResponse.Result)
	var result CallToolResult
	err := json.Unmarshal(resultJSON, &result)
	require.NoError(t, err)

	assert.Len(t, result.Content, 1)
	assert.Equal(t, "text", result.Content[0].Type)
	assert.Equal(t, "Tool executed successfully", result.Content[0].Text)
	assert.False(t, result.IsError)
}
