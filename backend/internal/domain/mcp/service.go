package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

const jsonRPCVersion = "2.0"

// HTTPResponse encapsulates both JSON-RPC response and HTTP status code
type HTTPResponse struct {
	JSONRPCResponse JSONRPCResponse
	StatusCode      int
}

// NewSuccessHTTPResponse creates a successful HTTP response with JSON-RPC result
func NewSuccessHTTPResponse(id json.RawMessage, result interface{}, statusCode int) HTTPResponse {
	return HTTPResponse{
		JSONRPCResponse: JSONRPCResponse{
			JSONRPC: jsonRPCVersion,
			ID:      id,
			Result:  result,
		},
		StatusCode: statusCode,
	}
}

// NewErrorHTTPResponse creates an error HTTP response with JSON-RPC error
func NewErrorHTTPResponse(id json.RawMessage, code int, message string, data interface{}, statusCode int) HTTPResponse {
	return HTTPResponse{
		JSONRPCResponse: JSONRPCResponse{
			JSONRPC: jsonRPCVersion,
			ID:      id,
			Error: &JSONRPCError{
				Code:    code,
				Message: message,
				Data:    data,
			},
		},
		StatusCode: statusCode,
	}
}

// Service handles MCP protocol operations
type Service struct {
	logger     *slog.Logger
	serverInfo ServerInfo
	registry   *HandlerRegistry
}

// NewService creates a new MCP service
func NewService(logger *slog.Logger, registry *HandlerRegistry) *Service {
	return &Service{
		logger: logger,
		serverInfo: ServerInfo{
			Name:    "myapp-mcp-server",
			Title:   "MCP ready accounting service.",
			Version: "1.0.0",
		},
		registry: registry,
	}
}

// HandleRequest processes a JSON-RPC request
func (s *Service) HandleRequest(ctx context.Context, request JSONRPCRequest) HTTPResponse {
	s.logger.Info("MCP request received", "method", request.Method)

	switch request.Method {
	case "initialize":
		return s.handleInitialize(ctx, request)
	case "initialized":
		return s.handleInitialized(ctx, request)
	case "notifications/initialized":
		return s.handleInitializedNotification(ctx, request)
	case "ping":
		return s.handlePing(ctx, request)
	case "resources/list":
		return s.handleListResources(ctx, request)
	case "resources/read":
		return s.handleReadResource(ctx, request)
	case "tools/list":
		return s.handleListTools(ctx, request)
	case "tools/call":
		return s.handleCallTool(ctx, request)
	default:
		return NewErrorHTTPResponse(request.ID, MethodNotFound, fmt.Sprintf("Method not found: %s", request.Method), nil, http.StatusOK)
	}
}

func (s *Service) handleInitialize(ctx context.Context, request JSONRPCRequest) HTTPResponse {
	var params InitializeParams
	if err := json.Unmarshal(request.Params, &params); err != nil {
		return NewErrorHTTPResponse(request.ID, InvalidParams, "Invalid initialize params", err, http.StatusOK)
	}

	result := InitializeResult{
		ProtocolVersion: "2024-11-05",
		Capabilities: ServerCapability{
			Resources: ResourcesCapability{
				ListChanged: true,
				Subscribe:   false,
			},
			Tools: ToolsCapability{
				ListChanged: true,
				Subscribe:   false,
			},
		},
		Instructions: "Use this MCP server to Double-entry bookkeeping",

		ServerInfo: s.serverInfo,
	}

	return NewSuccessHTTPResponse(request.ID, result, http.StatusOK)
}

func (s *Service) handlePing(ctx context.Context, request JSONRPCRequest) HTTPResponse {
	return NewSuccessHTTPResponse(request.ID, map[string]any{}, http.StatusOK)
}

func (s *Service) handleInitialized(ctx context.Context, request JSONRPCRequest) HTTPResponse {
	return NewSuccessHTTPResponse(request.ID, map[string]any{}, http.StatusOK)
}

func (s *Service) handleInitializedNotification(ctx context.Context, request JSONRPCRequest) HTTPResponse {
	return NewSuccessHTTPResponse(request.ID, map[string]any{}, http.StatusAccepted)
}

func (s *Service) handleListResources(ctx context.Context, request JSONRPCRequest) HTTPResponse {
	resources := s.registry.ListResources()
	result := ListResourcesResult{
		Resources: resources,
	}

	return NewSuccessHTTPResponse(request.ID, result, http.StatusOK)
}

func (s *Service) handleReadResource(ctx context.Context, request JSONRPCRequest) HTTPResponse {
	var params ReadResourceParams
	if err := json.Unmarshal(request.Params, &params); err != nil {
		return NewErrorHTTPResponse(request.ID, InvalidParams, "Invalid read resource params", err, http.StatusOK)
	}

	handler, ok := s.registry.GetResource(params.URI)
	if !ok {
		return NewErrorHTTPResponse(request.ID, InvalidParams, fmt.Sprintf("Resource not found: %s", params.URI), nil, http.StatusOK)
	}

	result, err := handler.Read(ctx)
	if err != nil {
		s.logger.Error("Failed to read resource", "uri", params.URI, "error", err)
		return NewErrorHTTPResponse(request.ID, InternalError, "Failed to read resource", err.Error(), http.StatusOK)
	}

	return NewSuccessHTTPResponse(request.ID, result, http.StatusOK)
}

func (s *Service) handleListTools(ctx context.Context, request JSONRPCRequest) HTTPResponse {
	tools := s.registry.ListTools()
	result := ListToolsResult{
		Tools: tools,
	}

	return NewSuccessHTTPResponse(request.ID, result, http.StatusOK)
}

func (s *Service) handleCallTool(ctx context.Context, request JSONRPCRequest) HTTPResponse {
	var params CallToolParams
	if err := json.Unmarshal(request.Params, &params); err != nil {
		return NewErrorHTTPResponse(request.ID, InvalidParams, "Invalid call tool params", err, http.StatusOK)
	}

	handler, ok := s.registry.GetTool(params.Name)
	if !ok {
		return NewErrorHTTPResponse(request.ID, InvalidParams, fmt.Sprintf("Tool not found: %s", params.Name), nil, http.StatusOK)
	}

	result, err := handler.Execute(ctx, params.Arguments)
	if err != nil {
		s.logger.Error("Failed to execute tool", "tool", params.Name, "error", err)
		// Return error in tool result format
		result = &CallToolResult{
			Content: []ToolResultContent{
				{
					Type: "text",
					Text: err.Error(),
				},
			},
			IsError: true,
		}
	}

	return NewSuccessHTTPResponse(request.ID, result, http.StatusOK)
}


func (s *Service) errorResponse(id json.RawMessage, code int, message string, data interface{}) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: jsonRPCVersion,
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}
