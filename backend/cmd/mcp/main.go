package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"runtime"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	// gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/api/mcp/resources"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/api/mcp/tools"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/api/response"
	envconfig "github.com/hirosato/go-mcp-scaffoldings/backend/internal/common/config"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/journal"
	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/mcp"
	dynamoClient "github.com/hirosato/go-mcp-scaffoldings/backend/internal/platform/dynamodb/client"
	dynamodbRepository "github.com/hirosato/go-mcp-scaffoldings/backend/internal/platform/dynamodb/repository"
)

type MCPRequestHandler struct {
	mcpService *mcp.Service
	logger     *slog.Logger
	config     *envconfig.Config
}

// NewMCPRequestHandler creates a new MCP request handler
func NewMCPRequestHandler(
	mcpService *mcp.Service,
	logger *slog.Logger,
	config *envconfig.Config,
) *MCPRequestHandler {
	return &MCPRequestHandler{
		mcpService: mcpService,
		logger:     logger,
		config:     config,
	}
}

func (h *MCPRequestHandler) HandleRequest(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Handle CORS preflight
	if request.HTTPMethod == "OPTIONS" {
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusOK,
			Headers:    h.getCORSHeaders(),
		}, nil
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	h.logger.Info("mcp - Memory Status", "MB", m.Alloc/1024/1024)

	if h.config.Environment == "dev" {
		h.logger.Info("Request Details",
			"path", request.Path,
			"method", request.HTTPMethod,
			"body", request.Body,
			"origin", request.Headers["Origin"],
			"referer", request.Headers["Referer"],
			"userAgent", request.Headers["User-Agent"],
			"requestId", request.RequestContext.RequestID,
			"sourceIP", request.RequestContext.Identity.SourceIP,
			"queryParams", request.QueryStringParameters,
			"headers", request.Headers,
		)
	}

	if request.Path == "/" && request.HTTPMethod != "POST" {
		return h.jsonRPCMethodNotAllowedError(), nil
	}

	// MCP servers handle JSON-RPC requests on the root path
	if request.Path != "/" || request.HTTPMethod != "POST" {
		return response.NotFound("Endpoint not found"), nil
	}

	// Parse JSON-RPC request
	var jsonRPCRequest mcp.JSONRPCRequest
	if err := json.Unmarshal([]byte(request.Body), &jsonRPCRequest); err != nil {
		h.logger.Error("Failed to parse JSON-RPC request", "error", err)
		return h.jsonRPCErrorResponse(mcp.ParseError, "Parse error", err.Error()), nil
	}

	// Handle the request
	httpResponse := h.mcpService.HandleRequest(ctx, jsonRPCRequest)

	// Marshal response
	responseBody, err := json.Marshal(httpResponse.JSONRPCResponse)
	if err != nil {
		h.logger.Error("Failed to marshal JSON-RPC response", "error", err)
		return h.jsonRPCErrorResponse(mcp.InternalError, "Internal error", "Failed to marshal response"), nil
	}

	if h.config.Environment == "dev" {
		h.logger.Info("Response Details",
			"response", string(responseBody),
		)
	}

	return events.APIGatewayProxyResponse{
		StatusCode: httpResponse.StatusCode,
		Headers:    h.getCORSHeaders(),
		Body:       string(responseBody),
	}, nil
}

func (h *MCPRequestHandler) getCORSHeaders() map[string]string {
	headers := make(map[string]string)
	headers["Content-Type"] = "application/json"
	headers["Access-Control-Allow-Origin"] = "*"
	headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
	headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
	return headers
}

func (h *MCPRequestHandler) jsonRPCErrorResponse(code int, message string, data string) events.APIGatewayProxyResponse {
	errorResponse := mcp.JSONRPCResponse{
		JSONRPC: "2.0",
		Error: &mcp.JSONRPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}

	body, _ := json.Marshal(errorResponse)
	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK, // JSON-RPC errors still return 200
		Headers:    h.getCORSHeaders(),
		Body:       string(body),
	}
}

func (h *MCPRequestHandler) jsonRPCMethodNotAllowedError() events.APIGatewayProxyResponse {
	errorResponse := mcp.JSONRPCResponse{
		JSONRPC: "2.0",
		Error: &mcp.JSONRPCError{
			Code:    mcp.MethodNotAllowed,
			Message: "Method Not Allowed",
		},
	}

	body, _ := json.Marshal(errorResponse)
	headers := h.getCORSHeaders()
	headers["Allow"] = "POST" // Add the allowed method to the CORS
	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusMethodNotAllowed,
		Headers:    headers,
		Body:       string(body),
	}
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Load configuration
	config, err := envconfig.LoadFromEnv()
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Initialize DynamoDB client
	dynamoClient, err := dynamoClient.NewDynamoDBClient(context.Background(), config.AWSRegion)
	if err != nil {
		logger.Error("Failed to initialize DynamoDB client", "error", err)
		os.Exit(1)
	}

	// Initialize transaction repository
	journalRepo := dynamodbRepository.NewDynamoDBJournalRepository(
		dynamoClient,
		config.DynamoDBTableName,
		logger,
	)

	// Initialize journal service
	journalService := journal.NewService(journalRepo)

	// Create MCP handler registry
	registry := mcp.NewHandlerRegistry()

	// Register demo tools
	registry.RegisterTool(&tools.SimpleTool{
		Name:        "Echo",
		Description: "Echoes back the provided message",
	})

	// Register transaction tools
	registry.RegisterTool(tools.NewCreateJournalEntryTool(journalService))

	// Register demo resources
	registry.RegisterResource(&resources.SimpleResource{
		URI:         "myapp://hello",
		Name:        "Sample Resource",
		Description: "A simple demo resource",
	})

	// Register journal entry resources
	registry.RegisterResource(resources.NewJournalEntriesResource(journalService))

	// Create MCP service with registry
	mcpService := mcp.NewService(logger, registry)

	// Create handler
	handler := NewMCPRequestHandler(
		mcpService,
		logger,
		config,
	)

	lambda.Start(handler.HandleRequest)
}
