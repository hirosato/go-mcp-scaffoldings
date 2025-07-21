package tools

import (
	"context"
	"encoding/json"

	"github.com/hirosato/go-mcp-scaffoldings/backend/internal/domain/mcp"
)

// SimpleTool is a demo tool implementation
type SimpleTool struct {
	Name        string
	Description string
}

func (t *SimpleTool) GetName() string        { return t.Name }
func (t *SimpleTool) GetDescription() string { return t.Description }
func (t *SimpleTool) GetInputSchema() mcp.JSONSchema {
	return mcp.JSONSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"message": map[string]string{
				"type":        "string",
				"description": "A message to echo",
			},
		},
		Required: []string{"message"},
	}
}

func (t *SimpleTool) Execute(ctx context.Context, arguments json.RawMessage) (*mcp.CallToolResult, error) {
	var args struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(arguments, &args); err != nil {
		return nil, err
	}

	return &mcp.CallToolResult{
		Content: []mcp.ToolResultContent{
			{
				Type: "text",
				Text: "Echo: " + args.Message,
			},
		},
		IsError: false,
	}, nil
}
