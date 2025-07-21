package mcp

import (
	"context"
	"encoding/json"
)

// ToolHandler defines the interface for tool handlers
type ToolHandler interface {
	GetName() string
	GetDescription() string
	GetInputSchema() JSONSchema
	Execute(ctx context.Context, arguments json.RawMessage) (*CallToolResult, error)
}

// ResourceHandler defines the interface for resource handlers
type ResourceHandler interface {
	GetURI() string
	GetName() string
	GetDescription() string
	GetMimeType() string
	Read(ctx context.Context) (*ReadResourceResult, error)
}

// HandlerRegistry manages tool and resource handlers
type HandlerRegistry struct {
	tools     map[string]ToolHandler
	resources map[string]ResourceHandler
}

// NewHandlerRegistry creates a new handler registry
func NewHandlerRegistry() *HandlerRegistry {
	return &HandlerRegistry{
		tools:     make(map[string]ToolHandler),
		resources: make(map[string]ResourceHandler),
	}
}

// RegisterTool registers a tool handler
func (r *HandlerRegistry) RegisterTool(handler ToolHandler) {
	r.tools[handler.GetName()] = handler
}

// RegisterResource registers a resource handler
func (r *HandlerRegistry) RegisterResource(handler ResourceHandler) {
	r.resources[handler.GetURI()] = handler
}

// GetTool retrieves a tool handler by name
func (r *HandlerRegistry) GetTool(name string) (ToolHandler, bool) {
	handler, ok := r.tools[name]
	return handler, ok
}

// GetResource retrieves a resource handler by URI
func (r *HandlerRegistry) GetResource(uri string) (ResourceHandler, bool) {
	handler, ok := r.resources[uri]
	return handler, ok
}

// ListTools returns all registered tools
func (r *HandlerRegistry) ListTools() []Tool {
	tools := make([]Tool, 0, len(r.tools))
	for _, handler := range r.tools {
		tools = append(tools, Tool{
			Name:        handler.GetName(),
			Description: handler.GetDescription(),
			InputSchema: handler.GetInputSchema(),
		})
	}
	return tools
}

// ListResources returns all registered resources
func (r *HandlerRegistry) ListResources() []Resource {
	resources := make([]Resource, 0, len(r.resources))
	for _, handler := range r.resources {
		resources = append(resources, Resource{
			URI:         handler.GetURI(),
			Name:        handler.GetName(),
			Description: handler.GetDescription(),
			MimeType:    handler.GetMimeType(),
		})
	}
	return resources
}